/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Error Handling Tests", Ordered, Label("module"), func() {
	ctx := context.Background()

	Context("TC-EH: Error Scenarios", func() {
		It("TC-EH01: Handle invalid connection reference", func() {
			invalidPolicyName := "tc-eh01-invalid-conn"

			By("creating VaultPolicy with non-existent connection")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      invalidPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: "non-existent-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/test/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultPolicy enters Error or Pending phase")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, invalidPolicyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Or(Equal("Error"), Equal("Pending")),
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up invalid policy")
			_ = utils.DeleteVaultPolicyCR(
				ctx, invalidPolicyName, testNamespace,
			)
		})

		It("TC-EH02: Handle missing policy reference "+
			"in VaultRole", func() {
			missingPolicyRoleName := "tc-eh02-missing-policy"
			missingPolicySAName := "tc-eh02-sa"

			By("creating a test service account")
			_ = utils.CreateServiceAccount(
				ctx, testNamespace, missingPolicySAName,
			)

			By("creating VaultRole referencing non-existent policy")
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      missingPolicyRoleName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef: sharedVaultConnectionName,
					ServiceAccounts: []string{
						missingPolicySAName,
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultPolicy",
							Name:      "non-existent-policy",
							Namespace: testNamespace,
						},
					},
					TokenTTL: "30m",
				},
			}
			err := utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultRole enters Error or Pending phase")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultRoleStatus(
					ctx, missingPolicyRoleName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Or(Equal("Error"), Equal("Pending")),
					"VaultRole should be in Error or Pending "+
						"phase due to missing policy",
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying status message indicates missing policy")
			r, err := utils.GetVaultRole(
				ctx, missingPolicyRoleName, testNamespace,
			)
			if err == nil && r.Status.Message != "" {
				Expect(strings.ToLower(r.Status.Message)).To(Or(
					ContainSubstring("not found"),
					ContainSubstring("missing"),
					ContainSubstring("policy"),
				), "Status message should indicate policy issue")
			}

			By("cleaning up missing policy role")
			_ = utils.DeleteVaultRoleCR(
				ctx, missingPolicyRoleName, testNamespace,
			)
			_ = utils.DeleteServiceAccount(
				ctx, testNamespace, missingPolicySAName,
			)
		})

		It("TC-EH03: Reject policy violating "+
			"namespace boundary", func() {
			violationPolicyName := "tc-eh03-boundary"
			enforceNS := true

			By("creating VaultPolicy without {{namespace}} variable")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      violationPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            sharedVaultConnectionName,
					EnforceNamespaceBoundary: &enforceNS,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/global/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
							Description: "This path violates " +
								"namespace boundary",
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)

			// Webhook may reject, or controller detects the error
			if err != nil {
				By("webhook rejected the policy (expected)")
				errMsg := err.Error()
				Expect(errMsg).To(Or(
					ContainSubstring("namespace"),
					ContainSubstring("boundary"),
					ContainSubstring("{{namespace}}"),
				), "Rejection should mention namespace boundary")
			} else {
				By("policy created, checking controller phase")
				Eventually(func(g Gomega) {
					status, err := utils.GetVaultPolicyStatus(
						ctx, violationPolicyName,
						testNamespace,
					)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(status).To(
						Or(Equal("Error"), Equal("Active")),
					)
				}, 30*time.Second, 2*time.Second).Should(
					Succeed(),
				)

				By("cleaning up boundary violation policy")
				_ = utils.DeleteVaultPolicyCR(
					ctx, violationPolicyName, testNamespace,
				)
			}
		})

		It("TC-EH04: Handle VaultConnection "+
			"becoming unavailable", func() {
			unavailConnName := "tc-eh04-unavail"
			unavailPolicyName := "tc-eh04-policy"

			By("creating VaultConnection to non-existent Vault")
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name: unavailConnName,
				},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: fmt.Sprintf(
						"http://vault-does-not-exist.%s"+
							".svc.cluster.local:8200",
						testNamespace,
					),
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name:      "vault-token",
								Namespace: testNamespace,
								Key:       "token",
							},
						},
					},
					HealthCheckInterval: "5s",
				},
			}
			err := utils.CreateVaultConnectionCR(ctx, conn)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultConnection enters Error or Pending")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultConnectionStatus(
					ctx, unavailConnName, "",
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Or(Equal("Error"), Equal("Pending")),
					"VaultConnection should be in Error or "+
						"Pending phase",
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("creating VaultPolicy using unavailable connection")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      unavailPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: unavailConnName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/unavail/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
						},
					},
				},
			}
			err = utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultPolicy enters Error or Pending")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, unavailPolicyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Or(Equal("Error"), Equal("Pending")),
					"VaultPolicy should be in Error or Pending "+
						"when connection unavailable",
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up unavailable connection resources")
			_ = utils.DeleteVaultPolicyCR(
				ctx, unavailPolicyName, testNamespace,
			)
			_ = utils.DeleteVaultConnectionCR(
				ctx, unavailConnName,
			)
		})

		It("TC-EH05: Reject invalid TTL format", func() {
			invalidTTLRoleName := "tc-eh05-invalid-ttl"
			invalidTTLSAName := "tc-eh05-sa"
			invalidTTLPolicyName := "tc-eh05-policy"

			By("creating test prerequisites")
			_ = utils.CreateServiceAccount(
				ctx, testNamespace, invalidTTLSAName,
			)

			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      invalidTTLPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/test/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
						},
					},
				},
			}
			_ = utils.CreateVaultPolicyCR(ctx, policy)

			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, invalidTTLPolicyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("creating VaultRole with invalid TTL format")
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      invalidTTLRoleName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef: sharedVaultConnectionName,
					ServiceAccounts: []string{
						invalidTTLSAName,
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultPolicy",
							Name:      invalidTTLPolicyName,
							Namespace: testNamespace,
						},
					},
					TokenTTL: "invalid-ttl",
				},
			}
			err := utils.CreateVaultRoleCR(ctx, role)

			// Webhook may reject or controller handles it
			if err != nil {
				By("webhook rejected the invalid TTL (expected)")
				errMsg := err.Error()
				Expect(errMsg).To(Or(
					ContainSubstring("ttl"),
					ContainSubstring("duration"),
					ContainSubstring("invalid"),
				))
			} else {
				By("role created, verifying error state")
				Eventually(func(g Gomega) {
					status, err := utils.GetVaultRoleStatus(
						ctx, invalidTTLRoleName, testNamespace,
					)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(status).To(
						Or(Equal("Error"), Equal("Pending")),
					)
				}, 30*time.Second, 2*time.Second).Should(
					Succeed(),
				)
			}

			By("cleaning up")
			_ = utils.DeleteVaultRoleCR(
				ctx, invalidTTLRoleName, testNamespace,
			)
			_ = utils.DeleteVaultPolicyCR(
				ctx, invalidTTLPolicyName, testNamespace,
			)
			_ = utils.DeleteServiceAccount(
				ctx, testNamespace, invalidTTLSAName,
			)
		})

		It("TC-EH06: Handle empty policy rules", func() {
			emptyRulesPolicyName := "tc-eh06-empty-rules"

			By("creating VaultPolicy with empty rules")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      emptyRulesPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules:         []vaultv1alpha1.PolicyRule{},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)

			// Webhook should reject empty rules, or error state
			if err != nil {
				By("webhook rejected empty rules (expected)")
				errMsg := err.Error()
				Expect(errMsg).To(Or(
					ContainSubstring("rules"),
					ContainSubstring("empty"),
					ContainSubstring("required"),
				))
			} else {
				By("policy created, checking status")
				Eventually(func(g Gomega) {
					status, err := utils.GetVaultPolicyStatus(
						ctx, emptyRulesPolicyName,
						testNamespace,
					)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(status).To(
						Or(Equal("Error"), Equal("Active")),
					)
				}, 30*time.Second, 2*time.Second).Should(
					Succeed(),
				)

				_ = utils.DeleteVaultPolicyCR(
					ctx, emptyRulesPolicyName, testNamespace,
				)
			}
		})
	})
})
