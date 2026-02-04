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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("VaultClusterPolicy Tests", Ordered, Label("module"), func() {
	const (
		clusterPolicyName = "tc-cp-cluster-policy"
	)

	ctx := context.Background()

	AfterAll(func() {
		By("cleaning up VaultClusterPolicy test resources")
		_ = utils.DeleteVaultClusterPolicyCR(
			ctx, clusterPolicyName,
		)
	})

	Context("TC-CP: VaultClusterPolicy Lifecycle", func() {
		It("TC-CP01: Create and sync cluster policy "+
			"to Vault", func() {
			By("creating VaultClusterPolicy resource")
			policy := &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterPolicyName,
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/shared/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
								vaultv1alpha1.CapabilityList,
							},
							Description: "Read shared secrets",
						},
						{
							Path: "secret/metadata/shared/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
								vaultv1alpha1.CapabilityList,
							},
						},
					},
				},
			}
			err := utils.CreateVaultClusterPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred(),
				"Failed to create VaultClusterPolicy")

			By("waiting for VaultClusterPolicy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultClusterPolicyStatus(
					ctx, clusterPolicyName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Equal("Active"),
					"VaultClusterPolicy not active, got: %s",
					status,
				)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying vaultName in status")
			p, err := utils.GetVaultClusterPolicy(
				ctx, clusterPolicyName,
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Status.VaultName).To(
				Equal(clusterPolicyName),
				"Cluster policy vaultName should match "+
					"resource name",
			)

			By("verifying rulesCount in status")
			Expect(p.Status.RulesCount).To(Equal(2),
				"Should have 2 rules")

			By("verifying policy exists in Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				content, err := vaultClient.ReadPolicy(
					ctx, clusterPolicyName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(content).To(
					ContainSubstring("secret/data/shared/*"),
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-CP02: Verify policy HCL content "+
			"in Vault", func() {
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			By("reading policy content from Vault")
			var policyContent string
			Eventually(func(g Gomega) {
				var readErr error
				policyContent, readErr = vaultClient.ReadPolicy(
					ctx, clusterPolicyName,
				)
				g.Expect(readErr).NotTo(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying all paths are present in policy HCL")
			Expect(policyContent).To(
				ContainSubstring(
					`path "secret/data/shared/*"`,
				),
				"Policy should contain secret/data/shared/*",
			)
			Expect(policyContent).To(
				ContainSubstring(
					`path "secret/metadata/shared/*"`,
				),
				"Policy should contain "+
					"secret/metadata/shared/*",
			)

			By("verifying capabilities are correctly written")
			Expect(policyContent).To(
				ContainSubstring("read"),
				"Policy should include read capability",
			)
			Expect(policyContent).To(
				ContainSubstring("list"),
				"Policy should include list capability",
			)
		})
	})

	Context("TC-CP: VaultClusterPolicy Error Handling", func() {
		It("TC-CP03: Handle invalid connection "+
			"reference", func() {
			invalidConnPolicyName := "tc-cp03-invalid-conn"

			By("creating VaultClusterPolicy with bad connection")
			policy := &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: invalidConnPolicyName,
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "non-existent-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/cluster/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
						},
					},
				},
			}
			err := utils.CreateVaultClusterPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("verifying it enters Error or Pending phase")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultClusterPolicyStatus(
					ctx, invalidConnPolicyName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Or(Equal("Error"), Equal("Pending")),
					"Should be in Error or Pending phase",
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying status message indicates issue")
			p, err := utils.GetVaultClusterPolicy(
				ctx, invalidConnPolicyName,
			)
			Expect(err).NotTo(HaveOccurred())
			if p.Status.Message != "" {
				Expect(p.Status.Message).To(Or(
					ContainSubstring("not found"),
					ContainSubstring("connection"),
					ContainSubstring("Not Found"),
				))
			}

			By("cleaning up invalid connection cluster policy")
			_ = utils.DeleteVaultClusterPolicyCR(
				ctx, invalidConnPolicyName,
			)
		})

		It("TC-CP04: Handle empty rules in "+
			"VaultClusterPolicy", func() {
			emptyRulesPolicyName := "tc-cp04-empty-rules"

			By("creating VaultClusterPolicy with empty rules")
			policy := &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: emptyRulesPolicyName,
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules:         []vaultv1alpha1.PolicyRule{},
				},
			}
			err := utils.CreateVaultClusterPolicyCR(ctx, policy)

			// Webhook should reject, or controller handles it
			if err != nil {
				By("webhook rejected empty rules (expected)")
				errMsg := err.Error()
				Expect(errMsg).To(Or(
					ContainSubstring("rules"),
					ContainSubstring("empty"),
					ContainSubstring("required"),
					ContainSubstring("at least"),
				))
			} else {
				By("policy created, checking status")
				Eventually(func(g Gomega) {
					status, err :=
						utils.GetVaultClusterPolicyStatus(
							ctx, emptyRulesPolicyName,
						)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(status).To(
						Or(Equal("Error"), Equal("Active")),
					)
				}, 30*time.Second, 2*time.Second).Should(
					Succeed(),
				)

				_ = utils.DeleteVaultClusterPolicyCR(
					ctx, emptyRulesPolicyName,
				)
			}
		})
	})
})
