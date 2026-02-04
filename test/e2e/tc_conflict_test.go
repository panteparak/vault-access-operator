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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Conflict Policy Tests", Ordered, Label("module"), func() {
	ctx := context.Background()

	Context("TC-CF: Policy Conflict Resolution", func() {
		It("TC-CF01-ADOPT: Adopt existing unmanaged policy", func() {
			adoptPolicyName := "tc-cf01-adopt"
			expectedVaultName := fmt.Sprintf(
				"%s-%s", testNamespace, adoptPolicyName,
			)
			unmanagedHCL := `path "secret/data/unmanaged/*"` +
				` { capabilities = ["read"] }`

			By("creating policy directly in Vault (unmanaged)")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			err = vaultClient.WritePolicy(
				ctx, expectedVaultName, unmanagedHCL,
			)
			Expect(err).NotTo(HaveOccurred(),
				"Failed to create unmanaged policy in Vault")

			By("verifying policy exists in Vault")
			exists, err := vaultClient.PolicyExists(
				ctx, expectedVaultName,
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeTrue(),
				"Unmanaged policy should exist in Vault")

			By("creating VaultPolicy with conflictPolicy=Adopt")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      adoptPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:  sharedVaultConnectionName,
					ConflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/adopted/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
								vaultv1alpha1.CapabilityList,
							},
							Description: "Adopted policy path",
						},
					},
				},
			}
			err = utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, adoptPolicyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"),
					"VaultPolicy should be Active after adoption")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying policy content was updated by operator")
			Eventually(func(g Gomega) {
				content, err := vaultClient.ReadPolicy(
					ctx, expectedVaultName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(content).To(
					ContainSubstring("adopted"),
					"Policy should contain new adopted path",
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up adopt test policy")
			_ = utils.DeleteVaultPolicyCR(
				ctx, adoptPolicyName, testNamespace,
			)
		})

		It("TC-CF02-FAIL: Fail when policy exists "+
			"and conflictPolicy=Fail", func() {
			failPolicyName := "tc-cf02-fail"
			expectedVaultName := fmt.Sprintf(
				"%s-%s", testNamespace, failPolicyName,
			)
			unmanagedHCL := `path "secret/data/preexisting/*"` +
				` { capabilities = ["read"] }`

			By("creating policy directly in Vault (unmanaged)")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			err = vaultClient.WritePolicy(
				ctx, expectedVaultName, unmanagedHCL,
			)
			Expect(err).NotTo(HaveOccurred(),
				"Failed to create unmanaged policy in Vault")

			By("creating VaultPolicy with conflictPolicy=Fail")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      failPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:  sharedVaultConnectionName,
					ConflictPolicy: vaultv1alpha1.ConflictPolicyFail,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/wontwork/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
						},
					},
				},
			}
			err = utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultPolicy enters Conflict or Error phase")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, failPolicyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Or(Equal("Conflict"), Equal("Error")),
					"VaultPolicy should be in Conflict or "+
						"Error phase",
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying original policy content is preserved")
			content, err := vaultClient.ReadPolicy(
				ctx, expectedVaultName,
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(content).To(
				ContainSubstring("preexisting"),
				"Original policy content should be preserved",
			)
			Expect(content).NotTo(
				ContainSubstring("wontwork"),
				"New policy content should NOT be written",
			)

			By("cleaning up fail test policy")
			_ = utils.DeleteVaultPolicyCR(
				ctx, failPolicyName, testNamespace,
			)
			_ = vaultClient.DeletePolicy(
				ctx, expectedVaultName,
			)
		})

		It("TC-CF03-NORM: Create policy normally "+
			"when no conflict exists", func() {
			newPolicyName := "tc-cf03-new"
			expectedVaultName := fmt.Sprintf(
				"%s-%s", testNamespace, newPolicyName,
			)

			By("ensuring policy does NOT exist in Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			_ = vaultClient.DeletePolicy(
				ctx, expectedVaultName,
			)

			By("creating VaultPolicy with conflictPolicy=Fail")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      newPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:  sharedVaultConnectionName,
					ConflictPolicy: vaultv1alpha1.ConflictPolicyFail,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/newpath/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
						},
					},
				},
			}
			err = utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, newPolicyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying policy was created in Vault")
			Eventually(func(g Gomega) {
				content, err := vaultClient.ReadPolicy(
					ctx, expectedVaultName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(content).To(
					ContainSubstring("newpath"),
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up new policy")
			_ = utils.DeleteVaultPolicyCR(
				ctx, newPolicyName, testNamespace,
			)
		})
	})
})
