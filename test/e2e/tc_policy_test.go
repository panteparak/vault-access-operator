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

var _ = Describe("VaultPolicy Tests", Ordered, Label("module"), func() {
	// Test configuration
	const (
		policyName = "tc-vp-policy"
	)

	ctx := context.Background()

	AfterAll(func() {
		By("cleaning up VaultPolicy test resources")
		_ = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
	})

	Context("TC-VP: VaultPolicy Lifecycle", func() {
		It("TC-VP01: Create namespaced VaultPolicy and sync to Vault", func() {
			By("creating VaultPolicy resource")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: fmt.Sprintf(
								"secret/data/%s/*", testNamespace,
							),
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityCreate,
								vaultv1alpha1.CapabilityRead,
								vaultv1alpha1.CapabilityUpdate,
								vaultv1alpha1.CapabilityDelete,
								vaultv1alpha1.CapabilityList,
							},
							Description: "Full access to namespace secrets",
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

			By("waiting for VaultPolicy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, policyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Equal("Active"),
					"VaultPolicy not active, got: %s", status,
				)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying VaultPolicy has namespaced vaultName")
			p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			expectedVaultName := fmt.Sprintf(
				"%s-%s", testNamespace, policyName,
			)
			Expect(p.Status.VaultName).To(Equal(expectedVaultName),
				"Namespaced policy should have namespace-prefixed vaultName")

			By("verifying policy exists in Vault with namespaced name")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				content, err := vaultClient.ReadPolicy(
					ctx, expectedVaultName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(content).To(ContainSubstring(testNamespace))
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-VP02: Substitute {{namespace}} variable in policy paths", func() {
			nsSubstPolicyName := "tc-vp02-ns-subst"
			expectedVaultName := fmt.Sprintf(
				"%s-%s", testNamespace, nsSubstPolicyName,
			)
			enforceNS := true

			By("creating VaultPolicy with {{namespace}} variable")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nsSubstPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            sharedVaultConnectionName,
					EnforceNamespaceBoundary: &enforceNS,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/{{namespace}}/app/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
								vaultv1alpha1.CapabilityList,
							},
							Description: "Namespace-scoped secret access",
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, nsSubstPolicyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("reading policy content from Vault and verifying namespace substitution")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				policyContent, err := vaultClient.ReadPolicy(
					ctx, expectedVaultName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				// The {{namespace}} variable should be replaced with actual namespace
				g.Expect(policyContent).To(ContainSubstring(testNamespace),
					"Policy should contain the substituted namespace")
				g.Expect(policyContent).NotTo(
					ContainSubstring("{{namespace}}"),
					"Policy should NOT contain unsubstituted "+
						"{{namespace}} variable",
				)
				// Verify the full path with namespace substituted
				expectedPath := fmt.Sprintf(
					"secret/data/%s/app/*", testNamespace,
				)
				g.Expect(policyContent).To(
					ContainSubstring(expectedPath),
					"Policy should contain the "+
						"namespace-substituted path",
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up namespace substitution test policy")
			_ = utils.DeleteVaultPolicyCR(
				ctx, nsSubstPolicyName, testNamespace,
			)
		})

		It("TC-VP03: Update VaultPolicy when spec changes", func() {
			By("updating VaultPolicy with additional rule")
			err := utils.UpdateVaultPolicyCR(
				ctx, policyName, testNamespace,
				func(p *vaultv1alpha1.VaultPolicy) {
					p.Spec.Rules = []vaultv1alpha1.PolicyRule{
						{
							Path: fmt.Sprintf(
								"secret/data/%s/*", testNamespace,
							),
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityCreate,
								vaultv1alpha1.CapabilityRead,
								vaultv1alpha1.CapabilityUpdate,
								vaultv1alpha1.CapabilityDelete,
								vaultv1alpha1.CapabilityList,
							},
							Description: "Full access to namespace secrets",
						},
						{
							Path: fmt.Sprintf(
								"secret/metadata/%s/*", testNamespace,
							),
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
								vaultv1alpha1.CapabilityList,
							},
							Description: "Read metadata",
						},
					}
				},
			)
			Expect(err).NotTo(HaveOccurred())

			By("verifying rulesCount updated to 2")
			Eventually(func(g Gomega) {
				p, err := utils.GetVaultPolicy(
					ctx, policyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(p.Status.RulesCount).To(Equal(2))
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-VP04-DEL: Handle VaultPolicy deletion with finalizer", func() {
			tempPolicyName := "tc-vp04-temp"
			expectedVaultName := fmt.Sprintf(
				"%s-%s", testNamespace, tempPolicyName,
			)

			By("creating temporary VaultPolicy")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tempPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/temp/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for temporary policy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, tempPolicyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying policy exists in Vault before deletion")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			exists, err := vaultClient.PolicyExists(ctx, expectedVaultName)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeTrue(), "Policy should exist in Vault")

			By("deleting the temporary VaultPolicy")
			err = utils.DeleteVaultPolicyCR(
				ctx, tempPolicyName, testNamespace,
			)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultPolicy resource is deleted")
			err = utils.WaitForDeletion(
				ctx, &vaultv1alpha1.VaultPolicy{},
				tempPolicyName, testNamespace,
				30*time.Second, 2*time.Second,
			)
			Expect(err).NotTo(HaveOccurred(),
				"VaultPolicy CR should be deleted")

			By("verifying policy is deleted from Vault")
			Eventually(func(g Gomega) {
				exists, err := vaultClient.PolicyExists(
					ctx, expectedVaultName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeFalse(),
					"Policy should be deleted from Vault")
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-VP05-RET: Respect deletionPolicy=Retain", func() {
			retainPolicyName := "tc-vp05-retain"
			expectedVaultName := fmt.Sprintf(
				"%s-%s", testNamespace, retainPolicyName,
			)

			By("creating VaultPolicy with deletionPolicy=Retain")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      retainPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:  sharedVaultConnectionName,
					DeletionPolicy: vaultv1alpha1.DeletionPolicyRetain,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/retain/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, retainPolicyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("deleting the VaultPolicy with Retain policy")
			err = utils.DeleteVaultPolicyCR(
				ctx, retainPolicyName, testNamespace,
			)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for K8s resource to be deleted")
			err = utils.WaitForDeletion(
				ctx, &vaultv1alpha1.VaultPolicy{},
				retainPolicyName, testNamespace,
				30*time.Second, 2*time.Second,
			)
			Expect(err).NotTo(HaveOccurred(),
				"VaultPolicy CR should be deleted from K8s")

			By("verifying policy is STILL in Vault after K8s deletion")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			content, err := vaultClient.ReadPolicy(ctx, expectedVaultName)
			Expect(err).NotTo(HaveOccurred(),
				"Policy should still exist in Vault")
			Expect(content).To(ContainSubstring("retain"))

			By("cleaning up retained policy from Vault")
			_ = vaultClient.DeletePolicy(ctx, expectedVaultName)
		})
	})
})
