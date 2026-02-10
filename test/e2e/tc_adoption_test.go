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

var _ = Describe("Adoption Tests", Ordered, Label("adoption"), func() {
	ctx := context.Background()

	Context("TC-ADOPT: Annotation-Based Adoption", func() {
		It("TC-ADOPT01-POLICY: Adopt existing policy via annotation", func() {
			policyName := "tc-adopt01-policy"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, policyName)
			existingHCL := `path "secret/data/existing/*" { capabilities = ["read", "list"] }`

			By("creating policy directly in Vault (unmanaged)")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			err = vaultClient.WritePolicy(ctx, expectedVaultName, existingHCL)
			Expect(err).NotTo(HaveOccurred(), "Failed to create unmanaged policy in Vault")

			By("verifying policy exists in Vault")
			exists, err := vaultClient.PolicyExists(ctx, expectedVaultName)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeTrue())

			By("creating VaultPolicy with adopt annotation")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue,
					},
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:  sharedVaultConnectionName,
					ConflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/adopted/*",
							Capabilities: []vaultv1alpha1.Capability{"read"},
						},
					},
				},
			}
			err = utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the policy binding is established")
			Eventually(func(g Gomega) {
				p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(p.Status.Binding.VaultPath).To(ContainSubstring("sys/policies/acl/"))
				g.Expect(p.Status.Binding.VaultResourceName).To(Equal(expectedVaultName))
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up")
			_ = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
		})

		It("TC-ADOPT02-ROLE: Adopt existing role via annotation", func() {
			roleName := "tc-adopt02-role"
			expectedVaultRoleName := fmt.Sprintf("%s-%s", testNamespace, roleName)
			authPath := "kubernetes"

			By("creating role directly in Vault (unmanaged)")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			roleData := map[string]interface{}{
				"bound_service_account_names":      []string{"existing-sa"},
				"bound_service_account_namespaces": []string{testNamespace},
				"policies":                         []string{"default"},
				"ttl":                              "5m",
			}
			err = vaultClient.WriteAuthRole(ctx, authPath, expectedVaultRoleName, roleData)
			Expect(err).NotTo(HaveOccurred(), "Failed to create unmanaged role in Vault")

			By("verifying role exists in Vault")
			exists, err := vaultClient.RoleExists(ctx, authPath, expectedVaultRoleName)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeTrue())

			By("creating VaultRole with adopt annotation")
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      roleName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue,
					},
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   sharedVaultConnectionName,
					ConflictPolicy:  vaultv1alpha1.ConflictPolicyAdopt,
					ServiceAccounts: []string{"adopted-sa"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "default",
						},
					},
				},
			}
			err = utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultRole to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultRoleStatus(ctx, roleName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the role binding is established")
			Eventually(func(g Gomega) {
				r, err := utils.GetVaultRole(ctx, roleName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(r.Status.Binding.VaultPath).To(ContainSubstring("auth/kubernetes/role/"))
				g.Expect(r.Status.Binding.VaultResourceName).To(Equal(expectedVaultRoleName))
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up")
			_ = utils.DeleteVaultRoleCR(ctx, roleName, testNamespace)
		})

		It("TC-ADOPT03-FAIL: Adoption fails when resource doesn't exist", func() {
			policyName := "tc-adopt03-nonexistent"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, policyName)

			By("ensuring policy does NOT exist in Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			_ = vaultClient.DeletePolicy(ctx, expectedVaultName)

			By("creating VaultPolicy with adopt annotation for non-existent policy")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue,
					},
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:  sharedVaultConnectionName,
					ConflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/nonexistent/*",
							Capabilities: []vaultv1alpha1.Capability{"read"},
						},
					},
				},
			}
			err = utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active (creates new policy since nothing to adopt)")
			// When adoption target doesn't exist, operator creates it instead
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up")
			_ = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
		})
	})

	Context("TC-ADOPT: Binding Verification", func() {
		It("TC-ADOPT04-VERIFY: Binding status populated after create", func() {
			policyName := "tc-adopt04-binding"

			By("creating VaultPolicy")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/binding/*",
							Capabilities: []vaultv1alpha1.Capability{"read"},
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying binding status is populated")
			Eventually(func(g Gomega) {
				p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(p.Status.Binding.VaultPath).NotTo(BeEmpty(),
					"VaultPath should be populated")
				g.Expect(p.Status.Binding.VaultResourceName).NotTo(BeEmpty(),
					"VaultResourceName should be populated")
				g.Expect(p.Status.Binding.BoundAt).NotTo(BeNil(),
					"BoundAt should be set")
				g.Expect(p.Status.Binding.BindingVerified).To(BeTrue(),
					"BindingVerified should be true")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up")
			_ = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
		})
	})
})
