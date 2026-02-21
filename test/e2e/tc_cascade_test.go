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

var _ = Describe("Cascade Deletion Tests", Ordered, Label("cascade"), func() {
	ctx := context.Background()

	Context("TC-CASCADE: Cross-Resource Deletion Behavior", func() {
		It("TC-CASCADE01: Delete VaultPolicy referenced by VaultRole", func() {
			policyName := uniqueName("tc-cascade01-pol")
			roleName := uniqueName("tc-cascade01-role")
			expectedVaultPolicyName := fmt.Sprintf("%s-%s", testNamespace, policyName)
			expectedVaultRoleName := fmt.Sprintf("%s-%s", testNamespace, roleName)

			By("creating a VaultPolicy")
			policy := BuildTestPolicy(policyName)
			policy.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyDelete
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active")
			ExpectPolicyActive(ctx, policyName)

			By("verifying policy exists in Vault")
			ExpectPolicyInVault(ctx, expectedVaultPolicyName)

			By("creating a VaultRole referencing the policy")
			role := BuildTestRole(roleName, "default", policyName)
			err = utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for role to become Active")
			ExpectRoleActive(ctx, roleName)

			By("verifying role exists in Vault")
			ExpectRoleInVault(ctx, "kubernetes", expectedVaultRoleName)

			By("deleting the policy while role still references it")
			CleanupPolicy(ctx, policyName)

			By("verifying the policy is removed from Vault")
			ExpectPolicyNotInVault(ctx, expectedVaultPolicyName)

			By("verifying the role still exists (not cascade-deleted)")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			exists, err := vaultClient.RoleExists(ctx, "kubernetes", expectedVaultRoleName)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeTrue(), "Role should still exist after policy deletion")

			By("cleaning up the role")
			CleanupRole(ctx, roleName)
		})

		It("TC-CASCADE02: Delete VaultConnection with dependent resources", func() {
			connName := uniqueName("tc-cascade02-conn")
			policyName := uniqueName("tc-cascade02-pol")
			tokenSecretName := uniqueName("tc-cascade02-secret")

			By("creating a dedicated child token for the new connection")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			// Create a child token so that revoking it on connection deletion
			// does not invalidate the root test token used by other tests.
			childToken, err := vaultClient.CreateToken(ctx, []string{operatorPolicyName}, "1h")
			Expect(err).NotTo(HaveOccurred())
			err = utils.CreateSecret(ctx, testNamespace, tokenSecretName, map[string][]byte{
				"token": []byte(childToken),
			})
			Expect(err).NotTo(HaveOccurred())

			By("creating a secondary VaultConnection")
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name: connName,
				},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: vaultK8sAddr,
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name:      tokenSecretName,
								Namespace: testNamespace,
								Key:       "token",
							},
						},
					},
					HealthCheckInterval: "10s",
				},
			}
			err = utils.CreateVaultConnectionCR(ctx, conn)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for connection to become Active")
			Eventually(func(g Gomega) {
				vc, err := utils.GetVaultConnection(ctx, connName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(string(vc.Status.Phase)).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("creating a policy using the secondary connection")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: connName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/cascade-test/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			}
			err = utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active")
			ExpectPolicyActive(ctx, policyName)

			By("deleting the secondary VaultConnection")
			_ = utils.DeleteVaultConnectionCR(ctx, connName)
			_ = utils.WaitForDeletion(
				ctx, &vaultv1alpha1.VaultConnection{},
				connName, "",
				30*time.Second, 2*time.Second,
			)

			By("verifying the policy still exists in K8s (not cascade-deleted)")
			p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(p).NotTo(BeNil())

			By("cleaning up")
			CleanupPolicy(ctx, policyName)
			_ = utils.DeleteSecret(ctx, testNamespace, tokenSecretName)
		})
	})
})
