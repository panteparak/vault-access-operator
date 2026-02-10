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
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("VaultClusterRole Tests", Ordered, Label("module"), func() {
	const (
		clusterRoleName       = "tc-cr-cluster-role"
		clusterRolePolicyName = "tc-cr-cluster-policy"
		clusterRoleSAName     = "tc-cr-sa"
		namespacedPolicyName  = "tc-cr-ns-policy"
	)

	ctx := context.Background()

	BeforeAll(func() {
		By("creating test service account for cluster role tests")
		_ = utils.CreateServiceAccount(
			ctx, testNamespace, clusterRoleSAName,
		)

		By("creating VaultClusterPolicy for cluster role binding")
		clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: clusterRolePolicyName,
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
					},
				},
			},
		}
		err := utils.CreateVaultClusterPolicyCR(
			ctx, clusterPolicy,
		)
		Expect(err).NotTo(HaveOccurred())

		By("creating namespaced VaultPolicy for cluster role")
		nsPolicy := &vaultv1alpha1.VaultPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      namespacedPolicyName,
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
							vaultv1alpha1.CapabilityRead,
							vaultv1alpha1.CapabilityList,
						},
					},
				},
			},
		}
		err = utils.CreateVaultPolicyCR(ctx, nsPolicy)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for policies to become Active")
		Eventually(func(g Gomega) {
			status, err := utils.GetVaultClusterPolicyStatus(
				ctx, clusterRolePolicyName,
			)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(status).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			status, err := utils.GetVaultPolicyStatus(
				ctx, namespacedPolicyName, testNamespace,
			)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(status).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterAll(func() {
		By("cleaning up VaultClusterRole test resources")
		_ = utils.DeleteVaultClusterRoleCR(
			ctx, clusterRoleName,
		)
		_ = utils.DeleteVaultClusterPolicyCR(
			ctx, clusterRolePolicyName,
		)
		_ = utils.DeleteVaultPolicyCR(
			ctx, namespacedPolicyName, testNamespace,
		)
		_ = utils.DeleteServiceAccount(
			ctx, testNamespace, clusterRoleSAName,
		)
	})

	Context("TC-CR: VaultClusterRole Lifecycle", func() {
		It("TC-CR01: Create VaultClusterRole referencing "+
			"multiple policies", func() {
			By("creating VaultClusterRole resource")
			role := &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterRoleName,
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: sharedVaultConnectionName,
					AuthPath:      "auth/kubernetes",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      clusterRoleSAName,
							Namespace: testNamespace,
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: clusterRolePolicyName,
						},
						{
							Kind:      "VaultPolicy",
							Name:      namespacedPolicyName,
							Namespace: testNamespace,
						},
					},
					TokenTTL:    "1h",
					TokenMaxTTL: "30m",
				},
			}
			err := utils.CreateVaultClusterRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred(),
				"Failed to create VaultClusterRole")

			By("waiting for VaultClusterRole to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultClusterRoleStatus(
					ctx, clusterRoleName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Equal("Active"),
					"VaultClusterRole not active, got: %s",
					status,
				)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying VaultClusterRole has correct status")
			r, err := utils.GetVaultClusterRole(
				ctx, clusterRoleName,
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Status.VaultRoleName).To(
				Equal(clusterRoleName),
			)

			By("verifying resolved policies")
			Expect(r.Status.ResolvedPolicies).To(
				ContainElement(clusterRolePolicyName),
			)
		})

		It("TC-CR02: Verify cluster role configuration "+
			"in Vault", func() {
			expectedNSPolicyName := fmt.Sprintf(
				"%s-%s", testNamespace, namespacedPolicyName,
			)

			By("reading role configuration from Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			var roleData map[string]interface{}
			Eventually(func(g Gomega) {
				var readErr error
				roleData, readErr = vaultClient.ReadAuthRole(
					ctx, "kubernetes", clusterRoleName,
				)
				g.Expect(readErr).NotTo(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("parsing and verifying role configuration")
			dataJSON, err := json.Marshal(roleData)
			Expect(err).NotTo(HaveOccurred())

			var roleConfig struct {
				BoundSANames []string `json:"bound_service_account_names"`
				BoundSANS    []string `json:"bound_service_account_namespaces"`
				Policies     []string `json:"token_policies"`
				TokenTTL     int      `json:"token_ttl"`
				TokenMaxTTL  int      `json:"token_max_ttl"`
			}
			err = json.Unmarshal(dataJSON, &roleConfig)
			Expect(err).NotTo(HaveOccurred(),
				"Failed to parse role data: %s",
				string(dataJSON))

			By("verifying bound service accounts")
			Expect(roleConfig.BoundSANames).To(
				ContainElement(clusterRoleSAName),
				"Role should have test SA bound",
			)

			By("verifying bound namespaces")
			Expect(roleConfig.BoundSANS).To(
				ContainElement(testNamespace),
				"Role should have test namespace bound",
			)

			By("verifying policies are attached")
			Expect(roleConfig.Policies).To(
				ContainElement(clusterRolePolicyName),
				"Should have cluster policy attached",
			)
			Expect(roleConfig.Policies).To(
				ContainElement(expectedNSPolicyName),
				"Should have namespaced policy attached",
			)

			By("verifying token TTL configuration")
			// tokenTTL "5m" = 300 seconds
			Expect(roleConfig.TokenTTL).To(Equal(300),
				"token_ttl should be 300 seconds")
			// tokenMaxTTL "30m" = 1800 seconds
			Expect(roleConfig.TokenMaxTTL).To(Equal(1800),
				"token_max_ttl should be 1800 seconds")
		})

		It("TC-CR03-DEL: Remove cluster role from Vault "+
			"on deletion", func() {
			tempClusterRoleName := "tc-cr03-temp"

			By("creating temporary VaultClusterRole")
			role := &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: tempClusterRoleName,
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: sharedVaultConnectionName,
					AuthPath:      "auth/kubernetes",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      clusterRoleSAName,
							Namespace: testNamespace,
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: clusterRolePolicyName,
						},
					},
					TokenTTL: "5m",
				},
			}
			err := utils.CreateVaultClusterRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultClusterRole to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultClusterRoleStatus(
					ctx, tempClusterRoleName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying role exists in Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				exists, err := vaultClient.RoleExists(
					ctx, "kubernetes", tempClusterRoleName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeTrue())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("deleting the VaultClusterRole")
			err = utils.DeleteVaultClusterRoleCR(
				ctx, tempClusterRoleName,
			)
			Expect(err).NotTo(HaveOccurred())

			By("verifying role is removed from Vault")
			Eventually(func(g Gomega) {
				exists, err := vaultClient.RoleExists(
					ctx, "kubernetes", tempClusterRoleName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeFalse(),
					"Role should be removed from Vault")
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})
	})

	// NOTE: TC-CR04 and TC-CR05 (Error Handling) removed - they duplicate TC-EH01 and TC-EH02
	// in tc_error_test.go which test the same invalid connection and missing policy scenarios
	// for VaultRole. The behavior is identical for VaultClusterRole.
})
