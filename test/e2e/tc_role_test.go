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

var _ = Describe("VaultRole Tests", Ordered, Label("module"), func() {
	// Test configuration
	const (
		roleName       = "tc-vr-role"
		rolePolicyName = "tc-vr-policy"
		roleSAName     = "tc-vr-sa"
	)

	ctx := context.Background()

	BeforeAll(func() {
		By("creating test service account for role tests")
		_ = utils.CreateServiceAccount(ctx, testNamespace, roleSAName)

		By("creating test policy for role binding")
		policy := &vaultv1alpha1.VaultPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rolePolicyName,
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
		err := utils.CreateVaultPolicyCR(ctx, policy)
		Expect(err).NotTo(HaveOccurred())

		Eventually(func(g Gomega) {
			status, err := utils.GetVaultPolicyStatus(
				ctx, rolePolicyName, testNamespace,
			)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(status).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterAll(func() {
		By("cleaning up VaultRole test resources")
		_ = utils.DeleteVaultRoleCR(ctx, roleName, testNamespace)
		_ = utils.DeleteVaultPolicyCR(
			ctx, rolePolicyName, testNamespace,
		)
		_ = utils.DeleteServiceAccount(
			ctx, testNamespace, roleSAName,
		)
	})

	Context("TC-VR: VaultRole Lifecycle", func() {
		It("TC-VR01: Create namespaced VaultRole", func() {
			By("creating VaultRole resource")
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      roleName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   sharedVaultConnectionName,
					ServiceAccounts: []string{roleSAName},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultPolicy",
							Name:      rolePolicyName,
							Namespace: testNamespace,
						},
					},
					TokenTTL: "30m",
				},
			}
			err := utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred(),
				"Failed to create VaultRole")

			By("waiting for VaultRole to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultRoleStatus(
					ctx, roleName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Equal("Active"),
					"VaultRole not active, got: %s", status,
				)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying VaultRole has namespaced vaultRoleName")
			r, err := utils.GetVaultRole(
				ctx, roleName, testNamespace,
			)
			Expect(err).NotTo(HaveOccurred())
			expectedRoleName := fmt.Sprintf(
				"%s-%s", testNamespace, roleName,
			)
			Expect(r.Status.VaultRoleName).To(
				Equal(expectedRoleName),
			)

			By("verifying VaultRole has bound service accounts")
			Expect(r.Status.BoundServiceAccounts).To(
				ContainElement(fmt.Sprintf("%s/%s", testNamespace, roleSAName)),
			)
		})

		It("TC-VR02: Verify role configuration in Vault", func() {
			expectedRoleName := fmt.Sprintf(
				"%s-%s", testNamespace, roleName,
			)
			expectedPolicyName := fmt.Sprintf(
				"%s-%s", testNamespace, rolePolicyName,
			)

			By("reading role configuration from Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			var roleData map[string]interface{}
			Eventually(func(g Gomega) {
				var readErr error
				roleData, readErr = vaultClient.ReadAuthRole(
					ctx, "kubernetes", expectedRoleName,
				)
				g.Expect(readErr).NotTo(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("parsing role data and verifying configuration")
			// Marshal/unmarshal to convert map[string]interface{}
			// into a typed struct for clean field access
			dataJSON, err := json.Marshal(roleData)
			Expect(err).NotTo(HaveOccurred())

			var roleConfig struct {
				BoundSANames []string `json:"bound_service_account_names"`
				BoundSANS    []string `json:"bound_service_account_namespaces"`
				Policies     []string `json:"token_policies"`
				TokenTTL     int      `json:"token_ttl"`
			}
			err = json.Unmarshal(dataJSON, &roleConfig)
			Expect(err).NotTo(HaveOccurred(),
				"Failed to parse role data: %s", string(dataJSON))

			By("verifying bound service accounts (namespace-scoped)")
			Expect(roleConfig.BoundSANames).To(
				ContainElement(roleSAName),
				"Role should have test SA as bound service account",
			)
			Expect(roleConfig.BoundSANS).To(
				ConsistOf(testNamespace),
				"Role should only be bound to its own namespace",
			)

			By("verifying policies are attached with namespace prefix")
			Expect(roleConfig.Policies).To(
				ContainElement(expectedPolicyName),
				"Role should have namespaced policy attached",
			)

			By("verifying token TTL configuration")
			// tokenTTL is "30m" = 1800 seconds
			Expect(roleConfig.TokenTTL).To(Equal(1800),
				"Role should have token_ttl of 30m (1800 seconds)")
		})

		It("TC-VR03-DEL: Remove role from Vault when VaultRole is deleted", func() {
			tempRoleName := "tc-vr03-temp"
			tempPolicyName := "tc-vr03-policy"
			tempSAName := "tc-vr03-sa"
			expectedRoleVaultName := fmt.Sprintf(
				"%s-%s", testNamespace, tempRoleName,
			)
			expectedPolicyVaultName := fmt.Sprintf(
				"%s-%s", testNamespace, tempPolicyName,
			)

			By("creating a temporary service account")
			_ = utils.CreateServiceAccount(
				ctx, testNamespace, tempSAName,
			)

			By("creating a temporary policy for the role")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tempPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/temp-role/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for temp policy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(
					ctx, tempPolicyName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("creating a temporary VaultRole")
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tempRoleName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   sharedVaultConnectionName,
					ServiceAccounts: []string{tempSAName},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultPolicy",
							Name:      tempPolicyName,
							Namespace: testNamespace,
						},
					},
					TokenTTL: "10m",
				},
			}
			err = utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultRole to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultRoleStatus(
					ctx, tempRoleName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying role exists in Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				exists, err := vaultClient.RoleExists(
					ctx, "kubernetes", expectedRoleVaultName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeTrue(),
					"Role should exist in Vault")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("deleting the VaultRole")
			err = utils.DeleteVaultRoleCR(
				ctx, tempRoleName, testNamespace,
			)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultRole resource is deleted from Kubernetes")
			err = utils.WaitForDeletion(
				ctx, &vaultv1alpha1.VaultRole{},
				tempRoleName, testNamespace,
				30*time.Second, 2*time.Second,
			)
			Expect(err).NotTo(HaveOccurred(),
				"VaultRole CR should be deleted")

			By("verifying role is removed from Vault")
			Eventually(func(g Gomega) {
				exists, err := vaultClient.RoleExists(
					ctx, "kubernetes", expectedRoleVaultName,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeFalse(),
					"Role should be removed from Vault")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up temp resources")
			_ = utils.DeleteVaultPolicyCR(
				ctx, tempPolicyName, testNamespace,
			)
			_ = utils.DeleteServiceAccount(
				ctx, testNamespace, tempSAName,
			)
			_ = vaultClient.DeletePolicy(
				ctx, expectedPolicyVaultName,
			)
		})
	})
})
