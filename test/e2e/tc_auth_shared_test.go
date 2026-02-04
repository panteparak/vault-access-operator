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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// AuthTestSuite defines a reusable test suite that runs against any AuthProvider.
// This allows the same tests to verify behavior across different auth methods.
var _ = Describe("TC-AU-SHARED: Authentication Method Compatibility",
	Label("auth"), func() {
		// Test with each available auth provider
		authProviders := []struct {
			name     string
			provider func() AuthProvider
		}{
			{"kubernetes", func() AuthProvider {
				return NewKubernetesAuthProvider()
			}},
			{"jwt", func() AuthProvider {
				return NewJWTAuthProvider()
			}},
			{"approle", func() AuthProvider {
				return NewAppRoleAuthProvider()
			}},
			{"oidc", func() AuthProvider {
				return NewOIDCAuthProvider()
			}},
		}

		ctx := context.Background()

		for _, ap := range authProviders {
			Context(fmt.Sprintf("with %s auth", ap.name),
				Ordered, func() {
					var (
						provider       AuthProvider
						testSAName     string
						testRoleName   string
						testPolicyName string
						skipReason     string
					)

					BeforeAll(func() {
						provider = ap.provider()
						testSAName = fmt.Sprintf(
							"tc-shared-%s-sa", ap.name,
						)
						testRoleName = fmt.Sprintf(
							"tc-shared-%s-role", ap.name,
						)
						testPolicyName = fmt.Sprintf(
							"tc-shared-%s-policy", ap.name,
						)

						By(fmt.Sprintf(
							"setting up %s auth provider",
							ap.name,
						))
						var err error
						skipReason, err = provider.Setup()
						if err != nil {
							Fail(fmt.Sprintf(
								"Failed to setup %s auth: %v",
								ap.name, err,
							))
						}
						if skipReason != "" {
							Skip(fmt.Sprintf(
								"%s auth not available: %s",
								ap.name, skipReason,
							))
						}

						By("creating test service account")
						_ = utils.CreateServiceAccount(
							ctx, testNamespace, testSAName,
						)

						By("creating test policy in Vault")
						vaultClient, err :=
							utils.GetTestVaultClient()
						Expect(err).NotTo(HaveOccurred())

						policyHCL := `
path "secret/data/shared-test/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/health" {
  capabilities = ["read"]
}
`
						err = vaultClient.WritePolicy(
							ctx, testPolicyName, policyHCL,
						)
						Expect(err).NotTo(HaveOccurred())

						By("creating Vault role for test SA")
						err = provider.CreateRole(
							testRoleName,
							testNamespace,
							testSAName,
							[]string{testPolicyName, "default"},
						)
						Expect(err).NotTo(HaveOccurred())
					})

					AfterAll(func() {
						if skipReason != "" {
							return // Nothing to clean up
						}

						By("cleaning up shared test resources")

						// Delete Vault role
						if provider != nil {
							_ = provider.DeleteRole(
								testRoleName,
							)
						}

						// Delete Vault policy
						vaultClient, err :=
							utils.GetTestVaultClient()
						if err == nil {
							_ = vaultClient.DeletePolicy(
								ctx, testPolicyName,
							)
						}

						// Delete service account
						_ = utils.DeleteServiceAccount(
							ctx, testNamespace, testSAName,
						)

						// Cleanup provider
						if provider != nil {
							_ = provider.Cleanup()
						}
					})

					It("should authenticate successfully "+
						"with valid credentials", func() {
						By("getting service account token")
						token, err := provider.GetToken(
							testNamespace, testSAName,
						)
						Expect(err).NotTo(HaveOccurred())
						Expect(token).NotTo(BeEmpty())

						By("logging into Vault")
						vaultToken, err := provider.Login(
							testRoleName, token,
						)
						Expect(err).NotTo(HaveOccurred())
						Expect(vaultToken).NotTo(BeEmpty())
					})

					It("should reject authentication "+
						"with invalid role", func() {
						By("getting service account token")
						token, err := provider.GetToken(
							testNamespace, testSAName,
						)
						Expect(err).NotTo(HaveOccurred())

						By("attempting login with " +
							"non-existent role")
						_, err = provider.Login(
							"non-existent-role", token,
						)
						Expect(err).To(HaveOccurred())
					})

					It("should work with VaultPolicy CRD",
						func() {
							policyName := fmt.Sprintf(
								"tc-shared-%s-crd-policy",
								ap.name,
							)
							expectedVaultName := fmt.Sprintf(
								"%s-%s",
								testNamespace, policyName,
							)

							vaultClient, err :=
								utils.GetTestVaultClient()
							Expect(err).NotTo(HaveOccurred())

							By("creating VaultPolicy using " +
								"shared VaultConnection")
							err = utils.CreateVaultPolicyCR(
								ctx,
								&vaultv1alpha1.VaultPolicy{
									ObjectMeta: metav1.ObjectMeta{
										Name:      policyName,
										Namespace: testNamespace,
									},
									Spec: vaultv1alpha1.VaultPolicySpec{
										ConnectionRef: sharedVaultConnectionName,
										Rules: []vaultv1alpha1.PolicyRule{
											{
												Path: fmt.Sprintf(
													"secret/data/%s/*",
													ap.name,
												),
												Capabilities: []vaultv1alpha1.Capability{"read"},
											},
										},
									},
								},
							)
							Expect(err).NotTo(HaveOccurred())

							By("waiting for VaultPolicy " +
								"to become Active")
							Eventually(func(g Gomega) {
								status, err :=
									utils.GetVaultPolicyStatus(
										ctx, policyName,
										testNamespace,
									)
								g.Expect(err).NotTo(
									HaveOccurred(),
								)
								g.Expect(status).To(
									Equal("Active"),
								)
							}, 30*time.Second,
								2*time.Second,
							).Should(Succeed())

							By("verifying policy " +
								"exists in Vault")
							policy, err :=
								vaultClient.ReadPolicy(
									ctx, expectedVaultName,
								)
							Expect(err).NotTo(HaveOccurred())
							Expect(policy).To(ContainSubstring(
								fmt.Sprintf(
									"secret/data/%s/*",
									ap.name,
								),
							))

							By("cleaning up VaultPolicy")
							_ = utils.DeleteVaultPolicyCR(
								ctx, policyName,
								testNamespace,
							)

							Eventually(func(g Gomega) {
								exists, err :=
									utils.ResourceExists(
										ctx,
										&vaultv1alpha1.VaultPolicy{},
										policyName,
										testNamespace,
									)
								g.Expect(err).NotTo(
									HaveOccurred(),
								)
								g.Expect(exists).To(BeFalse())
							}, 30*time.Second,
								2*time.Second,
							).Should(Succeed())
						})

					It("should work with VaultRole CRD",
						func() {
							roleName := fmt.Sprintf(
								"tc-shared-%s-crd-role",
								ap.name,
							)
							roleSAName := fmt.Sprintf(
								"tc-shared-%s-crd-sa",
								ap.name,
							)
							rolePolicyName := fmt.Sprintf(
								"tc-shared-%s-crd-role-policy",
								ap.name,
							)
							expectedVaultRoleName := fmt.Sprintf(
								"%s-%s",
								testNamespace, roleName,
							)

							vaultClient, err :=
								utils.GetTestVaultClient()
							Expect(err).NotTo(HaveOccurred())

							By("creating SA for VaultRole test")
							_ = utils.CreateServiceAccount(
								ctx, testNamespace, roleSAName,
							)

							By("creating VaultPolicy for " +
								"the role to reference")
							err = utils.CreateVaultPolicyCR(
								ctx,
								&vaultv1alpha1.VaultPolicy{
									ObjectMeta: metav1.ObjectMeta{
										Name:      rolePolicyName,
										Namespace: testNamespace,
									},
									Spec: vaultv1alpha1.VaultPolicySpec{
										ConnectionRef: sharedVaultConnectionName,
										Rules: []vaultv1alpha1.PolicyRule{
											{
												Path: fmt.Sprintf(
													"secret/data/%s/*",
													ap.name,
												),
												Capabilities: []vaultv1alpha1.Capability{"read"},
											},
										},
									},
								},
							)
							Expect(err).NotTo(HaveOccurred())

							By("waiting for VaultPolicy " +
								"to become Active")
							Eventually(func(g Gomega) {
								status, err :=
									utils.GetVaultPolicyStatus(
										ctx, rolePolicyName,
										testNamespace,
									)
								g.Expect(err).NotTo(
									HaveOccurred(),
								)
								g.Expect(status).To(
									Equal("Active"),
								)
							}, 30*time.Second,
								2*time.Second,
							).Should(Succeed())

							By("creating VaultRole using " +
								"shared VaultConnection")
							err = utils.CreateVaultRoleCR(
								ctx,
								&vaultv1alpha1.VaultRole{
									ObjectMeta: metav1.ObjectMeta{
										Name:      roleName,
										Namespace: testNamespace,
									},
									Spec: vaultv1alpha1.VaultRoleSpec{
										ConnectionRef: sharedVaultConnectionName,
										ServiceAccounts: []string{
											roleSAName,
										},
										Policies: []vaultv1alpha1.PolicyReference{
											{
												Kind:      "VaultPolicy",
												Name:      rolePolicyName,
												Namespace: testNamespace,
											},
										},
										TokenTTL: "1h",
									},
								},
							)
							Expect(err).NotTo(HaveOccurred())

							By("waiting for VaultRole " +
								"to become Active")
							Eventually(func(g Gomega) {
								status, err :=
									utils.GetVaultRoleStatus(
										ctx, roleName,
										testNamespace,
									)
								g.Expect(err).NotTo(
									HaveOccurred(),
								)
								g.Expect(status).To(
									Equal("Active"),
								)
							}, 2*time.Minute,
								5*time.Second,
							).Should(Succeed())

							By("verifying role " +
								"exists in Vault")
							roleData, err :=
								vaultClient.ReadAuthRole(
									ctx, "kubernetes",
									expectedVaultRoleName,
								)
							Expect(err).NotTo(HaveOccurred())
							Expect(roleData).NotTo(BeNil())

							By("cleaning up VaultRole, " +
								"VaultPolicy, and SA")
							_ = utils.DeleteVaultRoleCR(
								ctx, roleName,
								testNamespace,
							)
							_ = utils.DeleteVaultPolicyCR(
								ctx, rolePolicyName,
								testNamespace,
							)
							_ = utils.DeleteServiceAccount(
								ctx, testNamespace, roleSAName,
							)

							Eventually(func(g Gomega) {
								exists, err :=
									utils.ResourceExists(
										ctx,
										&vaultv1alpha1.VaultRole{},
										roleName,
										testNamespace,
									)
								g.Expect(err).NotTo(
									HaveOccurred(),
								)
								g.Expect(exists).To(BeFalse())
							}, 30*time.Second,
								2*time.Second,
							).Should(Succeed())
						})
				})
		}
	})
