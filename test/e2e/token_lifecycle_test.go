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
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Token Lifecycle", Ordered,
	Label("auth"), func() {
		const (
			tokenLifecycleNamespace = "e2e-token-lifecycle"
			bootstrapSecretName     = "vault-bootstrap-token"
			bootstrapConnectionName = "e2e-bootstrap-conn"
			k8sAuthConnectionName   = "e2e-k8s-auth-conn"
			operatorRole            = "vault-access-operator"
			operatorPolicy          = "vault-access-operator"
		)

		ctx := context.Background()

		BeforeAll(func() {
			By("creating token lifecycle test namespace")
			_ = utils.CreateNamespace(
				ctx, tokenLifecycleNamespace,
			)

			By("waiting for Vault API to be accessible")
			// Vault runs as external docker-compose service, not as k8s pods.
			// Check health via the Vault API client instead.
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred(), "Failed to get Vault client")
			Eventually(func(g Gomega) {
				healthy, err := vaultClient.Health(ctx)
				g.Expect(err).NotTo(HaveOccurred(), "Vault health check failed")
				g.Expect(healthy).To(BeTrue(), "Vault not healthy (not initialized or sealed)")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("creating bootstrap token secret " +
				"with Vault root token")
			_ = utils.CreateSecret(
				ctx, tokenLifecycleNamespace,
				bootstrapSecretName,
				map[string][]byte{"token": []byte("root")},
			)

			// The operator policy ("vault-access-operator") is created
			// by BeforeSuite with comprehensive permissions.
			// Do NOT overwrite it here — that would reduce permissions
			// for ALL tokens referencing this policy (Vault evaluates
			// policies dynamically at access time).
		})

		AfterAll(func() {
			By("cleaning up token lifecycle " +
				"test resources")

			// Delete VaultConnections
			_ = utils.DeleteVaultConnectionCR(
				ctx, bootstrapConnectionName,
			)
			_ = utils.DeleteVaultConnectionCR(
				ctx, k8sAuthConnectionName,
			)

			// Wait for VaultConnections to be deleted
			Eventually(func(g Gomega) {
				exists, err :=
					utils.ClusterResourceExists(
						ctx,
						&vaultv1alpha1.VaultConnection{},
						bootstrapConnectionName,
					)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeFalse(),
					"VaultConnection should be deleted")
			}, 60*time.Second,
				2*time.Second,
			).Should(Succeed())

			Eventually(func(g Gomega) {
				exists, err :=
					utils.ClusterResourceExists(
						ctx,
						&vaultv1alpha1.VaultConnection{},
						k8sAuthConnectionName,
					)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeFalse(),
					"VaultConnection should be deleted")
			}, 60*time.Second,
				2*time.Second,
			).Should(Succeed())

			// Do NOT disable kubernetes auth or delete the shared
			// operator policy — both are shared resources created by
			// BeforeSuite/Makefile and used by subsequent auth tests
			// (TC-AU01, TC-AU-SHARED with kubernetes auth, etc.).

			// Delete namespace
			_ = utils.DeleteNamespace(
				ctx, tokenLifecycleNamespace,
			)
		})

		// Use CI-aware timeouts
		SetDefaultEventuallyTimeout(defaultTimeout)
		SetDefaultEventuallyPollingInterval(
			3 * time.Second,
		)

		Context("Bootstrap Flow", func() {
			It("should bootstrap Kubernetes auth "+
				"using bootstrap token", func() {
				autoRevokeFalse := false

				By("creating VaultConnection with " +
					"bootstrap configuration")
				err := utils.CreateVaultConnectionCR(
					ctx,
					&vaultv1alpha1.VaultConnection{
						ObjectMeta: metav1.ObjectMeta{
							Name: bootstrapConnectionName,
						},
						Spec: vaultv1alpha1.VaultConnectionSpec{
							Address: fmt.Sprintf(
								"http://vault.%s.svc.cluster.local:8200",
								vaultNamespace,
							),
							Auth: vaultv1alpha1.AuthConfig{
								Bootstrap: &vaultv1alpha1.BootstrapAuth{
									SecretRef: vaultv1alpha1.SecretKeySelector{
										Name:      bootstrapSecretName,
										Namespace: tokenLifecycleNamespace,
										Key:       "token",
									},
									AutoRevoke: &autoRevokeFalse,
								},
								Kubernetes: &vaultv1alpha1.KubernetesAuth{
									Role:           operatorRole,
									AuthPath:       "kubernetes",
									KubernetesHost: os.Getenv("E2E_K8S_HOST"),
									TokenDuration: metav1.Duration{
										Duration: time.Hour,
									},
								},
							},
							HealthCheckInterval: "30s",
						},
					},
				)
				Expect(err).NotTo(HaveOccurred(),
					"Failed to create VaultConnection "+
						"with bootstrap")

				By("waiting for VaultConnection " +
					"to become Active")
				Eventually(func(g Gomega) {
					status, err :=
						utils.GetVaultConnectionStatus(
							ctx,
							bootstrapConnectionName,
							"",
						)
					g.Expect(err).NotTo(
						HaveOccurred(),
					)
					g.Expect(status).To(
						Equal("Active"),
						"VaultConnection not active, "+
							"got: %s", status,
					)
				}, 3*time.Minute,
					5*time.Second,
				).Should(Succeed())
			})

			It("should complete bootstrap and "+
				"transition to Kubernetes auth",
				func() {
					By("verifying bootstrapComplete " +
						"is true")
					Eventually(func(g Gomega) {
						conn, err :=
							utils.GetVaultConnection(
								ctx,
								bootstrapConnectionName,
								"",
							)
						g.Expect(err).NotTo(
							HaveOccurred(),
						)
						g.Expect(
							conn.Status.AuthStatus,
						).NotTo(BeNil())
						g.Expect(
							conn.Status.AuthStatus.BootstrapComplete,
						).To(BeTrue(),
							"Bootstrap not complete")
					}).Should(Succeed())

					By("verifying authMethod " +
						"is kubernetes")
					conn, err :=
						utils.GetVaultConnection(
							ctx,
							bootstrapConnectionName,
							"",
						)
					Expect(err).NotTo(HaveOccurred())
					Expect(
						conn.Status.AuthStatus.AuthMethod,
					).To(Equal("kubernetes"))

					By("verifying " +
						"bootstrapCompletedAt is set")
					Expect(
						conn.Status.AuthStatus.BootstrapCompletedAt,
					).NotTo(BeNil(),
						"bootstrapCompletedAt "+
							"should be set")
				})

			It("should have Kubernetes auth "+
				"enabled in Vault", func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("verifying Kubernetes auth " +
					"method is enabled")
				Eventually(func(g Gomega) {
					auths, err :=
						vaultClient.ListAuth(ctx)
					g.Expect(err).NotTo(
						HaveOccurred(),
					)
					_, exists :=
						auths["kubernetes/"]
					g.Expect(exists).To(BeTrue(),
						"Kubernetes auth method "+
							"not found in vault "+
							"auth list")
				}).Should(Succeed())
			})

			It("should have operator role "+
				"created in Vault", func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("verifying operator role exists " +
					"with correct configuration")
				Eventually(func(g Gomega) {
					roleData, err :=
						vaultClient.ReadAuthRole(
							ctx, "kubernetes",
							operatorRole,
						)
					g.Expect(err).NotTo(
						HaveOccurred(),
					)
					g.Expect(roleData).To(
						HaveKey(
							"bound_service_account_names",
						),
					)
				}).Should(Succeed())
			})

			It("should not re-bootstrap on "+
				"subsequent reconciles", func() {
				By("getting current " +
					"bootstrapCompletedAt timestamp " +
					"and resourceVersion")
				conn, err :=
					utils.GetVaultConnection(
						ctx,
						bootstrapConnectionName, "",
					)
				Expect(err).NotTo(HaveOccurred())
				Expect(
					conn.Status.AuthStatus,
				).NotTo(BeNil())
				Expect(
					conn.Status.AuthStatus.BootstrapCompletedAt,
				).NotTo(BeNil())

				originalTimestamp :=
					conn.Status.AuthStatus.BootstrapCompletedAt.Format(
						time.RFC3339,
					)
				originalResourceVersion :=
					conn.ResourceVersion

				By("triggering reconciliation " +
					"via annotation")
				patch := client.MergeFrom(
					conn.DeepCopy(),
				)
				if conn.Annotations == nil {
					conn.Annotations =
						make(map[string]string)
				}
				conn.Annotations["reconcile-trigger"] =
					fmt.Sprintf(
						"%d", time.Now().Unix(),
					)
				err = utils.PatchObject(
					ctx, conn, patch,
				)
				Expect(err).NotTo(HaveOccurred())

				// Wait for reconciliation
				Eventually(func(g Gomega) {
					c, err :=
						utils.GetVaultConnection(
							ctx,
							bootstrapConnectionName,
							"",
						)
					g.Expect(err).NotTo(
						HaveOccurred(),
					)
					g.Expect(
						c.ResourceVersion,
					).NotTo(
						Equal(originalResourceVersion),
						"resourceVersion should "+
							"change after annotation",
					)
				}, 30*time.Second,
					2*time.Second,
				).Should(Succeed())

				By("verifying " +
					"bootstrapCompletedAt " +
					"timestamp hasn't changed")
				conn, err =
					utils.GetVaultConnection(
						ctx,
						bootstrapConnectionName, "",
					)
				Expect(err).NotTo(HaveOccurred())
				Expect(
					conn.Status.AuthStatus,
				).NotTo(BeNil())
				Expect(
					conn.Status.AuthStatus.BootstrapCompletedAt,
				).NotTo(BeNil())
				newTimestamp :=
					conn.Status.AuthStatus.BootstrapCompletedAt.Format(
						time.RFC3339,
					)
				Expect(newTimestamp).To(
					Equal(originalTimestamp),
					"bootstrapCompletedAt should "+
						"not change after "+
						"re-reconcile",
				)

				By("verifying connection " +
					"is still Active")
				status, err :=
					utils.GetVaultConnectionStatus(
						ctx,
						bootstrapConnectionName, "",
					)
				Expect(err).NotTo(HaveOccurred())
				Expect(status).To(Equal("Active"))
			})

			It("should have token expiration "+
				"information", func() {
				By("verifying tokenExpiration " +
					"is set")
				conn, err :=
					utils.GetVaultConnection(
						ctx,
						bootstrapConnectionName, "",
					)
				Expect(err).NotTo(HaveOccurred())
				Expect(
					conn.Status.AuthStatus,
				).NotTo(BeNil())
				Expect(
					conn.Status.AuthStatus.TokenExpiration,
				).NotTo(BeNil(),
					"tokenExpiration should be set")
			})

			It("should have Vault version "+
				"in status", func() {
				By("verifying vaultVersion is set")
				conn, err :=
					utils.GetVaultConnection(
						ctx,
						bootstrapConnectionName, "",
					)
				Expect(err).NotTo(HaveOccurred())
				Expect(
					conn.Status.VaultVersion,
				).To(
					ContainSubstring("1."),
					"Expected Vault version "+
						"like 1.x.x",
				)
			})
		})

		Context("Kubernetes Auth Without Bootstrap",
			func() {
				It("should connect using "+
					"pre-configured Kubernetes auth",
					func() {
						By("creating VaultConnection " +
							"with only Kubernetes auth " +
							"(no bootstrap)")
						err :=
							utils.CreateVaultConnectionCR(
								ctx,
								&vaultv1alpha1.VaultConnection{
									ObjectMeta: metav1.ObjectMeta{
										Name: k8sAuthConnectionName,
									},
									Spec: vaultv1alpha1.VaultConnectionSpec{
										Address: fmt.Sprintf(
											"http://vault.%s.svc.cluster.local:8200",
											vaultNamespace,
										),
										Auth: vaultv1alpha1.AuthConfig{
											Kubernetes: &vaultv1alpha1.KubernetesAuth{
												Role:     operatorRole,
												AuthPath: "kubernetes",
												TokenDuration: metav1.Duration{
													Duration: time.Hour,
												},
											},
										},
										HealthCheckInterval: "30s",
									},
								},
							)
						Expect(err).NotTo(
							HaveOccurred(),
							"Failed to create "+
								"VaultConnection "+
								"with K8s auth",
						)

						By("waiting for " +
							"VaultConnection " +
							"to become Active")
						Eventually(func(g Gomega) {
							status, err :=
								utils.GetVaultConnectionStatus(
									ctx,
									k8sAuthConnectionName,
									"",
								)
							g.Expect(err).NotTo(
								HaveOccurred(),
							)
							g.Expect(status).To(
								Equal("Active"),
								"VaultConnection "+
									"not active, "+
									"got: %s", status,
							)
						}, 2*time.Minute,
							5*time.Second,
						).Should(Succeed())
					})

				It("should NOT have "+
					"bootstrapComplete set",
					func() {
						By("verifying " +
							"bootstrapComplete " +
							"is NOT true")
						conn, err :=
							utils.GetVaultConnection(
								ctx,
								k8sAuthConnectionName,
								"",
							)
						Expect(err).NotTo(
							HaveOccurred(),
						)
						if conn.Status.AuthStatus != nil {
							Expect(
								conn.Status.AuthStatus.BootstrapComplete,
							).To(BeFalse(),
								"bootstrapComplete "+
									"should not be "+
									"true when no "+
									"bootstrap was "+
									"configured")
						}
					})

				It("should have authMethod "+
					"set to kubernetes", func() {
					By("verifying authMethod " +
						"is kubernetes")
					conn, err :=
						utils.GetVaultConnection(
							ctx,
							k8sAuthConnectionName, "",
						)
					Expect(err).NotTo(
						HaveOccurred(),
					)
					Expect(
						conn.Status.AuthStatus,
					).NotTo(BeNil())
					Expect(
						conn.Status.AuthStatus.AuthMethod,
					).To(Equal("kubernetes"))
				})

				It("should have Vault version "+
					"in status", func() {
					By("verifying vaultVersion " +
						"is set")
					conn, err :=
						utils.GetVaultConnection(
							ctx,
							k8sAuthConnectionName, "",
						)
					Expect(err).NotTo(
						HaveOccurred(),
					)
					Expect(
						conn.Status.VaultVersion,
					).To(
						ContainSubstring("1."),
						"Expected Vault version "+
							"like 1.x.x",
					)
				})

				It("should have token expiration "+
					"information", func() {
					By("verifying tokenExpiration " +
						"is set")
					conn, err :=
						utils.GetVaultConnection(
							ctx,
							k8sAuthConnectionName, "",
						)
					Expect(err).NotTo(
						HaveOccurred(),
					)
					Expect(
						conn.Status.AuthStatus,
					).NotTo(BeNil())
					Expect(
						conn.Status.AuthStatus.TokenExpiration,
					).NotTo(BeNil(),
						"tokenExpiration "+
							"should be set")
				})
			})

		Context("Token Lifecycle - Renewal",
			Label("slow"), func() {
				const (
					renewalConnectionName = "e2e-renewal-conn"
					renewalRoleName       = "e2e-short-ttl-role"
				)

				AfterEach(func() {
					By("cleaning up renewal " +
						"test connection")
					_ = utils.DeleteVaultConnectionCR(
						ctx, renewalConnectionName,
					)
					// Wait for deletion
					Eventually(func(g Gomega) {
						exists, err :=
							utils.ClusterResourceExists(
								ctx,
								&vaultv1alpha1.VaultConnection{},
								renewalConnectionName,
							)
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(exists).To(BeFalse())
					}, 30*time.Second,
						2*time.Second,
					).Should(Succeed())

					By("cleaning up short-TTL " +
						"Vault role")
					vc, err :=
						utils.GetTestVaultClient()
					if err == nil {
						_ = vc.DeleteAuthRole(
							ctx, "kubernetes",
							renewalRoleName,
						)
					}
				})

				It("TC-LC07: Renew token when "+
					"approaching expiration",
					Label("slow"), func() {
						By("creating a Vault role " +
							"with short TTL (2m) " +
							"for renewal testing")
						vc, err :=
							utils.GetTestVaultClient()
						Expect(err).NotTo(
							HaveOccurred(),
						)
						err = vc.WriteAuthRole(
							ctx, "kubernetes",
							renewalRoleName,
							map[string]interface{}{
								"bound_service_account_names":      "vault-access-operator",
								"bound_service_account_namespaces": "vault-access-operator-system",
								"policies":                         operatorPolicy,
								"ttl":                              "2m",
								"max_ttl":                          "10m",
							},
						)
						Expect(err).NotTo(
							HaveOccurred(),
							"Failed to create "+
								"short-TTL Vault role",
						)

						By("creating VaultConnection " +
							"with short-TTL " +
							"Vault role")
						err =
							utils.CreateVaultConnectionCR(
								ctx,
								&vaultv1alpha1.VaultConnection{
									ObjectMeta: metav1.ObjectMeta{
										Name: renewalConnectionName,
									},
									Spec: vaultv1alpha1.VaultConnectionSpec{
										Address: fmt.Sprintf(
											"http://vault.%s.svc.cluster.local:8200",
											vaultNamespace,
										),
										Auth: vaultv1alpha1.AuthConfig{
											Kubernetes: &vaultv1alpha1.KubernetesAuth{
												Role:     renewalRoleName,
												AuthPath: "kubernetes",
												TokenDuration: metav1.Duration{
													Duration: 10 * time.Minute,
												},
											},
										},
										HealthCheckInterval: "10s",
									},
								},
							)
						Expect(err).NotTo(
							HaveOccurred(),
						)

						By("waiting for " +
							"VaultConnection " +
							"to become Active")
						Eventually(func(g Gomega) {
							status, err :=
								utils.GetVaultConnectionStatus(
									ctx,
									renewalConnectionName,
									"",
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

						By("getting initial " +
							"tokenLastRenewed " +
							"timestamp")
						conn, err :=
							utils.GetVaultConnection(
								ctx,
								renewalConnectionName,
								"",
							)
						Expect(err).NotTo(
							HaveOccurred(),
						)
						initialRenewed := ""
						if conn.Status.AuthStatus != nil &&
							conn.Status.AuthStatus.TokenLastRenewed != nil {
							initialRenewed =
								conn.Status.AuthStatus.TokenLastRenewed.Format(
									time.RFC3339,
								)
						}

						By("waiting for token " +
							"renewal (Vault TTL=2m, " +
							"renewal at ~75% = ~90s)")
						Eventually(func(g Gomega) {
							c, err :=
								utils.GetVaultConnection(
									ctx,
									renewalConnectionName,
									"",
								)
							g.Expect(err).NotTo(
								HaveOccurred(),
							)
							g.Expect(
								c.Status.AuthStatus,
							).NotTo(BeNil())
							g.Expect(
								c.Status.AuthStatus.TokenRenewalCount,
							).To(
								BeNumerically(">", 0),
								"Expected token to "+
									"have been renewed",
							)
						}, 3*time.Minute,
							10*time.Second,
						).Should(Succeed())

						By("verifying " +
							"tokenLastRenewed " +
							"has been updated")
						conn, err =
							utils.GetVaultConnection(
								ctx,
								renewalConnectionName,
								"",
							)
						Expect(err).NotTo(
							HaveOccurred(),
						)
						newRenewed := ""
						if conn.Status.AuthStatus != nil &&
							conn.Status.AuthStatus.TokenLastRenewed != nil {
							newRenewed =
								conn.Status.AuthStatus.TokenLastRenewed.Format(
									time.RFC3339,
								)
						}
						Expect(newRenewed).NotTo(
							Equal(initialRenewed),
							"tokenLastRenewed should "+
								"have been updated "+
								"after renewal",
						)

						By("verifying connection " +
							"is still Active " +
							"after renewal")
						status, err :=
							utils.GetVaultConnectionStatus(
								ctx,
								renewalConnectionName,
								"",
							)
						Expect(err).NotTo(
							HaveOccurred(),
						)
						Expect(status).To(
							Equal("Active"),
						)
					})
			})
	})
