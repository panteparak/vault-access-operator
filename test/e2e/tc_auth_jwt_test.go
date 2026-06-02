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
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkOIDCDiscoveryAvailable uses client-go to verify
// that Kubernetes OIDC discovery is available.
// Skips the test if OIDC discovery is not available.
func checkOIDCDiscoveryAvailable(
	ctx context.Context,
) {
	By("checking Kubernetes OIDC discovery " +
		"availability")
	output, err := utils.GetK8sRawEndpoint(
		ctx, "/.well-known/openid-configuration",
	)
	if err != nil {
		Skip("Kubernetes OIDC discovery not " +
			"available - skipping JWT auth tests")
	}

	var oidcConfig struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(
		output, &oidcConfig,
	); err != nil {
		Skip(fmt.Sprintf(
			"Failed to parse OIDC config: %v"+
				" - skipping JWT auth tests", err,
		))
	}

	if oidcConfig.Issuer == "" {
		Skip("OIDC issuer is empty - " +
			"skipping JWT auth tests")
	}
}

var _ = Describe("JWT Authentication Tests",
	Label("auth"), func() {
		// TC-AU04: JWT Authentication with Kubernetes
		// Service Account Token
		Context("TC-AU04: JWT Auth with Kubernetes "+
			"Service Account Token", Ordered, func() {
			const (
				jwtPolicyName = "tc-au04-jwt-policy"
				jwtRoleName   = "tc-au04-jwt-role"
				jwtSAName     = "tc-au04-jwt-sa"
			)

			ctx := context.Background()

			BeforeAll(func() {
				By("creating service account for " +
					"JWT auth tests")
				_ = utils.CreateServiceAccount(
					ctx, testNamespace, jwtSAName,
				)

				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("enabling JWT auth method in Vault")
				err = vaultClient.EnableAuth(
					ctx, "jwt", "jwt",
				)
				if err != nil &&
					!strings.Contains(
						err.Error(), "already in use",
					) {
					Fail(fmt.Sprintf(
						"Failed to enable JWT auth: %v",
						err,
					))
				}

				By("creating JWT operator policy")
				jwtOperatorPolicyHCL := `
# JWT auth configuration
path "auth/jwt/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
path "sys/auth/jwt" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}
# Policy management
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`
				err = vaultClient.WritePolicy(
					ctx,
					"jwt-operator-policy",
					jwtOperatorPolicyHCL,
				)
				Expect(err).NotTo(HaveOccurred())

				// Check OIDC and configure JWT auth
				checkOIDCDiscoveryAvailable(ctx)
				err = configureJWTAuthAtPath("auth/jwt")
				Expect(err).NotTo(HaveOccurred())
			})

			AfterAll(func() {
				By("cleaning up TC-AU04 test resources")
				_ = utils.DeleteVaultPolicyCR(
					ctx, jwtPolicyName, testNamespace,
				)
				_ = utils.DeleteVaultRoleCR(
					ctx, jwtRoleName, testNamespace,
				)
				_ = utils.DeleteServiceAccount(
					ctx, testNamespace, jwtSAName,
				)

				vaultClient, err :=
					utils.GetTestVaultClient()
				if err == nil {
					jwtVaultRoleName := fmt.Sprintf(
						"%s-%s",
						testNamespace, jwtRoleName,
					)
					_ = vaultClient.DeleteAuthRole(
						ctx, "jwt", jwtVaultRoleName,
					)
				}
			})

			It("TC-AU04-01: should authenticate using "+
				"JWT method with service account token",
				func() {
					vaultClient, err :=
						utils.GetTestVaultClient()
					Expect(err).NotTo(HaveOccurred())

					By("creating JWT auth role in Vault")
					jwtVaultRoleName := fmt.Sprintf(
						"%s-%s",
						testNamespace, jwtRoleName,
					)
					err = vaultClient.WriteAuthRole(
						ctx, "jwt", jwtVaultRoleName,
						map[string]interface{}{
							"role_type": "jwt",
							"bound_audiences": "https://" +
								"kubernetes.default." +
								"svc.cluster.local",
							"bound_subject": fmt.Sprintf(
								"system:serviceaccount:%s:%s",
								testNamespace, jwtSAName,
							),
							"user_claim": "sub",
							"policies":   "default",
							"ttl":        "5m",
						},
					)
					Expect(err).NotTo(HaveOccurred())

					By("getting a service account token")
					saToken, err :=
						utils.CreateServiceAccountTokenClientGo(
							ctx, testNamespace, jwtSAName,
						)
					Expect(err).NotTo(HaveOccurred())
					Expect(saToken).NotTo(BeEmpty())

					By("attempting JWT login with " +
						"service account token")
					secret, err := vaultClient.Write(
						ctx,
						"auth/jwt/login",
						map[string]interface{}{
							"role": jwtVaultRoleName,
							"jwt":  saToken,
						},
					)
					Expect(err).NotTo(HaveOccurred())
					Expect(secret).NotTo(BeNil())
					Expect(secret.Auth).NotTo(BeNil())
					Expect(
						secret.Auth.ClientToken,
					).NotTo(BeEmpty())
				})

			It("TC-AU04-02: should reject JWT with "+
				"wrong audience", func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("creating a role with " +
					"specific audience")
				wrongAudRole :=
					"tc-au04-wrong-aud-role"
				err = vaultClient.WriteAuthRole(
					ctx, "jwt", wrongAudRole,
					map[string]interface{}{
						"role_type": "jwt",
						"bound_audiences": "https://" +
							"wrong-audience.example.com",
						"user_claim": "sub",
						"policies":   "default",
					},
				)
				Expect(err).NotTo(HaveOccurred())

				By("getting service account token " +
					"with default audience")
				saToken, err :=
					utils.CreateServiceAccountTokenClientGo(
						ctx, testNamespace, jwtSAName,
					)
				Expect(err).NotTo(HaveOccurred())

				By("attempting login - should fail " +
					"due to audience mismatch")
				_, err = vaultClient.LoginJWT(
					ctx, "jwt", wrongAudRole, saToken,
				)
				Expect(err).To(HaveOccurred())

				By("cleaning up wrong audience role")
				_ = vaultClient.DeleteAuthRole(
					ctx, "jwt", wrongAudRole,
				)
			})

			It("TC-AU04-03: should reject JWT with "+
				"wrong subject", func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("creating a role with specific " +
					"bound subject")
				wrongSubRole :=
					"tc-au04-wrong-sub-role"
				err = vaultClient.WriteAuthRole(
					ctx, "jwt", wrongSubRole,
					map[string]interface{}{
						"role_type": "jwt",
						"bound_audiences": "https://" +
							"kubernetes.default." +
							"svc.cluster.local",
						"bound_subject": "system:" +
							"serviceaccount:" +
							"other-namespace:other-sa",
						"user_claim": "sub",
						"policies":   "default",
					},
				)
				Expect(err).NotTo(HaveOccurred())

				By("getting service account token")
				saToken, err :=
					utils.CreateServiceAccountTokenClientGo(
						ctx, testNamespace, jwtSAName,
					)
				Expect(err).NotTo(HaveOccurred())

				By("attempting login - should fail " +
					"due to subject mismatch")
				_, err = vaultClient.LoginJWT(
					ctx, "jwt", wrongSubRole, saToken,
				)
				Expect(err).To(HaveOccurred())

				By("cleaning up wrong subject role")
				_ = vaultClient.DeleteAuthRole(
					ctx, "jwt", wrongSubRole,
				)
			})
		})

		// TC-AU07: JWT auth via OIDC discovery (external Vault → control plane).
		// This is how EKS/IRSA and self-managed JWT auth work: the SA-token
		// issuer is a network-reachable OIDC URL, and Vault validates tokens by
		// fetching the JWKS from the issuer's discovery endpoint at login time —
		// rather than being handed static public keys out of band.
		// The local stack models this with an EXTERNAL Vault and the in-cluster
		// issuer https://kubernetes.default.svc: the k8s-svc-proxy container
		// (443 → k3s:6443 passthrough, see docker-compose.e2e.yaml) plays the
		// role of the real kubernetes.default.svc Service, and anonymous
		// discovery is granted by vault-rbac.yaml. The same mechanism covers the
		// EKS public-OIDC-URL style — only the issuer host differs. These tests
		// fail loudly if the config silently fell back to static JWKS.
		Context("TC-AU07: JWT auth via OIDC discovery "+
			"(external Vault)", Ordered, func() {
			const (
				discoverySAName   = "tc-au07-discovery-sa"
				discoveryRoleName = "tc-au07-discovery-role"
			)

			ctx := context.Background()

			BeforeAll(func() {
				checkOIDCDiscoveryAvailable(ctx)

				By("creating service account for " +
					"discovery tests")
				_ = utils.CreateServiceAccount(
					ctx, testNamespace, discoverySAName,
				)

				By("ensuring JWT auth is enabled")
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())
				err = vaultClient.EnableAuth(
					ctx, "jwt", "jwt",
				)
				if err != nil &&
					!strings.Contains(
						err.Error(), "already in use",
					) {
					Fail(fmt.Sprintf(
						"Failed to enable JWT auth: %v",
						err,
					))
				}

				By("configuring auth/jwt via OIDC " +
					"discovery against the k3s issuer")
				// Prefers oidc_discovery_url; only falls
				// back to static JWKS if discovery is
				// unreachable. With a reachable issuer it
				// must take the discovery path —
				// TC-AU07-01 asserts that.
				Expect(
					configureJWTAuthAtPath("auth/jwt"),
				).To(Succeed())
			})

			AfterAll(func() {
				By("cleaning up TC-AU07 test resources")
				_ = utils.DeleteServiceAccount(
					ctx, testNamespace, discoverySAName,
				)
				vaultClient, err :=
					utils.GetTestVaultClient()
				if err == nil {
					_ = vaultClient.DeleteAuthRole(
						ctx, "jwt", fmt.Sprintf(
							"%s-%s", testNamespace,
							discoveryRoleName,
						),
					)
				}
			})

			It("TC-AU07-01: auth/jwt must use OIDC "+
				"discovery, not static JWKS", func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("reading auth/jwt/config")
				cfg, err := vaultClient.Read(
					ctx, "auth/jwt/config",
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(cfg).NotTo(BeNil())
				Expect(cfg.Data).NotTo(BeNil())

				By("asserting oidc_discovery_url is set " +
					"(discovery active)")
				discoveryURL, _ := cfg.Data["oidc_discovery_url"].(string)
				Expect(discoveryURL).NotTo(BeEmpty(),
					"auth/jwt must use "+
						"oidc_discovery_url "+
						"(EKS-faithful), not the "+
						"static-JWKS fallback")

				By("asserting no static " +
					"jwt_validation_pubkeys")
				if keys, ok := cfg.Data["jwt_validation_pubkeys"].([]interface{}); ok {
					Expect(keys).To(BeEmpty(),
						"static pubkeys present "+
							"means discovery "+
							"fell back")
				}
			})

			It("TC-AU07-02: should authenticate a real "+
				"K8s SA token verified via JWKS "+
				"discovery", func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				roleName := fmt.Sprintf(
					"%s-%s", testNamespace,
					discoveryRoleName,
				)
				By("creating a JWT role bound to the " +
					"test SA subject")
				err = vaultClient.WriteAuthRole(
					ctx, "jwt", roleName,
					map[string]interface{}{
						"role_type": "jwt",
						"bound_audiences": []string{
							"https://kubernetes." +
								"default.svc." +
								"cluster.local",
						},
						"bound_subject": fmt.Sprintf(
							"system:serviceaccount:"+
								"%s:%s",
							testNamespace,
							discoverySAName,
						),
						"user_claim": "sub",
						"policies":   "default",
						"ttl":        "5m",
					},
				)
				Expect(err).NotTo(HaveOccurred())

				By("minting a real K8s service " +
					"account token")
				saToken, err :=
					utils.CreateServiceAccountTokenClientGo(
						ctx, testNamespace,
						discoverySAName,
					)
				Expect(err).NotTo(HaveOccurred())
				Expect(saToken).NotTo(BeEmpty())

				By("logging in — Vault must fetch JWKS " +
					"from the issuer to verify the " +
					"token signature")
				clientToken, err := vaultClient.LoginJWT(
					ctx, "jwt", roleName, saToken,
				)
				Expect(err).NotTo(HaveOccurred(),
					"login via discovery-based JWKS "+
						"validation should succeed")
				Expect(clientToken).NotTo(BeEmpty())
			})
		})

		// TC-AU05: OIDC-style JWT Authentication
		Context("TC-AU05: OIDC with Kubernetes built-in "+
			"OIDC issuer", Ordered, func() {
			const (
				oidcSAName   = "tc-au05-oidc-sa"
				oidcRoleName = "tc-au05-oidc-role"
			)

			ctx := context.Background()

			BeforeAll(func() {
				By("creating service account " +
					"for OIDC tests")
				_ = utils.CreateServiceAccount(
					ctx, testNamespace, oidcSAName,
				)

				By("enabling JWT auth method in " +
					"Vault (if not already enabled)")
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				err = vaultClient.EnableAuth(
					ctx, "jwt", "jwt",
				)
				if err != nil &&
					!strings.Contains(
						err.Error(), "already in use",
					) {
					Fail(fmt.Sprintf(
						"Failed to enable JWT auth: %v",
						err,
					))
				}

				// Check OIDC and configure JWT auth
				checkOIDCDiscoveryAvailable(ctx)
				err = configureJWTAuthAtPath("auth/jwt")
				Expect(err).NotTo(HaveOccurred())
			})

			AfterAll(func() {
				By("cleaning up TC-AU05 test resources")
				_ = utils.DeleteServiceAccount(
					ctx, testNamespace, oidcSAName,
				)

				vaultClient, err :=
					utils.GetTestVaultClient()
				if err == nil {
					_ = vaultClient.DeleteAuthRole(
						ctx, "jwt", oidcRoleName,
					)
				}
			})

			It("TC-AU05-01: should discover OIDC "+
				"configuration from Kubernetes API",
				func() {
					By("fetching OIDC discovery document")
					output, err := utils.GetK8sRawEndpoint(
						ctx,
						"/.well-known/openid-configuration",
					)
					Expect(err).NotTo(HaveOccurred())

					var oidcConfig struct {
						Issuer  string `json:"issuer"`
						JWKSURI string `json:"jwks_uri"`
					}
					err = json.Unmarshal(
						output, &oidcConfig,
					)
					Expect(err).NotTo(HaveOccurred())

					By("verifying OIDC configuration " +
						"fields")
					Expect(oidcConfig.Issuer).NotTo(
						BeEmpty(),
						"issuer should be present",
					)
					Expect(oidcConfig.JWKSURI).NotTo(
						BeEmpty(),
						"jwks_uri should be present",
					)
				})

			It("TC-AU05-02: should authenticate with "+
				"OIDC-discovered keys", func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("creating OIDC-style role")
				err = vaultClient.WriteAuthRole(
					ctx, "jwt", oidcRoleName,
					map[string]interface{}{
						"role_type": "jwt",
						"bound_audiences": "https://" +
							"kubernetes.default." +
							"svc.cluster.local",
						"bound_claims": map[string]interface{}{
							"sub": fmt.Sprintf(
								"system:serviceaccount:%s:%s",
								testNamespace, oidcSAName,
							),
						},
						"user_claim": "sub",
						"policies":   "default",
						"ttl":        "5m",
					},
				)
				Expect(err).NotTo(HaveOccurred())

				By("getting service account token")
				saToken, err :=
					utils.CreateServiceAccountTokenClientGo(
						ctx, testNamespace, oidcSAName,
					)
				Expect(err).NotTo(HaveOccurred())

				By("authenticating via JWT method " +
					"with OIDC-discovered keys")
				secret, err := vaultClient.Write(
					ctx,
					"auth/jwt/login",
					map[string]interface{}{
						"role": oidcRoleName,
						"jwt":  saToken,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(secret).NotTo(BeNil())
				Expect(secret.Auth).NotTo(BeNil())

				Expect(
					secret.Auth.ClientToken,
				).NotTo(BeEmpty())
				// 5m = 300s
				Expect(
					secret.Auth.LeaseDuration,
				).To(BeNumerically("<=", 300))
				Expect(
					secret.Auth.Policies,
				).To(ContainElement("default"))
			})

			It("TC-AU05-03: should support custom "+
				"audiences via TokenRequest API",
				func() {
					vaultClient, err :=
						utils.GetTestVaultClient()
					Expect(err).NotTo(HaveOccurred())

					By("creating service account " +
						"token with custom audience")
					customAudience :=
						"vault-custom-audience"
					expSeconds := int64(600) // 10m - Kubernetes TokenRequest minimum
					customToken, err :=
						utils.CreateServiceAccountTokenWithOpts(
							ctx, testNamespace,
							oidcSAName,
							[]string{customAudience},
							&expSeconds,
						)
					Expect(err).NotTo(HaveOccurred())
					Expect(customToken).NotTo(BeEmpty())

					By("creating role that accepts " +
						"custom audience")
					customAudRole :=
						"tc-au05-custom-aud-role"
					err = vaultClient.WriteAuthRole(
						ctx, "jwt", customAudRole,
						map[string]interface{}{
							"role_type":       "jwt",
							"bound_audiences": customAudience,
							"bound_claims": map[string]interface{}{
								"sub": fmt.Sprintf(
									"system:serviceaccount:%s:%s",
									testNamespace, oidcSAName,
								),
							},
							"user_claim": "sub",
							"policies":   "default",
						},
					)
					Expect(err).NotTo(HaveOccurred())

					By("authenticating with " +
						"custom-audience token")
					secret, err := vaultClient.Write(
						ctx,
						"auth/jwt/login",
						map[string]interface{}{
							"role": customAudRole,
							"jwt":  customToken,
						},
					)
					Expect(err).NotTo(HaveOccurred())
					Expect(secret).NotTo(BeNil())
					Expect(secret.Auth).NotTo(BeNil())
					Expect(
						secret.Auth.ClientToken,
					).NotTo(BeEmpty())

					By("cleaning up custom " +
						"audience role")
					_ = vaultClient.DeleteAuthRole(
						ctx, "jwt", customAudRole,
					)
				})
		})

		// TC-AU06: VaultConnection with JWT Auth
		Context("TC-AU06: VaultConnection with JWT Auth",
			Ordered, func() {
				const (
					jwtConnName       = "tc-au06-jwt-connection"
					jwtConnRoleName   = "tc-au06-jwt-conn-role"
					jwtConnPolicyName = "tc-au06-jwt-conn-policy"
				)

				// Operator service account info
				operatorNamespace := "vault-access-operator-system"
				operatorSAName := "vault-access-operator"

				ctx := context.Background()

				BeforeAll(func() {
					// Check for operator SA override from environment
					if ns := os.Getenv("OPERATOR_NAMESPACE"); ns != "" {
						operatorNamespace = ns
					}
					if sa := os.Getenv("OPERATOR_SERVICE_ACCOUNT"); sa != "" {
						operatorSAName = sa
					}

					vaultClient, err :=
						utils.GetTestVaultClient()
					Expect(err).NotTo(HaveOccurred())

					By("enabling JWT auth method " +
						"in Vault (if not already " +
						"enabled)")
					err = vaultClient.EnableAuth(
						ctx, "jwt", "jwt",
					)
					if err != nil &&
						!strings.Contains(
							err.Error(),
							"already in use",
						) {
						Fail(fmt.Sprintf(
							"Failed to enable JWT "+
								"auth: %v", err,
						))
					}

					// Check OIDC and configure JWT
					checkOIDCDiscoveryAvailable(ctx)
					err = configureJWTAuthAtPath(
						"auth/jwt",
					)
					Expect(err).NotTo(HaveOccurred())

					By("creating Vault policy for " +
						"VaultConnection JWT auth")
					connPolicyHCL := `
# Allow token self-lookup for connection health check
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow health check
path "sys/health" {
  capabilities = ["read"]
}

# Allow policy management (for VaultPolicy reconciliation)
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow role management (for VaultRole reconciliation)
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow reading managed secrets metadata
path "secret/metadata/managed/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`
					err = vaultClient.WritePolicy(
						ctx,
						jwtConnPolicyName,
						connPolicyHCL,
					)
					Expect(err).NotTo(HaveOccurred())

					By(fmt.Sprintf("creating JWT role for "+
						"operator SA (%s/%s)",
						operatorNamespace, operatorSAName))
					// The JWT role must accept tokens from the operator's SA
					// because that's what the handler uses to get JWT tokens
					err = vaultClient.WriteAuthRole(
						ctx, "jwt", jwtConnRoleName,
						map[string]interface{}{
							"role_type": "jwt",
							// Accept both k8s default audience and "vault"
							"bound_audiences": []string{
								"https://kubernetes.default.svc.cluster.local",
								"vault",
							},
							// Bind to operator's service account
							"bound_subject": fmt.Sprintf(
								"system:serviceaccount:%s:%s",
								operatorNamespace,
								operatorSAName,
							),
							"user_claim": "sub",
							"policies":   jwtConnPolicyName,
							"ttl":        "5m",
						},
					)
					Expect(err).NotTo(HaveOccurred())
				})

				AfterAll(func() {
					By("cleaning up TC-AU06 " +
						"test resources")
					_ = utils.DeleteVaultConnectionCR(
						ctx, jwtConnName,
					)

					vaultClient, err :=
						utils.GetTestVaultClient()
					if err == nil {
						_ = vaultClient.DeleteAuthRole(
							ctx, "jwt",
							jwtConnRoleName,
						)
						_ = vaultClient.DeletePolicy(
							ctx, jwtConnPolicyName,
						)
					}
				})

				It("TC-AU06-01: should create "+
					"VaultConnection using JWT "+
					"auth spec", func() {
					By("creating VaultConnection with JWT auth")
					conn := &vaultv1alpha1.VaultConnection{
						ObjectMeta: metav1.ObjectMeta{
							Name:      jwtConnName,
							Namespace: testNamespace,
						},
						Spec: vaultv1alpha1.VaultConnectionSpec{
							Address: vaultK8sAddr,
							Auth: vaultv1alpha1.AuthConfig{
								JWT: &vaultv1alpha1.JWTAuth{
									Role:     jwtConnRoleName,
									AuthPath: "jwt",
									Audiences: []string{
										"vault",
									},
									TokenDuration: metav1.Duration{
										Duration: time.Hour,
									},
								},
							},
						},
					}

					err := utils.CreateVaultConnectionCR(ctx, conn)
					Expect(err).NotTo(HaveOccurred())

					By("waiting for VaultConnection to become Active")
					Eventually(func(g Gomega) {
						status, err := utils.GetVaultConnectionStatus(
							ctx, jwtConnName, testNamespace,
						)
						g.Expect(err).NotTo(HaveOccurred())
						g.Expect(status).To(Equal("Active"),
							"VaultConnection should become Active with JWT auth")
					}, 2*time.Minute, 5*time.Second).Should(Succeed())

					By("verifying VaultConnection status fields")
					connStatus, err := utils.GetVaultConnection(
						ctx, jwtConnName, testNamespace,
					)
					Expect(err).NotTo(HaveOccurred())
					Expect(connStatus.Status.Phase).To(
						Equal(vaultv1alpha1.PhaseActive))
					// Verify auth method is reflected in status
					GinkgoWriter.Printf(
						"VaultConnection %s is Active with JWT auth\n",
						jwtConnName)
				})
			})
	})
