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
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
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
							"ttl":        "1h",
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
						"bound_claims": fmt.Sprintf(
							"sub=system:serviceaccount:"+
								"%s:%s",
							testNamespace, oidcSAName,
						),
						"user_claim": "sub",
						"policies":   "default",
						"ttl":        "15m",
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
				// 15m = 900s
				Expect(
					secret.Auth.LeaseDuration,
				).To(BeNumerically("<=", 900))
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
					expSeconds := int64(3600) // 1h
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
							"bound_claims": fmt.Sprintf(
								"sub=system:serviceaccount:"+
									"%s:%s",
								testNamespace, oidcSAName,
							),
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
		// (Future feature)
		Context("TC-AU06: VaultConnection with JWT Auth",
			Ordered, func() {
				const (
					jwtConnSAName     = "tc-au06-jwt-conn-sa"
					jwtConnName       = "tc-au06-jwt-connection"
					jwtConnRoleName   = "tc-au06-jwt-conn-role"
					jwtConnPolicyName = "tc-au06-jwt-conn-policy"
				)

				ctx := context.Background()

				BeforeAll(func() {
					By("creating dedicated service " +
						"account for VaultConnection " +
						"JWT test")
					_ = utils.CreateServiceAccount(
						ctx, testNamespace,
						jwtConnSAName,
					)

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
						"VaultConnection")
					connPolicyHCL := `
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "sys/health" {
  capabilities = ["read"]
}
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`
					err = vaultClient.WritePolicy(
						ctx,
						jwtConnPolicyName,
						connPolicyHCL,
					)
					Expect(err).NotTo(HaveOccurred())

					By("creating JWT role for " +
						"VaultConnection")
					err = vaultClient.WriteAuthRole(
						ctx, "jwt", jwtConnRoleName,
						map[string]interface{}{
							"role_type": "jwt",
							"bound_audiences": "https://" +
								"kubernetes.default." +
								"svc.cluster.local,vault",
							"bound_claims": fmt.Sprintf(
								"sub=system:"+
									"serviceaccount:%s:%s",
								testNamespace,
								jwtConnSAName,
							),
							"user_claim": "sub",
							"policies":   jwtConnPolicyName,
							"ttl":        "1h",
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

					_ = utils.DeleteServiceAccount(
						ctx, testNamespace,
						jwtConnSAName,
					)
				})

				It("TC-AU06-01: should create "+
					"VaultConnection using JWT "+
					"auth spec", func() {
					Skip("VaultConnection JWT auth " +
						"not yet implemented - " +
						"this test documents the " +
						"expected API")
				})
			})
	})
