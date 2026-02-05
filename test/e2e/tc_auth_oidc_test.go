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
	"io"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// checkDexOIDCAvailability verifies that Dex OIDC discovery is reachable.
// Skips the current test if Dex is not available.
func checkDexOIDCAvailability() {
	By("checking Dex OIDC provider availability")
	resp, err := http.Get(dexDiscoveryURL) //nolint:gosec
	if err != nil {
		Skip(fmt.Sprintf(
			"Dex OIDC provider not available at %s: %v",
			dexDiscoveryURL, err,
		))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Skip(fmt.Sprintf(
			"Failed to read Dex discovery response: %v",
			err,
		))
	}

	if resp.StatusCode != http.StatusOK {
		Skip(fmt.Sprintf(
			"Dex discovery returned status %d",
			resp.StatusCode,
		))
	}

	var discoveryResp struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &discoveryResp); err != nil {
		Skip(fmt.Sprintf(
			"Failed to parse Dex discovery: %v", err,
		))
	}

	if discoveryResp.Issuer == "" {
		Skip("Dex issuer is empty in discovery response")
	}
}

var _ = Describe("OIDC Authentication Tests",
	Label("auth"), func() {
		// TC-AU-OIDC: OIDC Authentication (JWT at oidc path)
		// Uses Dex as a standalone OIDC provider. Vault validates
		// Dex-issued JWTs via standard OIDC discovery.
		Context("TC-AU-OIDC: OIDC Auth with "+
			"Dex OIDC provider", Ordered, func() {
			const (
				oidcRoleName   = "tc-au-oidc-role"
				oidcPolicyName = "tc-au-oidc-policy"
			)

			ctx := context.Background()

			BeforeAll(func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("enabling OIDC auth method " +
					"(JWT engine at oidc path)")
				err = vaultClient.EnableAuth(
					ctx, "oidc", "jwt",
				)
				if err != nil &&
					!strings.Contains(
						err.Error(), "already in use",
					) {
					Fail(fmt.Sprintf(
						"Failed to enable OIDC auth: %v",
						err,
					))
				}

				By("creating test policy for OIDC tests")
				policyHCL := `
path "secret/data/oidc-test/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/health" {
  capabilities = ["read"]
}
`
				err = vaultClient.WritePolicy(
					ctx, oidcPolicyName, policyHCL,
				)
				Expect(err).NotTo(HaveOccurred())

				// Check Dex availability and configure
				checkDexOIDCAvailability()
				err = configureOIDCAuth()
				Expect(err).NotTo(HaveOccurred())
			})

			AfterAll(func() {
				By("cleaning up TC-AU-OIDC resources")
				vaultClient, err :=
					utils.GetTestVaultClient()
				if err != nil {
					return
				}
				_ = vaultClient.DeleteAuthRole(
					ctx, "oidc", oidcRoleName,
				)
				_ = vaultClient.DeletePolicy(
					ctx, oidcPolicyName,
				)
			})

			It("TC-AU-OIDC-01: should authenticate "+
				"using Dex-issued OIDC JWT", func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("creating OIDC role bound to " +
					"Dex user email")
				err = vaultClient.WriteAuthRole(
					ctx, "oidc", oidcRoleName,
					map[string]interface{}{
						"role_type":       "jwt",
						"bound_audiences": dexClientID,
						"user_claim":      "email",
						"bound_claims": map[string]interface{}{
							"email": dexTestEmail,
						},
						"policies": fmt.Sprintf(
							"%s,default",
							oidcPolicyName,
						),
						"ttl": "1h",
					},
				)
				Expect(err).NotTo(HaveOccurred())

				By("getting Dex id_token via " +
					"password grant")
				idToken, err := getDexToken(
					dexClientID, dexClientSecret,
				)
				Expect(err).NotTo(HaveOccurred())

				By("authenticating via OIDC (JWT at " +
					"oidc path) with Dex token")
				secret, err := vaultClient.Write(
					ctx, "auth/oidc/login",
					map[string]interface{}{
						"role": oidcRoleName,
						"jwt":  idToken,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(secret).NotTo(BeNil())
				Expect(secret.Auth).NotTo(BeNil())
				Expect(secret.Auth.ClientToken).NotTo(
					BeEmpty(),
				)
				Expect(secret.Auth.Policies).To(
					ContainElement(oidcPolicyName),
				)
			})

			It("TC-AU-OIDC-02: should verify OIDC "+
				"issuer discovery from Dex", func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("fetching OIDC discovery " +
					"document from Dex")
				resp, err := http.Get( //nolint:gosec
					dexDiscoveryURL,
				)
				Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(
					Equal(http.StatusOK),
				)

				body, err := io.ReadAll(resp.Body)
				Expect(err).NotTo(HaveOccurred())

				var discoveryConfig struct {
					Issuer      string   `json:"issuer"`
					JWKSURI     string   `json:"jwks_uri"`
					SigningAlgs []string `json:"id_token_signing_alg_values_supported"`
				}
				err = json.Unmarshal(
					body, &discoveryConfig,
				)
				Expect(err).NotTo(HaveOccurred())

				By("verifying Dex OIDC discovery " +
					"fields are present")
				Expect(discoveryConfig.Issuer).To(
					Equal(dexIssuer),
					"issuer should match Dex config",
				)
				Expect(discoveryConfig.JWKSURI).NotTo(
					BeEmpty(),
					"jwks_uri should be present",
				)

				By("verifying Vault's OIDC auth " +
					"config references Dex issuer")
				vaultConfig, err := vaultClient.Read(
					ctx, "auth/oidc/config",
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(vaultConfig).NotTo(BeNil())
				Expect(vaultConfig.Data).NotTo(BeNil())

				// The oidc_discovery_url field should
				// contain the Dex issuer URL
				oidcDiscURL, ok :=
					vaultConfig.Data["oidc_discovery_url"]
				Expect(ok).To(BeTrue(),
					"oidc_discovery_url should "+
						"be in config",
				)
				Expect(fmt.Sprint(oidcDiscURL)).To(
					Equal(dexIssuer),
				)
			})

			It("TC-AU-OIDC-03: should support custom "+
				"audience via Dex client", func() {
				customAudRole := "tc-au-oidc-custom-aud"

				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("creating OIDC role bound to " +
					"custom-audience Dex client")
				err = vaultClient.WriteAuthRole(
					ctx, "oidc", customAudRole,
					map[string]interface{}{
						"role_type":       "jwt",
						"bound_audiences": dexCustomClientID,
						"user_claim":      "email",
						"bound_claims": map[string]interface{}{
							"email": dexTestEmail,
						},
						"policies": "default",
					},
				)
				Expect(err).NotTo(HaveOccurred())

				By("getting Dex id_token with " +
					"custom-audience client")
				customToken, err := getDexToken(
					dexCustomClientID,
					dexCustomClientSecret,
				)
				Expect(err).NotTo(HaveOccurred())

				By("authenticating with " +
					"custom-audience token")
				secret, err := vaultClient.Write(
					ctx, "auth/oidc/login",
					map[string]interface{}{
						"role": customAudRole,
						"jwt":  customToken,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(secret).NotTo(BeNil())
				Expect(secret.Auth).NotTo(BeNil())
				Expect(secret.Auth.ClientToken).NotTo(
					BeEmpty(),
				)

				By("cleaning up custom audience role")
				_ = vaultClient.DeleteAuthRole(
					ctx, "oidc", customAudRole,
				)
			})

			It("TC-AU-OIDC-04: should reject token "+
				"with wrong audience", func() {
				wrongAudRole := "tc-au-oidc-wrong-aud"

				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("creating OIDC role bound to " +
					"a non-existent audience")
				err = vaultClient.WriteAuthRole(
					ctx, "oidc", wrongAudRole,
					map[string]interface{}{
						"role_type":       "jwt",
						"bound_audiences": "https://wrong-audience.example.com",
						"user_claim":      "email",
						"policies":        "default",
					},
				)
				Expect(err).NotTo(HaveOccurred())

				By("getting Dex token " +
					"(aud=vault, mismatches role)")
				dexToken, err := getDexToken(
					dexClientID, dexClientSecret,
				)
				Expect(err).NotTo(HaveOccurred())

				By("attempting login - should fail " +
					"due to audience mismatch")
				_, err = vaultClient.LoginJWT(
					ctx, "oidc",
					wrongAudRole, dexToken,
				)
				Expect(err).To(HaveOccurred())

				By("cleaning up wrong audience role")
				_ = vaultClient.DeleteAuthRole(
					ctx, "oidc", wrongAudRole,
				)
			})

			It("TC-AU-OIDC-05: VaultConnection "+
				"with OIDC auth", func() {
				Skip("VaultConnection OIDC auth " +
					"not yet fully implemented")
			})
		})
	})
