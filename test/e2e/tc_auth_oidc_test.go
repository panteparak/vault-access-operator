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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// oidcAuthHelper provides reusable functions for OIDC (JWT at oidc path) auth tests.
// Uses Dex as the OIDC provider instead of Kubernetes built-in OIDC issuer.
type oidcAuthHelper struct {
	issuer string
}

// checkOIDCAvailability verifies Dex OIDC discovery is available.
// Returns the issuer URL or skips the test if Dex is not reachable.
func (h *oidcAuthHelper) checkOIDCAvailability() string {
	By("checking Dex OIDC provider availability")
	resp, err := http.Get(dexDiscoveryURL)
	if err != nil {
		Skip(fmt.Sprintf("Dex OIDC provider not available at %s: %v", dexDiscoveryURL, err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Skip(fmt.Sprintf("Failed to read Dex discovery response: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		Skip(fmt.Sprintf("Dex discovery returned status %d", resp.StatusCode))
	}

	var discoveryResp struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &discoveryResp); err != nil {
		Skip(fmt.Sprintf("Failed to parse Dex discovery: %v", err))
	}

	if discoveryResp.Issuer == "" {
		Skip("Dex issuer is empty in discovery response")
	}

	h.issuer = discoveryResp.Issuer
	return discoveryResp.Issuer
}

// configureOIDCAuth configures Vault's JWT auth at the "oidc" mount path with Dex.
func (h *oidcAuthHelper) configureOIDCAuth(_ string) {
	configureVaultJWTAuthForTest("auth/oidc", "OIDC", h.issuer)
}

var _ = Describe("OIDC Authentication Tests", func() {
	// TC-AU-OIDC: OIDC Authentication (JWT at oidc path)
	// Uses Dex as a standalone OIDC provider. Vault validates Dex-issued JWTs
	// via standard OIDC discovery (/.well-known/openid-configuration).
	Context("TC-AU-OIDC: OIDC Auth with Dex OIDC provider", Ordered, func() {
		const (
			oidcRoleName   = "tc-au-oidc-role"
			oidcPolicyName = "tc-au-oidc-policy"
		)

		var helper oidcAuthHelper

		BeforeAll(func() {
			By("enabling OIDC auth method (JWT engine at oidc path)")
			_, err := utils.RunVaultCommand("auth", "enable", "-path=oidc", "jwt")
			if err != nil && !strings.Contains(err.Error(), "already in use") {
				Fail(fmt.Sprintf("Failed to enable OIDC auth: %v", err))
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
			err = utils.CreateUnmanagedVaultPolicy(oidcPolicyName, policyHCL)
			Expect(err).NotTo(HaveOccurred())

			// Check Dex availability and configure auth
			issuer := helper.checkOIDCAvailability()
			helper.configureOIDCAuth(issuer)
		})

		AfterAll(func() {
			By("cleaning up TC-AU-OIDC test resources")
			_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/oidc/role/%s", oidcRoleName))
			_, _ = utils.RunVaultCommand("policy", "delete", oidcPolicyName)
		})

		It("TC-AU-OIDC-01: should authenticate using Dex-issued OIDC JWT", func() {
			By("creating OIDC role bound to Dex user email")
			_, err := utils.RunVaultCommand("write", fmt.Sprintf("auth/oidc/role/%s", oidcRoleName),
				"role_type=jwt",
				fmt.Sprintf("bound_audiences=%s", dexClientID),
				"user_claim=email",
				fmt.Sprintf("bound_claims=email=%s", dexTestEmail),
				fmt.Sprintf("policies=%s,default", oidcPolicyName),
				"ttl=1h",
			)
			Expect(err).NotTo(HaveOccurred())

			By("getting Dex id_token via password grant")
			idToken, err := getDexToken(dexClientID, dexClientSecret)
			Expect(err).NotTo(HaveOccurred())

			By("authenticating via OIDC (JWT at oidc path) with Dex token")
			loginOutput, err := utils.VaultLoginWithJWT("auth/oidc", oidcRoleName, idToken)
			Expect(err).NotTo(HaveOccurred())

			var loginResp struct {
				Auth struct {
					ClientToken string   `json:"client_token"`
					Policies    []string `json:"policies"`
				} `json:"auth"`
			}
			err = json.Unmarshal([]byte(loginOutput), &loginResp)
			Expect(err).NotTo(HaveOccurred())
			Expect(loginResp.Auth.ClientToken).NotTo(BeEmpty())
			Expect(loginResp.Auth.Policies).To(ContainElement(oidcPolicyName))
		})

		It("TC-AU-OIDC-02: should verify OIDC issuer discovery from Dex", func() {
			By("fetching OIDC discovery document from Dex")
			resp, err := http.Get(dexDiscoveryURL)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			Expect(resp.StatusCode).To(Equal(http.StatusOK))

			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())

			var discoveryConfig struct {
				Issuer               string   `json:"issuer"`
				JWKSURI              string   `json:"jwks_uri"`
				SigningAlgsSupported []string `json:"id_token_signing_alg_values_supported"`
			}
			err = json.Unmarshal(body, &discoveryConfig)
			Expect(err).NotTo(HaveOccurred())

			By("verifying Dex OIDC discovery fields are present")
			Expect(discoveryConfig.Issuer).To(Equal(dexIssuer), "issuer should match Dex config")
			Expect(discoveryConfig.JWKSURI).NotTo(BeEmpty(), "jwks_uri should be present")

			By("verifying Vault's OIDC auth config references Dex issuer")
			vaultConfig, err := utils.RunVaultCommand("read", "-format=json", "auth/oidc/config")
			Expect(err).NotTo(HaveOccurred())
			Expect(vaultConfig).To(ContainSubstring(dexIssuer))
		})

		It("TC-AU-OIDC-03: should support custom audience via Dex client", func() {
			customAudRole := "tc-au-oidc-custom-aud"

			By("creating OIDC role bound to custom-audience Dex client")
			_, err := utils.RunVaultCommand("write", fmt.Sprintf("auth/oidc/role/%s", customAudRole),
				"role_type=jwt",
				fmt.Sprintf("bound_audiences=%s", dexCustomClientID),
				"user_claim=email",
				fmt.Sprintf("bound_claims=email=%s", dexTestEmail),
				"policies=default",
			)
			Expect(err).NotTo(HaveOccurred())

			By("getting Dex id_token with custom-audience client")
			customToken, err := getDexToken(dexCustomClientID, dexCustomClientSecret)
			Expect(err).NotTo(HaveOccurred())

			By("authenticating with custom-audience token")
			loginOutput, err := utils.VaultLoginWithJWT("auth/oidc", customAudRole, customToken)
			Expect(err).NotTo(HaveOccurred())

			var loginResp struct {
				Auth struct {
					ClientToken string `json:"client_token"`
				} `json:"auth"`
			}
			err = json.Unmarshal([]byte(loginOutput), &loginResp)
			Expect(err).NotTo(HaveOccurred())
			Expect(loginResp.Auth.ClientToken).NotTo(BeEmpty())

			By("cleaning up custom audience role")
			_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/oidc/role/%s", customAudRole))
		})

		It("TC-AU-OIDC-04: should reject token with wrong audience", func() {
			wrongAudRole := "tc-au-oidc-wrong-aud"

			By("creating OIDC role bound to a non-existent audience")
			_, err := utils.RunVaultCommand("write", fmt.Sprintf("auth/oidc/role/%s", wrongAudRole),
				"role_type=jwt",
				"bound_audiences=https://wrong-audience.example.com",
				"user_claim=email",
				"policies=default",
			)
			Expect(err).NotTo(HaveOccurred())

			By("getting Dex token (aud=vault, mismatches role)")
			dexToken, err := getDexToken(dexClientID, dexClientSecret)
			Expect(err).NotTo(HaveOccurred())

			By("attempting login - should fail due to audience mismatch")
			_, err = utils.VaultLoginWithJWT("auth/oidc", wrongAudRole, dexToken)
			Expect(err).To(HaveOccurred())

			By("cleaning up wrong audience role")
			_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/oidc/role/%s", wrongAudRole))
		})

		It("TC-AU-OIDC-05: VaultConnection with OIDC auth", func() {
			Skip("VaultConnection OIDC auth not yet fully implemented - this test documents the expected API")

			// When OIDC auth is added to the VaultConnection spec, this test should be enabled.
			//
			// Expected VaultConnection YAML:
			// apiVersion: vault.platform.io/v1alpha1
			// kind: VaultConnection
			// metadata:
			//   name: oidc-connection
			// spec:
			//   address: http://vault.vault.svc.cluster.local:8200
			//   auth:
			//     oidc:
			//       role: my-oidc-role
			//       authPath: oidc
			//       serviceAccountRef:
			//         name: my-service-account
			//         namespace: my-namespace
		})
	})
})
