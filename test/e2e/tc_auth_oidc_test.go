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
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// oidcAuthHelper provides reusable functions for OIDC (JWT at oidc path) auth tests
type oidcAuthHelper struct {
	issuer string
}

// checkOIDCAvailability verifies OIDC discovery is available from the Kubernetes API.
// Returns the issuer URL or skips the test if not available.
func (h *oidcAuthHelper) checkOIDCAvailability() string {
	By("getting the Kubernetes OIDC issuer URL")
	cmd := exec.Command("kubectl", "get", "--raw", "/.well-known/openid-configuration")
	output, err := utils.Run(cmd)
	if err != nil {
		Skip("Kubernetes OIDC discovery not available - skipping OIDC auth tests")
	}

	var oidcConfig struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal([]byte(output), &oidcConfig); err != nil {
		Skip(fmt.Sprintf("Failed to parse OIDC config: %v - skipping OIDC auth tests", err))
	}

	if oidcConfig.Issuer == "" {
		Skip("OIDC issuer is empty - skipping OIDC auth tests")
	}

	h.issuer = oidcConfig.Issuer
	return oidcConfig.Issuer
}

// configureOIDCAuth configures Vault's JWT auth at the "oidc" mount path.
// Delegates to the shared configureVaultJWTAuthForTest helper.
func (h *oidcAuthHelper) configureOIDCAuth(issuer string) {
	configureVaultJWTAuthForTest("auth/oidc", "OIDC", issuer)
}

var _ = Describe("OIDC Authentication Tests", func() {
	// TC-AU-OIDC: OIDC Authentication (JWT at oidc path)
	// This tests Vault's JWT auth engine mounted at the "oidc" path, validating K8s SA tokens
	// against the cluster's built-in OIDC issuer. This mirrors real-world EKS/GKE/AKS behavior.
	Context("TC-AU-OIDC: OIDC Auth with Kubernetes built-in OIDC issuer", Ordered, func() {
		const (
			oidcSAName     = "tc-au-oidc-sa"
			oidcRoleName   = "tc-au-oidc-role"
			oidcPolicyName = "tc-au-oidc-policy"
		)

		var helper oidcAuthHelper

		BeforeAll(func() {
			By("creating service account for OIDC tests")
			cmd := exec.Command("kubectl", "create", "serviceaccount", oidcSAName, "-n", testNamespace)
			_, _ = utils.Run(cmd) // Ignore if exists

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

			// Check OIDC discovery and configure auth
			issuer := helper.checkOIDCAvailability()
			helper.configureOIDCAuth(issuer)
		})

		AfterAll(func() {
			By("cleaning up TC-AU-OIDC test resources")
			_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/oidc/role/%s", oidcRoleName))
			_, _ = utils.RunVaultCommand("policy", "delete", oidcPolicyName)

			cmd := exec.Command("kubectl", "delete", "serviceaccount", oidcSAName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("TC-AU-OIDC-01: should authenticate using K8s SA token as OIDC JWT", func() {
			By("creating OIDC role bound to service account")
			_, err := utils.RunVaultCommand("write", fmt.Sprintf("auth/oidc/role/%s", oidcRoleName),
				"role_type=jwt",
				"bound_audiences=https://kubernetes.default.svc.cluster.local",
				fmt.Sprintf("bound_subject=system:serviceaccount:%s:%s", testNamespace, oidcSAName),
				"user_claim=sub",
				fmt.Sprintf("policies=%s,default", oidcPolicyName),
				"ttl=1h",
			)
			Expect(err).NotTo(HaveOccurred())

			By("getting service account token")
			saToken, err := utils.GetServiceAccountToken(testNamespace, oidcSAName)
			Expect(err).NotTo(HaveOccurred())
			saToken = strings.TrimSpace(saToken)

			By("authenticating via OIDC (JWT at oidc path) with SA token")
			loginOutput, err := utils.VaultLoginWithJWT("auth/oidc", oidcRoleName, saToken)
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

		It("TC-AU-OIDC-02: should verify OIDC issuer discovery from Kubernetes API", func() {
			By("fetching OIDC discovery document from Kubernetes API")
			cmd := exec.Command("kubectl", "get", "--raw", "/.well-known/openid-configuration")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var oidcConfig struct {
				Issuer               string   `json:"issuer"`
				JWKSURI              string   `json:"jwks_uri"`
				SigningAlgsSupported []string `json:"id_token_signing_alg_values_supported"`
			}
			err = json.Unmarshal([]byte(output), &oidcConfig)
			Expect(err).NotTo(HaveOccurred())

			By("verifying OIDC configuration fields are present")
			Expect(oidcConfig.Issuer).NotTo(BeEmpty(), "issuer should be present")
			Expect(oidcConfig.JWKSURI).NotTo(BeEmpty(), "jwks_uri should be present")

			By("verifying Vault's OIDC auth config matches the issuer")
			vaultConfig, err := utils.RunVaultCommand("read", "-format=json", "auth/oidc/config")
			Expect(err).NotTo(HaveOccurred())

			// Vault config should reference the same issuer
			Expect(vaultConfig).To(ContainSubstring(oidcConfig.Issuer))
		})

		It("TC-AU-OIDC-03: should support custom audience via TokenRequest API", func() {
			customAudience := "vault-oidc-custom"
			customAudRole := "tc-au-oidc-custom-aud"

			By("creating OIDC role bound to custom audience")
			_, err := utils.RunVaultCommand("write", fmt.Sprintf("auth/oidc/role/%s", customAudRole),
				"role_type=jwt",
				fmt.Sprintf("bound_audiences=%s", customAudience),
				fmt.Sprintf("bound_subject=system:serviceaccount:%s:%s", testNamespace, oidcSAName),
				"user_claim=sub",
				"policies=default",
			)
			Expect(err).NotTo(HaveOccurred())

			By("creating service account token with custom audience via TokenRequest API")
			cmd := exec.Command("kubectl", "create", "token", oidcSAName,
				"-n", testNamespace,
				"--audience", customAudience,
				"--duration", "1h")
			tokenOutput, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			customToken := strings.TrimSpace(tokenOutput)

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

			By("creating OIDC role bound to a specific audience")
			_, err := utils.RunVaultCommand("write", fmt.Sprintf("auth/oidc/role/%s", wrongAudRole),
				"role_type=jwt",
				"bound_audiences=https://wrong-audience.example.com",
				"user_claim=sub",
				"policies=default",
			)
			Expect(err).NotTo(HaveOccurred())

			By("getting service account token with default audience")
			saToken, err := utils.GetServiceAccountToken(testNamespace, oidcSAName)
			Expect(err).NotTo(HaveOccurred())
			saToken = strings.TrimSpace(saToken)

			By("attempting login - should fail due to audience mismatch")
			_, err = utils.VaultLoginWithJWT("auth/oidc", wrongAudRole, saToken)
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
