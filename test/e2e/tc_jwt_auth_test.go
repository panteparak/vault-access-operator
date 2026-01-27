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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

var _ = Describe("TC-AU04: JWT Authentication", Ordered, func() {
	// Test configuration
	const (
		jwtConnectionName = "tc-au04-jwt-conn"
		jwtPolicyName     = "tc-au04-jwt-policy"
		jwtRoleName       = "tc-au04-jwt-role"
		jwtSAName         = "tc-au04-jwt-sa"
	)

	// jwtOperatorPolicyHCL extends the operator policy with JWT auth permissions
	const jwtOperatorPolicyHCL = `
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

	BeforeAll(func() {
		By("creating service account for JWT auth tests")
		cmd := exec.Command("kubectl", "create", "serviceaccount", jwtSAName, "-n", testNamespace)
		_, _ = utils.Run(cmd)

		By("enabling JWT auth method in Vault")
		_, err := utils.RunVaultCommand("auth", "enable", "jwt")
		// Ignore error if already enabled
		if err != nil && !strings.Contains(err.Error(), "already in use") {
			Fail(fmt.Sprintf("Failed to enable JWT auth: %v", err))
		}

		By("creating JWT operator policy")
		cmd = exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "-i", "--",
			"vault", "policy", "write", "jwt-operator-policy", "-")
		cmd.Stdin = stringReader(jwtOperatorPolicyHCL)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("cleaning up JWT auth test resources")

		// Delete VaultConnection
		cmd := exec.Command("kubectl", "delete", "vaultconnection", jwtConnectionName,
			"--ignore-not-found", "--timeout=30s")
		_, _ = utils.Run(cmd)

		// Delete VaultPolicy
		cmd = exec.Command("kubectl", "delete", "vaultpolicy", jwtPolicyName,
			"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
		_, _ = utils.Run(cmd)

		// Delete VaultRole
		cmd = exec.Command("kubectl", "delete", "vaultrole", jwtRoleName,
			"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
		_, _ = utils.Run(cmd)

		// Delete service account
		cmd = exec.Command("kubectl", "delete", "serviceaccount", jwtSAName,
			"-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		// Wait for cleanup
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "vaultconnection", jwtConnectionName)
			_, err := utils.Run(cmd)
			g.Expect(err).To(HaveOccurred()) // Should fail when deleted
		}, 30*time.Second, 2*time.Second).Should(Succeed())
	})

	Context("TC-AU04: JWT Auth with Kubernetes Service Account Token", func() {
		It("TC-AU04-01: should authenticate using JWT method with service account token", func() {
			By("getting the Kubernetes OIDC issuer URL")
			cmd := exec.Command("kubectl", "get", "--raw", "/.well-known/openid-configuration")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var oidcConfig struct {
				Issuer  string `json:"issuer"`
				JWKSURI string `json:"jwks_uri"`
			}
			err = json.Unmarshal([]byte(output), &oidcConfig)
			Expect(err).NotTo(HaveOccurred())
			Expect(oidcConfig.Issuer).NotTo(BeEmpty())

			By("configuring JWT auth to validate Kubernetes tokens")
			// Configure JWT auth with Kubernetes OIDC issuer
			_, err = utils.RunVaultCommand("write", "auth/jwt/config",
				fmt.Sprintf("oidc_discovery_url=%s", oidcConfig.Issuer),
				"bound_issuer="+oidcConfig.Issuer,
			)
			Expect(err).NotTo(HaveOccurred())

			By("creating JWT auth role in Vault")
			jwtVaultRoleName := fmt.Sprintf("%s-%s", testNamespace, jwtRoleName)
			_, err = utils.RunVaultCommand("write", fmt.Sprintf("auth/jwt/role/%s", jwtVaultRoleName),
				"role_type=jwt",
				"bound_audiences=https://kubernetes.default.svc.cluster.local",
				fmt.Sprintf("bound_subject=system:serviceaccount:%s:%s", testNamespace, jwtSAName),
				"user_claim=sub",
				"policies=default",
				"ttl=1h",
			)
			Expect(err).NotTo(HaveOccurred())

			By("getting a service account token")
			saToken, err := utils.GetServiceAccountToken(testNamespace, jwtSAName)
			Expect(err).NotTo(HaveOccurred())
			saToken = strings.TrimSpace(saToken)

			By("attempting JWT login with service account token")
			loginOutput, err := utils.VaultLoginWithJWT("auth/jwt", jwtVaultRoleName, saToken)
			Expect(err).NotTo(HaveOccurred())

			// Parse login response
			var loginResponse struct {
				Auth struct {
					ClientToken string `json:"client_token"`
				} `json:"auth"`
			}
			err = json.Unmarshal([]byte(loginOutput), &loginResponse)
			Expect(err).NotTo(HaveOccurred())
			Expect(loginResponse.Auth.ClientToken).NotTo(BeEmpty())
		})

		It("TC-AU04-02: should reject JWT with wrong audience", func() {
			By("creating a role with specific audience")
			wrongAudRole := "tc-au04-wrong-aud-role"
			_, err := utils.RunVaultCommand("write", fmt.Sprintf("auth/jwt/role/%s", wrongAudRole),
				"role_type=jwt",
				"bound_audiences=https://wrong-audience.example.com",
				"user_claim=sub",
				"policies=default",
			)
			Expect(err).NotTo(HaveOccurred())

			By("getting service account token with default audience")
			saToken, err := utils.GetServiceAccountToken(testNamespace, jwtSAName)
			Expect(err).NotTo(HaveOccurred())
			saToken = strings.TrimSpace(saToken)

			By("attempting login - should fail due to audience mismatch")
			_, err = utils.VaultLoginWithJWT("auth/jwt", wrongAudRole, saToken)
			Expect(err).To(HaveOccurred())

			By("cleaning up wrong audience role")
			_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/jwt/role/%s", wrongAudRole))
		})

		It("TC-AU04-03: should reject JWT with wrong subject", func() {
			By("creating a role with specific bound subject")
			wrongSubRole := "tc-au04-wrong-sub-role"
			_, err := utils.RunVaultCommand("write", fmt.Sprintf("auth/jwt/role/%s", wrongSubRole),
				"role_type=jwt",
				"bound_audiences=https://kubernetes.default.svc.cluster.local",
				"bound_subject=system:serviceaccount:other-namespace:other-sa",
				"user_claim=sub",
				"policies=default",
			)
			Expect(err).NotTo(HaveOccurred())

			By("getting service account token")
			saToken, err := utils.GetServiceAccountToken(testNamespace, jwtSAName)
			Expect(err).NotTo(HaveOccurred())
			saToken = strings.TrimSpace(saToken)

			By("attempting login - should fail due to subject mismatch")
			_, err = utils.VaultLoginWithJWT("auth/jwt", wrongSubRole, saToken)
			Expect(err).To(HaveOccurred())

			By("cleaning up wrong subject role")
			_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/jwt/role/%s", wrongSubRole))
		})
	})
})

var _ = Describe("TC-AU05: OIDC-style JWT Authentication", Ordered, func() {
	// This test uses Kind's built-in OIDC issuer discovery to test OIDC-style authentication
	// without requiring an external OIDC provider like Dex or Keycloak

	const (
		oidcSAName   = "tc-au05-oidc-sa"
		oidcRoleName = "tc-au05-oidc-role"
	)

	BeforeAll(func() {
		By("creating service account for OIDC tests")
		cmd := exec.Command("kubectl", "create", "serviceaccount", oidcSAName, "-n", testNamespace)
		_, _ = utils.Run(cmd)
	})

	AfterAll(func() {
		By("cleaning up OIDC test resources")
		cmd := exec.Command("kubectl", "delete", "serviceaccount", oidcSAName,
			"-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/jwt/role/%s", oidcRoleName))
	})

	Context("TC-AU05: OIDC with Kind's built-in OIDC issuer", func() {
		It("TC-AU05-01: should discover OIDC configuration from Kubernetes API", func() {
			By("fetching OIDC discovery document")
			cmd := exec.Command("kubectl", "get", "--raw", "/.well-known/openid-configuration")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var oidcConfig struct {
				Issuer                 string   `json:"issuer"`
				JWKSURI                string   `json:"jwks_uri"`
				ResponseTypesSupported []string `json:"response_types_supported"`
				SubjectTypesSupported  []string `json:"subject_types_supported"`
				SigningAlgsSupported   []string `json:"id_token_signing_alg_values_supported"`
				ClaimsSupported        []string `json:"claims_supported"`
			}
			err = json.Unmarshal([]byte(output), &oidcConfig)
			Expect(err).NotTo(HaveOccurred())

			By("verifying OIDC configuration fields")
			Expect(oidcConfig.Issuer).NotTo(BeEmpty(), "issuer should be present")
			Expect(oidcConfig.JWKSURI).NotTo(BeEmpty(), "jwks_uri should be present")
		})

		It("TC-AU05-02: should authenticate with OIDC-discovered keys", func() {
			By("getting the OIDC issuer URL from Kubernetes")
			cmd := exec.Command("kubectl", "get", "--raw", "/.well-known/openid-configuration")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var oidcConfig struct {
				Issuer string `json:"issuer"`
			}
			err = json.Unmarshal([]byte(output), &oidcConfig)
			Expect(err).NotTo(HaveOccurred())

			By("configuring JWT auth with OIDC discovery")
			_, err = utils.RunVaultCommand("write", "auth/jwt/config",
				fmt.Sprintf("oidc_discovery_url=%s", oidcConfig.Issuer),
			)
			Expect(err).NotTo(HaveOccurred())

			By("creating OIDC-style role")
			_, err = utils.RunVaultCommand("write", fmt.Sprintf("auth/jwt/role/%s", oidcRoleName),
				"role_type=jwt",
				"bound_audiences=https://kubernetes.default.svc.cluster.local",
				fmt.Sprintf("bound_claims=sub=system:serviceaccount:%s:%s", testNamespace, oidcSAName),
				"user_claim=sub",
				"policies=default",
				"ttl=15m",
			)
			Expect(err).NotTo(HaveOccurred())

			By("getting service account token")
			saToken, err := utils.GetServiceAccountToken(testNamespace, oidcSAName)
			Expect(err).NotTo(HaveOccurred())
			saToken = strings.TrimSpace(saToken)

			By("authenticating via JWT method with OIDC-discovered keys")
			loginOutput, err := utils.VaultLoginWithJWT("auth/jwt", oidcRoleName, saToken)
			Expect(err).NotTo(HaveOccurred())

			var loginResponse struct {
				Auth struct {
					ClientToken   string   `json:"client_token"`
					LeaseDuration int      `json:"lease_duration"`
					Policies      []string `json:"policies"`
				} `json:"auth"`
			}
			err = json.Unmarshal([]byte(loginOutput), &loginResponse)
			Expect(err).NotTo(HaveOccurred())

			Expect(loginResponse.Auth.ClientToken).NotTo(BeEmpty())
			Expect(loginResponse.Auth.LeaseDuration).To(BeNumerically("<=", 900)) // 15m = 900s
			Expect(loginResponse.Auth.Policies).To(ContainElement("default"))
		})

		It("TC-AU05-03: should support custom audiences via TokenRequest API", func() {
			By("creating service account token with custom audience")
			customAudience := "vault-custom-audience"
			cmd := exec.Command("kubectl", "create", "token", oidcSAName,
				"-n", testNamespace,
				"--audience", customAudience,
				"--duration", "1h")
			tokenOutput, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			customToken := strings.TrimSpace(tokenOutput)

			By("creating role that accepts custom audience")
			customAudRole := "tc-au05-custom-aud-role"
			_, err = utils.RunVaultCommand("write", fmt.Sprintf("auth/jwt/role/%s", customAudRole),
				"role_type=jwt",
				fmt.Sprintf("bound_audiences=%s", customAudience),
				fmt.Sprintf("bound_claims=sub=system:serviceaccount:%s:%s", testNamespace, oidcSAName),
				"user_claim=sub",
				"policies=default",
			)
			Expect(err).NotTo(HaveOccurred())

			By("authenticating with custom-audience token")
			loginOutput, err := utils.VaultLoginWithJWT("auth/jwt", customAudRole, customToken)
			Expect(err).NotTo(HaveOccurred())

			var loginResponse struct {
				Auth struct {
					ClientToken string `json:"client_token"`
				} `json:"auth"`
			}
			err = json.Unmarshal([]byte(loginOutput), &loginResponse)
			Expect(err).NotTo(HaveOccurred())
			Expect(loginResponse.Auth.ClientToken).NotTo(BeEmpty())

			By("cleaning up custom audience role")
			_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/jwt/role/%s", customAudRole))
		})
	})
})

var _ = Describe("TC-AU06: VaultConnection with JWT Auth", Ordered, func() {
	// This test verifies VaultConnection CRD works with JWT authentication

	const (
		jwtConnSAName     = "tc-au06-jwt-conn-sa"
		jwtConnName       = "tc-au06-jwt-connection"
		jwtConnRoleName   = "tc-au06-jwt-conn-role"
		jwtConnPolicyName = "tc-au06-jwt-conn-policy"
	)

	BeforeAll(func() {
		By("creating dedicated service account for VaultConnection JWT test")
		cmd := exec.Command("kubectl", "create", "serviceaccount", jwtConnSAName, "-n", testNamespace)
		_, _ = utils.Run(cmd)

		By("getting OIDC issuer URL")
		cmd = exec.Command("kubectl", "get", "--raw", "/.well-known/openid-configuration")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		var oidcConfig struct {
			Issuer string `json:"issuer"`
		}
		err = json.Unmarshal([]byte(output), &oidcConfig)
		Expect(err).NotTo(HaveOccurred())

		By("configuring JWT auth for VaultConnection")
		_, err = utils.RunVaultCommand("write", "auth/jwt/config",
			fmt.Sprintf("oidc_discovery_url=%s", oidcConfig.Issuer),
		)
		Expect(err).NotTo(HaveOccurred())

		By("creating Vault policy for VaultConnection")
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
		cmd = exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "-i", "--",
			"vault", "policy", "write", jwtConnPolicyName, "-")
		cmd.Stdin = stringReader(connPolicyHCL)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("creating JWT role for VaultConnection")
		_, err = utils.RunVaultCommand("write", fmt.Sprintf("auth/jwt/role/%s", jwtConnRoleName),
			"role_type=jwt",
			"bound_audiences=https://kubernetes.default.svc.cluster.local,vault",
			fmt.Sprintf("bound_claims=sub=system:serviceaccount:%s:%s", testNamespace, jwtConnSAName),
			"user_claim=sub",
			fmt.Sprintf("policies=%s", jwtConnPolicyName),
			"ttl=1h",
		)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("cleaning up VaultConnection JWT test resources")

		cmd := exec.Command("kubectl", "delete", "vaultconnection", jwtConnName,
			"--ignore-not-found", "--timeout=30s")
		_, _ = utils.Run(cmd)

		_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/jwt/role/%s", jwtConnRoleName))
		_, _ = utils.RunVaultCommand("policy", "delete", jwtConnPolicyName)

		cmd = exec.Command("kubectl", "delete", "serviceaccount", jwtConnSAName,
			"-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "vaultconnection", jwtConnName)
			_, err := utils.Run(cmd)
			g.Expect(err).To(HaveOccurred())
		}, 30*time.Second, 2*time.Second).Should(Succeed())
	})

	It("TC-AU06-01: should create VaultConnection using JWT auth spec", func() {
		Skip("VaultConnection JWT auth not yet implemented - this test documents the expected API")

		// This test is skipped because VaultConnection CRD does not yet support JWT auth directly.
		// When JWT auth is added to the VaultConnection spec, this test should be enabled.
		//
		// Expected VaultConnection YAML:
		// apiVersion: vault.platform.io/v1alpha1
		// kind: VaultConnection
		// metadata:
		//   name: jwt-connection
		// spec:
		//   address: http://vault.vault.svc.cluster.local:8200
		//   auth:
		//     jwt:
		//       role: my-jwt-role
		//       authPath: jwt
		//       serviceAccountRef:
		//         name: my-service-account
		//         namespace: my-namespace
	})
})
