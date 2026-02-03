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

var _ = Describe("Authentication Tests", Ordered, Label("auth"), func() {
	// Test configuration
	const (
		authSAName     = "tc-au-sa"
		authPolicyName = "tc-au-policy"
		authRoleName   = "tc-au-role"
	)

	BeforeAll(func() {
		By("creating test service account for auth tests")
		cmd := exec.Command("kubectl", "create", "serviceaccount", authSAName, "-n", testNamespace)
		_, _ = utils.Run(cmd)

		By("creating VaultPolicy for auth tests")
		policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  rules:
    - path: "secret/data/auth-test/*"
      capabilities: ["read"]
`, authPolicyName, testNamespace, sharedVaultConnectionName)

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = stringReader(policyYAML)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for auth test policy to become Active")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "vaultpolicy", authPolicyName,
				"-n", testNamespace, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("creating VaultRole for auth tests")
		roleYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  serviceAccounts:
    - %s
  policies:
    - kind: VaultPolicy
      name: %s
      namespace: %s
  tokenTTL: "15m"
`, authRoleName, testNamespace, sharedVaultConnectionName, authSAName, authPolicyName, testNamespace)

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = stringReader(roleYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for auth role to become Active")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "vaultrole", authRoleName,
				"-n", testNamespace, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterAll(func() {
		By("cleaning up authentication test resources")
		cmd := exec.Command("kubectl", "delete", "vaultrole", authRoleName,
			"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "vaultpolicy", authPolicyName,
			"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "serviceaccount", authSAName,
			"-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	Context("TC-AU01: Service Account Authentication", func() {
		It("TC-AU01-01: Allow bound service account to authenticate with Vault", func() {
			expectedPolicyVaultName := fmt.Sprintf("%s-%s", testNamespace, authPolicyName)
			expectedRoleVaultName := fmt.Sprintf("%s-%s", testNamespace, authRoleName)

			By("getting a JWT token for the service account")
			saToken, err := utils.GetServiceAccountToken(testNamespace, authSAName)
			Expect(err).NotTo(HaveOccurred())
			saToken = strings.TrimSpace(saToken)
			Expect(saToken).NotTo(BeEmpty(), "Service account token should not be empty")

			By("attempting to login to Vault with the service account JWT")
			Eventually(func(g Gomega) {
				loginOutput, err := utils.VaultLoginWithJWT("auth/kubernetes", expectedRoleVaultName, saToken)
				g.Expect(err).NotTo(HaveOccurred(), "Vault login should succeed")

				// Parse the login response to verify policies
				var loginResponse struct {
					Auth struct {
						ClientToken   string   `json:"client_token"`
						TokenPolicies []string `json:"token_policies"`
						LeaseDuration int      `json:"lease_duration"`
					} `json:"auth"`
				}
				err = json.Unmarshal([]byte(loginOutput), &loginResponse)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to parse login response")

				// Verify we got a client token
				g.Expect(loginResponse.Auth.ClientToken).NotTo(BeEmpty(),
					"Should receive a Vault client token")

				// Verify policies are attached
				g.Expect(loginResponse.Auth.TokenPolicies).To(ContainElement(expectedPolicyVaultName),
					"Token should have the auth test policy attached")

				// Verify lease duration matches TTL (15m = 900s)
				g.Expect(loginResponse.Auth.LeaseDuration).To(Equal(900),
					"Token lease duration should be 15m (900 seconds)")
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-AU01-02: Reject authentication with incorrect service account", func() {
			wrongSAName := "tc-au02-wrong-sa"
			expectedRoleVaultName := fmt.Sprintf("%s-%s", testNamespace, authRoleName)

			By("creating a service account that is NOT bound to the role")
			cmd := exec.Command("kubectl", "create", "serviceaccount", wrongSAName, "-n", testNamespace)
			_, _ = utils.Run(cmd)

			By("getting a JWT token for the wrong service account")
			wrongSAToken, err := utils.GetServiceAccountToken(testNamespace, wrongSAName)
			Expect(err).NotTo(HaveOccurred())
			wrongSAToken = strings.TrimSpace(wrongSAToken)
			Expect(wrongSAToken).NotTo(BeEmpty())

			By("attempting to login to Vault with the wrong service account JWT")
			_, err = utils.VaultLoginWithJWT("auth/kubernetes", expectedRoleVaultName, wrongSAToken)
			Expect(err).To(HaveOccurred(), "Vault login should fail with unbound service account")

			By("cleaning up wrong service account")
			cmd = exec.Command("kubectl", "delete", "serviceaccount", wrongSAName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("TC-AU01-03: Reject authentication with invalid JWT token", func() {
			expectedRoleVaultName := fmt.Sprintf("%s-%s", testNamespace, authRoleName)

			By("attempting to login to Vault with an invalid JWT")
			invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.token"
			_, err := utils.VaultLoginWithJWT("auth/kubernetes", expectedRoleVaultName, invalidToken)
			Expect(err).To(HaveOccurred(), "Vault login should fail with invalid JWT")
		})

		It("TC-AU01-04: Successfully re-authenticate after token expiration", func() {
			// This test verifies that the operator can handle token expiration gracefully
			// by re-authenticating when the Vault token expires
			expectedRoleVaultName := fmt.Sprintf("%s-%s", testNamespace, authRoleName)

			By("getting initial service account token")
			saToken, err := utils.GetServiceAccountToken(testNamespace, authSAName)
			Expect(err).NotTo(HaveOccurred())
			saToken = strings.TrimSpace(saToken)

			By("performing initial authentication to Vault")
			loginOutput, err := utils.VaultLoginWithJWT("auth/kubernetes", expectedRoleVaultName, saToken)
			Expect(err).NotTo(HaveOccurred())

			// Parse the response to get the initial token
			var loginResponse struct {
				Auth struct {
					ClientToken   string `json:"client_token"`
					LeaseDuration int    `json:"lease_duration"`
				} `json:"auth"`
			}
			err = json.Unmarshal([]byte(loginOutput), &loginResponse)
			Expect(err).NotTo(HaveOccurred())
			initialToken := loginResponse.Auth.ClientToken
			Expect(initialToken).NotTo(BeEmpty())

			By("simulating token expiration by revoking the token")
			// Revoke the token to simulate expiration
			_, err = utils.RunVaultCommand("token", "revoke", initialToken)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the revoked token is no longer valid")
			// This should fail since the token was revoked
			_, err = utils.RunVaultCommandWithToken(initialToken, "token", "lookup-self")
			Expect(err).To(HaveOccurred(), "Revoked token should not be valid")

			By("re-authenticating with a fresh service account token")
			// Get a new SA token and re-authenticate
			newSAToken, err := utils.GetServiceAccountToken(testNamespace, authSAName)
			Expect(err).NotTo(HaveOccurred())
			newSAToken = strings.TrimSpace(newSAToken)

			newLoginOutput, err := utils.VaultLoginWithJWT("auth/kubernetes", expectedRoleVaultName, newSAToken)
			Expect(err).NotTo(HaveOccurred())

			var newLoginResponse struct {
				Auth struct {
					ClientToken string `json:"client_token"`
				} `json:"auth"`
			}
			err = json.Unmarshal([]byte(newLoginOutput), &newLoginResponse)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the new token is valid")
			Expect(newLoginResponse.Auth.ClientToken).NotTo(BeEmpty())
			Expect(newLoginResponse.Auth.ClientToken).NotTo(Equal(initialToken),
				"New authentication should produce a different token")
		})

		It("TC-AU01-05: Verify multiple service accounts can authenticate to the same role", func() {
			// This tests the scenario where a role is bound to multiple service accounts
			additionalSAName := "tc-au01-05-additional-sa"
			expectedRoleVaultName := fmt.Sprintf("%s-%s", testNamespace, authRoleName)

			By("creating an additional service account")
			cmd := exec.Command("kubectl", "create", "serviceaccount", additionalSAName, "-n", testNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("updating the VaultRole to include the additional service account")
			roleYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  serviceAccounts:
    - %s
    - %s
  policies:
    - kind: VaultPolicy
      name: %s
      namespace: %s
  tokenTTL: "15m"
`, authRoleName, testNamespace, sharedVaultConnectionName, authSAName, additionalSAName, authPolicyName, testNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for role update to propagate")
			time.Sleep(5 * time.Second)

			By("authenticating with the original service account")
			saToken, err := utils.GetServiceAccountToken(testNamespace, authSAName)
			Expect(err).NotTo(HaveOccurred())
			_, err = utils.VaultLoginWithJWT("auth/kubernetes", expectedRoleVaultName, strings.TrimSpace(saToken))
			Expect(err).NotTo(HaveOccurred(), "Original SA should still authenticate")

			By("authenticating with the additional service account")
			additionalSAToken, err := utils.GetServiceAccountToken(testNamespace, additionalSAName)
			Expect(err).NotTo(HaveOccurred())
			_, err = utils.VaultLoginWithJWT("auth/kubernetes", expectedRoleVaultName, strings.TrimSpace(additionalSAToken))
			Expect(err).NotTo(HaveOccurred(), "Additional SA should authenticate after role update")

			By("cleaning up the additional service account")
			cmd = exec.Command("kubectl", "delete", "serviceaccount", additionalSAName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})
	})
})
