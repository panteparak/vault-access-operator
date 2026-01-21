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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	"github.com/panteparak/vault-access-operator/test/utils"
)

var _ = Describe("VaultClusterRole Tests", Ordered, func() {
	// Test configuration
	const (
		clusterRoleName       = "tc-cr-cluster-role"
		clusterRolePolicyName = "tc-cr-cluster-policy"
		clusterRoleSAName     = "tc-cr-sa"
		namespacedPolicyName  = "tc-cr-ns-policy"
	)

	BeforeAll(func() {
		By("creating test service account for cluster role tests")
		cmd := exec.Command("kubectl", "create", "serviceaccount", clusterRoleSAName, "-n", testNamespace)
		_, _ = utils.Run(cmd)

		By("creating VaultClusterPolicy for cluster role binding")
		clusterPolicyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: %s
spec:
  connectionRef: %s
  rules:
    - path: "secret/data/shared/*"
      capabilities: ["read", "list"]
`, clusterRolePolicyName, sharedVaultConnectionName)

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = stringReader(clusterPolicyYAML)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("creating namespaced VaultPolicy for cluster role binding")
		nsPolicyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  rules:
    - path: "secret/data/%s/*"
      capabilities: ["read", "list"]
`, namespacedPolicyName, testNamespace, sharedVaultConnectionName, testNamespace)

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = stringReader(nsPolicyYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for policies to become Active")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "vaultclusterpolicy", clusterRolePolicyName,
				"-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "vaultpolicy", namespacedPolicyName,
				"-n", testNamespace, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterAll(func() {
		By("cleaning up VaultClusterRole test resources")
		cmd := exec.Command("kubectl", "delete", "vaultclusterrole", clusterRoleName,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "vaultclusterpolicy", clusterRolePolicyName,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "vaultpolicy", namespacedPolicyName,
			"-n", testNamespace, "--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "serviceaccount", clusterRoleSAName,
			"-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	Context("TC-CR: VaultClusterRole Lifecycle", func() {
		It("TC-CR01: Create VaultClusterRole referencing multiple policies", func() {
			By("creating VaultClusterRole resource")
			roleYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: %s
spec:
  connectionRef: %s
  authPath: "auth/kubernetes"
  serviceAccounts:
    - name: %s
      namespace: %s
  policies:
    - kind: VaultClusterPolicy
      name: %s
    - kind: VaultPolicy
      name: %s
      namespace: %s
  tokenTTL: "1h"
  tokenMaxTTL: "24h"
`, clusterRoleName, sharedVaultConnectionName, clusterRoleSAName, testNamespace,
				clusterRolePolicyName, namespacedPolicyName, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultClusterRole")

			By("waiting for VaultClusterRole to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultclusterrole", clusterRoleName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultClusterRole not active, got: %s", output)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying VaultClusterRole has correct vaultRoleName")
			cmd = exec.Command("kubectl", "get", "vaultclusterrole", clusterRoleName,
				"-o", "jsonpath={.status.vaultRoleName}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal(clusterRoleName))

			By("verifying VaultClusterRole has resolved policies")
			cmd = exec.Command("kubectl", "get", "vaultclusterrole", clusterRoleName,
				"-o", "jsonpath={.status.resolvedPolicies}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring(clusterRolePolicyName))
		})

		It("TC-CR02: Verify cluster role configuration in Vault", func() {
			expectedNamespacedPolicyName := fmt.Sprintf("%s-%s", testNamespace, namespacedPolicyName)

			By("reading role configuration from Vault")
			var roleJSON string
			Eventually(func(g Gomega) {
				var err error
				roleJSON, err = utils.ReadVaultRole("auth/kubernetes", clusterRoleName)
				g.Expect(err).NotTo(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("parsing role JSON and verifying configuration")
			var roleResponse struct {
				Data struct {
					BoundServiceAccountNames      []string `json:"bound_service_account_names"`
					BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
					TokenPolicies                 []string `json:"token_policies"`
					TokenTTL                      int      `json:"token_ttl"`
					TokenMaxTTL                   int      `json:"token_max_ttl"`
				} `json:"data"`
			}
			err := json.Unmarshal([]byte(roleJSON), &roleResponse)
			Expect(err).NotTo(HaveOccurred(), "Failed to parse role JSON: %s", roleJSON)

			By("verifying bound service accounts")
			Expect(roleResponse.Data.BoundServiceAccountNames).To(ContainElement(clusterRoleSAName),
				"Role should have test SA as bound service account")

			By("verifying bound namespaces")
			Expect(roleResponse.Data.BoundServiceAccountNamespaces).To(ContainElement(testNamespace),
				"Role should have test namespace as bound namespace")

			By("verifying policies are attached")
			Expect(roleResponse.Data.TokenPolicies).To(ContainElement(clusterRolePolicyName),
				"Role should have cluster policy attached")
			Expect(roleResponse.Data.TokenPolicies).To(ContainElement(expectedNamespacedPolicyName),
				"Role should have namespaced policy attached")

			By("verifying token TTL configuration")
			// tokenTTL is "1h" = 3600 seconds
			Expect(roleResponse.Data.TokenTTL).To(Equal(3600),
				"Role should have token_ttl of 1h (3600 seconds)")
			// tokenMaxTTL is "24h" = 86400 seconds
			Expect(roleResponse.Data.TokenMaxTTL).To(Equal(86400),
				"Role should have token_max_ttl of 24h (86400 seconds)")
		})

		It("TC-CR03-DEL: Remove cluster role from Vault on deletion", func() {
			tempClusterRoleName := "tc-cr03-temp"

			By("creating temporary VaultClusterRole")
			roleYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: %s
spec:
  connectionRef: %s
  authPath: "auth/kubernetes"
  serviceAccounts:
    - name: %s
      namespace: %s
  policies:
    - kind: VaultClusterPolicy
      name: %s
  tokenTTL: "15m"
`, tempClusterRoleName, sharedVaultConnectionName, clusterRoleSAName, testNamespace, clusterRolePolicyName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultClusterRole to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultclusterrole", tempClusterRoleName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying role exists in Vault")
			Eventually(func(g Gomega) {
				exists, err := utils.VaultRoleExists("auth/kubernetes", tempClusterRoleName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeTrue())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("deleting the VaultClusterRole")
			cmd = exec.Command("kubectl", "delete", "vaultclusterrole", tempClusterRoleName)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying role is removed from Vault")
			Eventually(func(g Gomega) {
				exists, err := utils.VaultRoleExists("auth/kubernetes", tempClusterRoleName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeFalse(), "Role should be removed from Vault after deletion")
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})
	})

	Context("TC-CR: VaultClusterRole Error Handling", func() {
		// verifyClusterRoleError is a helper to test VaultClusterRole error scenarios
		verifyClusterRoleError := func(roleName, roleYAML string, expectedMsgPatterns []string) {
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultClusterRole enters Error or Pending phase")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultclusterrole", roleName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Error"), Equal("Pending")))
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying status message indicates the issue")
			cmd = exec.Command("kubectl", "get", "vaultclusterrole", roleName,
				"-o", "jsonpath={.status.message}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			if output != "" {
				matchers := make([]types.GomegaMatcher, len(expectedMsgPatterns))
				for i, pattern := range expectedMsgPatterns {
					matchers[i] = ContainSubstring(pattern)
				}
				Expect(output).To(Or(matchers...))
			}

			By("cleaning up cluster role")
			cmd = exec.Command("kubectl", "delete", "vaultclusterrole", roleName,
				"--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
		}

		It("TC-CR04: Handle invalid connection reference", func() {
			roleName := "tc-cr04-invalid-conn"
			By("creating VaultClusterRole with non-existent connection")
			roleYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: %s
spec:
  connectionRef: non-existent-connection
  authPath: "auth/kubernetes"
  serviceAccounts:
    - name: %s
      namespace: %s
  policies:
    - kind: VaultClusterPolicy
      name: %s
  tokenTTL: "1h"
`, roleName, clusterRoleSAName, testNamespace, clusterRolePolicyName)
			verifyClusterRoleError(roleName, roleYAML, []string{"not found", "connection", "Not Found"})
		})

		It("TC-CR05: Handle missing policy reference", func() {
			roleName := "tc-cr05-missing-policy"
			By("creating VaultClusterRole referencing non-existent policy")
			roleYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: %s
spec:
  connectionRef: %s
  authPath: "auth/kubernetes"
  serviceAccounts:
    - name: %s
      namespace: %s
  policies:
    - kind: VaultClusterPolicy
      name: non-existent-cluster-policy
  tokenTTL: "1h"
`, roleName, sharedVaultConnectionName, clusterRoleSAName, testNamespace)
			verifyClusterRoleError(roleName, roleYAML, []string{"not found", "policy", "Not Found"})
		})
	})
})
