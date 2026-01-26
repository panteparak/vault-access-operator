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
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// TC-OP: Operator Token Tests
// These tests validate that the operator token has the correct permissions
// following the Principle of Least Privilege.
var _ = Describe("TC-OP: Operator Token Permissions", func() {

	// Get the operator token for capability checks
	var operatorToken string

	BeforeEach(func() {
		// Get a fresh operator token for testing
		var err error
		operatorToken, err = getOperatorToken()
		Expect(err).NotTo(HaveOccurred(), "Failed to get operator token")
		Expect(operatorToken).NotTo(BeEmpty())
	})

	Describe("TC-OP01: Policy Management Permissions", func() {
		It("should have create capability on sys/policies/acl/*", func() {
			By("checking capabilities on policy path")
			capabilities := getTokenCapabilities(operatorToken, "sys/policies/acl/test-policy")
			Expect(capabilities).To(ContainSubstring("create"))
			Expect(capabilities).To(ContainSubstring("read"))
			Expect(capabilities).To(ContainSubstring("update"))
			Expect(capabilities).To(ContainSubstring("delete"))
		})

		It("should have list capability on sys/policies/acl", func() {
			By("checking list capability on policies path")
			capabilities := getTokenCapabilities(operatorToken, "sys/policies/acl")
			Expect(capabilities).To(ContainSubstring("list"))
		})
	})

	Describe("TC-OP02: Kubernetes Auth Role Permissions", func() {
		It("should have CRUD capabilities on auth/kubernetes/role/*", func() {
			By("checking capabilities on kubernetes role path")
			capabilities := getTokenCapabilities(operatorToken, "auth/kubernetes/role/test-role")
			Expect(capabilities).To(ContainSubstring("create"))
			Expect(capabilities).To(ContainSubstring("read"))
			Expect(capabilities).To(ContainSubstring("update"))
			Expect(capabilities).To(ContainSubstring("delete"))
		})

		It("should have list capability on auth/kubernetes/role", func() {
			By("checking list capability on roles path")
			capabilities := getTokenCapabilities(operatorToken, "auth/kubernetes/role")
			Expect(capabilities).To(ContainSubstring("list"))
		})
	})

	Describe("TC-OP03: Health Check Permissions", func() {
		It("should have read capability on sys/health", func() {
			By("checking capabilities on health path")
			capabilities := getTokenCapabilities(operatorToken, "sys/health")
			Expect(capabilities).To(ContainSubstring("read"))
		})
	})

	Describe("TC-OP04: Denied Paths (Principle of Least Privilege)", func() {
		It("should NOT have access to secret/* paths", func() {
			By("verifying operator cannot access secrets - operator manages access, not secrets")
			capabilities := getTokenCapabilities(operatorToken, "secret/data/test")
			Expect(capabilities).To(Equal("deny"))
		})

		It("should NOT have access to sys/seal", func() {
			By("verifying operator cannot seal/unseal Vault")
			capabilities := getTokenCapabilities(operatorToken, "sys/seal")
			Expect(capabilities).To(Equal("deny"))
		})

		It("should NOT have access to sys/unseal", func() {
			By("verifying operator cannot unseal Vault")
			capabilities := getTokenCapabilities(operatorToken, "sys/unseal")
			Expect(capabilities).To(Equal("deny"))
		})

		It("should NOT have root capability", func() {
			By("verifying operator token is not root")
			// Check token info - root tokens have no policies
			cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
				"vault", "token", "lookup", operatorToken, "-format=json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			// Root tokens have empty policies array, operator tokens should have our policy
			Expect(output).To(ContainSubstring(operatorPolicyName))
		})
	})

	Describe("TC-OP05: Functional Verification", func() {
		It("should successfully create a test policy", func() {
			By("creating a test policy using operator token")
			testPolicyHCL := `path "secret/data/operator-test/*" { capabilities = ["read"] }`

			// Use the operator token to create a policy
			cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
				"sh", "-c",
				"VAULT_TOKEN="+operatorToken+" vault policy write operator-test-policy -")
			cmd.Stdin = strings.NewReader(testPolicyHCL)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Operator should be able to create policies")

			// Cleanup
			cmd = exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
				"sh", "-c",
				"VAULT_TOKEN="+operatorToken+" vault policy delete operator-test-policy")
			_, _ = utils.Run(cmd) // Ignore cleanup errors
		})

		It("should successfully read the policy it created", func() {
			By("reading the operator policy")
			cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
				"sh", "-c",
				"VAULT_TOKEN="+operatorToken+" vault policy read "+operatorPolicyName)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Operator should be able to read policies")
			Expect(output).To(ContainSubstring("sys/policies/acl"))
		})
	})
})

// getTokenCapabilities returns the capabilities of a token for a given path
func getTokenCapabilities(token, path string) string {
	cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
		"vault", "token", "capabilities", token, path)
	output, err := utils.Run(cmd)
	if err != nil {
		return "error"
	}
	return strings.TrimSpace(output)
}
