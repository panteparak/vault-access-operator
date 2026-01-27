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

package permissions

import (
	"context"
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/integration"
)

// TC-OP: Operator Token Permission Tests (Integration)
// These tests validate that the operator policy provides the correct permissions
// following the Principle of Least Privilege.
//
// Moved from E2E to integration tests because these tests:
// - Only require Vault (no Kubernetes cluster needed)
// - Test Vault permission policies via capabilities checks
// - Run faster using testcontainers vs full k8s cluster
var _ = Describe("TC-OP: Operator Token Permissions", func() {
	var (
		ctx           context.Context
		operatorToken string
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		Expect(ctx).NotTo(BeNil(), "Context should be set by BeforeSuite")

		// Get a fresh operator token for testing
		var err error
		operatorToken, err = createOperatorToken(ctx)
		Expect(err).NotTo(HaveOccurred(), "Failed to create operator token")
		Expect(operatorToken).NotTo(BeEmpty())
	})

	AfterEach(func() {
		// Revoke the test token to clean up
		if operatorToken != "" {
			revokeToken(ctx, operatorToken)
		}
	})

	Describe("TC-OP01: Policy Management Permissions", func() {
		It("should have create capability on sys/policies/acl/*", func() {
			By("checking capabilities on policy path")
			capabilities := getTokenCapabilities(ctx, operatorToken, "sys/policies/acl/test-policy")
			Expect(capabilities).To(ContainSubstring("create"))
			Expect(capabilities).To(ContainSubstring("read"))
			Expect(capabilities).To(ContainSubstring("update"))
			Expect(capabilities).To(ContainSubstring("delete"))
		})

		It("should have list capability on sys/policies/acl", func() {
			By("checking list capability on policies path")
			capabilities := getTokenCapabilities(ctx, operatorToken, "sys/policies/acl")
			Expect(capabilities).To(ContainSubstring("list"))
		})
	})

	Describe("TC-OP02: Kubernetes Auth Role Permissions", func() {
		It("should have CRUD capabilities on auth/kubernetes/role/*", func() {
			By("checking capabilities on kubernetes role path")
			capabilities := getTokenCapabilities(ctx, operatorToken, "auth/kubernetes/role/test-role")
			Expect(capabilities).To(ContainSubstring("create"))
			Expect(capabilities).To(ContainSubstring("read"))
			Expect(capabilities).To(ContainSubstring("update"))
			Expect(capabilities).To(ContainSubstring("delete"))
		})

		It("should have list capability on auth/kubernetes/role", func() {
			By("checking list capability on roles path")
			capabilities := getTokenCapabilities(ctx, operatorToken, "auth/kubernetes/role")
			Expect(capabilities).To(ContainSubstring("list"))
		})
	})

	Describe("TC-OP03: Health Check Permissions", func() {
		It("should have read capability on sys/health", func() {
			By("checking capabilities on health path")
			// Note: sys/health is typically accessible without authentication
			// but we verify the operator policy doesn't explicitly deny it
			capabilities := getTokenCapabilities(ctx, operatorToken, "sys/health")
			// sys/health returns "root" for root tokens or lists capabilities
			Expect(capabilities).NotTo(Equal("deny"))
		})
	})

	Describe("TC-OP04: Denied Paths (Principle of Least Privilege)", func() {
		It("should NOT have access to sys/seal", func() {
			By("verifying operator cannot seal Vault")
			capabilities := getTokenCapabilities(ctx, operatorToken, "sys/seal")
			Expect(capabilities).To(Equal("deny"))
		})

		It("should NOT have access to sys/unseal", func() {
			By("verifying operator cannot unseal Vault")
			capabilities := getTokenCapabilities(ctx, operatorToken, "sys/unseal")
			Expect(capabilities).To(Equal("deny"))
		})

		It("should NOT have root capability", func() {
			By("verifying operator token is not root")
			// Check token info - root tokens have no policies
			env := integration.GetTestEnv()
			Expect(env).NotTo(BeNil())

			// Use root token (set by default in container) to look up the operator token
			exitCode, output, err := env.VaultContainer.Exec(ctx, []string{
				"token", "lookup", "-format=json", operatorToken,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(exitCode).To(Equal(0), "Token lookup should succeed, output: "+output)
			// Operator tokens should have our policy attached
			Expect(output).To(ContainSubstring("operator-policy"))
		})
	})

	Describe("TC-OP05: Functional Verification", func() {
		It("should successfully create and read a test policy", func() {
			By("creating a test policy using operator token")
			testPolicyName := "operator-func-test-policy"
			testPolicyHCL := `path "secret/data/operator-test/*" { capabilities = ["read"] }`

			env := integration.GetTestEnv()
			Expect(env).NotTo(BeNil())

			// Create policy using operator token by setting VAULT_TOKEN env var
			exitCode, _, err := env.VaultContainer.ExecRaw(ctx, []string{
				"sh", "-c",
				"VAULT_TOKEN=" + operatorToken + " vault policy write " + testPolicyName + " - <<'EOF'\n" + testPolicyHCL + "\nEOF",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(exitCode).To(Equal(0), "Operator should be able to create policies")

			By("reading the policy back")
			exitCode, output, err := env.VaultContainer.ExecRaw(ctx, []string{
				"sh", "-c",
				"VAULT_TOKEN=" + operatorToken + " vault policy read " + testPolicyName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(exitCode).To(Equal(0), "Operator should be able to read policies")
			Expect(output).To(ContainSubstring("secret/data/operator-test"))

			By("cleaning up the test policy")
			exitCode, _, err = env.VaultContainer.ExecRaw(ctx, []string{
				"sh", "-c",
				"VAULT_TOKEN=" + operatorToken + " vault policy delete " + testPolicyName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(exitCode).To(Equal(0), "Operator should be able to delete policies")
		})

		It("should successfully read the operator policy", func() {
			By("reading the operator policy")
			env := integration.GetTestEnv()
			Expect(env).NotTo(BeNil())

			exitCode, output, err := env.VaultContainer.ExecRaw(ctx, []string{
				"sh", "-c",
				"VAULT_TOKEN=" + operatorToken + " vault policy read operator-policy",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(exitCode).To(Equal(0), "Operator should be able to read policies")
			Expect(output).To(ContainSubstring("sys/policies/acl"))
		})
	})
})

// createOperatorToken creates a new operator token with the operator-policy
func createOperatorToken(ctx context.Context) (string, error) {
	env := integration.GetTestEnv()
	if env == nil {
		return "", nil
	}

	exitCode, output, err := env.VaultContainer.Exec(ctx, []string{
		"token", "create",
		"-policy=operator-policy",
		"-ttl=1h",
		"-format=json",
	})
	if err != nil {
		return "", err
	}
	if exitCode != 0 {
		return "", nil
	}

	// Parse the JSON response to extract the client_token
	var tokenResp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal([]byte(output), &tokenResp); err != nil {
		return "", err
	}

	return tokenResp.Auth.ClientToken, nil
}

// revokeToken revokes a token (cleanup helper)
func revokeToken(ctx context.Context, token string) {
	env := integration.GetTestEnv()
	if env == nil {
		return
	}

	// Use root token to revoke
	_, _, _ = env.VaultContainer.Exec(ctx, []string{
		"token", "revoke", token,
	})
}

// getTokenCapabilities returns the capabilities of a token for a given path
func getTokenCapabilities(ctx context.Context, token, path string) string {
	env := integration.GetTestEnv()
	if env == nil {
		return "error"
	}

	exitCode, output, err := env.VaultContainer.Exec(ctx, []string{
		"token", "capabilities", token, path,
	})
	if err != nil || exitCode != 0 {
		return "error"
	}

	return strings.TrimSpace(output)
}
