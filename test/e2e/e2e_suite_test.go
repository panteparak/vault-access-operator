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
	"os"
	"os/exec"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// Shared constants for all E2E tests
const (
	// vaultNamespace is where Vault dev server is deployed
	vaultNamespace = "vault"

	// testNamespace is where namespaced test resources are created
	testNamespace = "e2e-test"

	// sharedVaultConnectionName is the VaultConnection used by most tests
	sharedVaultConnectionName = "e2e-vault"

	// sharedVaultTokenSecretName is the secret containing the Vault token
	sharedVaultTokenSecretName = "vault-token"

	// operatorPolicyName is the Vault policy for the operator
	operatorPolicyName = "vault-access-operator"
)

// operatorPolicyHCL defines the minimum permissions required for the operator.
// This follows the Principle of Least Privilege - only granting what's needed.
const operatorPolicyHCL = `
# Policy management - operator needs to create/update/delete policies
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/policies/acl" {
  capabilities = ["list"]
}

# Kubernetes auth role management
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/kubernetes/role" {
  capabilities = ["list"]
}

# Kubernetes auth configuration (for initial setup)
path "auth/kubernetes/config" {
  capabilities = ["create", "read", "update", "delete"]
}

# Auth method management (enable/disable kubernetes auth)
path "sys/auth" {
  capabilities = ["read"]
}
path "sys/auth/*" {
  capabilities = ["sudo", "create", "read", "update", "delete", "list"]
}

# Health checks
path "sys/health" {
  capabilities = ["read"]
}
`

var (
	// projectImage is the name of the image which will be build and loaded
	// with the code source changes to be tested.
	// Can be overridden via E2E_IMAGE environment variable.
	projectImage = "example.com/vault-access-operator:v0.0.1"

	// skipBuild skips building the image (useful when image is pre-built in CI).
	// Set E2E_SKIP_BUILD=true to skip.
	skipBuild = os.Getenv("E2E_SKIP_BUILD") == "true"

	// skipImageLoad skips loading image to cluster (useful when image is pre-loaded by CI).
	// Set E2E_SKIP_IMAGE_LOAD=true to skip.
	skipImageLoad = os.Getenv("E2E_SKIP_IMAGE_LOAD") == "true"
)

func init() {
	// Allow overriding image via environment variable
	if img := os.Getenv("E2E_IMAGE"); img != "" {
		projectImage = img
	}
}

// TestE2E runs the end-to-end (e2e) test suite for the project. These tests execute in an isolated,
// temporary environment to validate project changes with the purpose to be used in CI jobs.
// The default setup uses k3d and builds/loads the Manager Docker image locally.
// In CI, E2E_SKIP_BUILD and E2E_SKIP_IMAGE_LOAD are set to use pre-built images.
// Note: Webhooks use self-signed TLS certificates instead of cert-manager.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting vault-access-operator integration test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	By(fmt.Sprintf("using image: %s (skipBuild=%v, skipImageLoad=%v)", projectImage, skipBuild, skipImageLoad))

	if !skipBuild {
		By("building the manager(Operator) image")
		cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
		_, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager(Operator) image")
	} else {
		By("skipping image build (E2E_SKIP_BUILD=true)")
	}

	if !skipImageLoad {
		By("loading the manager(Operator) image into cluster")
		err := utils.LoadImageToCluster(projectImage)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager(Operator) image into cluster")
	} else {
		By("skipping image load (E2E_SKIP_IMAGE_LOAD=true)")
	}

	// Set default timeouts for all tests
	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(2 * time.Second)

	// Setup shared test infrastructure
	setupSharedTestInfrastructure()
})

var _ = AfterSuite(func() {
	// Cleanup shared test infrastructure
	cleanupSharedTestInfrastructure()
})

// setupSharedTestInfrastructure creates resources shared across all test files
func setupSharedTestInfrastructure() {
	By("creating test namespace")
	cmd := exec.Command("kubectl", "create", "ns", testNamespace)
	_, _ = utils.Run(cmd) // Ignore error if already exists

	// Check if Vault is already deployed (CI deploys it before tests)
	By("checking if Vault is deployed")
	cmd = exec.Command("kubectl", "get", "ns", vaultNamespace)
	_, err := utils.Run(cmd)
	if err != nil {
		By("deploying Vault dev server (not found, deploying for local development)")
		cmd = exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/vault.yaml")
		_, err = utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to deploy Vault")
	}

	By("waiting for Vault to be ready")
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "pods", "-n", vaultNamespace,
			"-l", "app=vault", "-o", "jsonpath={.items[0].status.phase}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("Running"))
	}, 2*time.Minute, 5*time.Second).Should(Succeed())

	// Wait for Vault API to be accessible (pod Running doesn't mean API is ready)
	By("waiting for Vault API to be accessible")
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
			"vault", "status", "-format=json")
		_, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
	}, 1*time.Minute, 5*time.Second).Should(Succeed())

	// Create operator policy with least-privilege permissions
	// This demonstrates proper Vault security practices - never use root token in production
	By("creating operator policy with least-privilege permissions")
	err = createOperatorPolicy()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create operator policy")

	// Create operator token (non-root) with the operator policy
	By("creating operator token (non-root)")
	operatorToken, err := getOperatorToken()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create operator token")
	ExpectWithOffset(1, operatorToken).NotTo(BeEmpty(), "Operator token should not be empty")

	By("creating Vault token secret for shared VaultConnection (using operator token, not root)")
	cmd = exec.Command("kubectl", "create", "secret", "generic", sharedVaultTokenSecretName,
		"-n", testNamespace,
		"--from-literal=token="+operatorToken)
	_, _ = utils.Run(cmd) // Ignore error if already exists

	By("creating shared VaultConnection for tests")
	connectionYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: %s
spec:
  address: http://vault.%s.svc.cluster.local:8200
  auth:
    token:
      secretRef:
        name: %s
        namespace: %s
        key: token
  healthCheckInterval: "10s"
`, sharedVaultConnectionName, vaultNamespace, sharedVaultTokenSecretName, testNamespace)

	cmd = exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = stringReader(connectionYAML)
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create shared VaultConnection")

	By("waiting for shared VaultConnection to become Active")
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "vaultconnection", sharedVaultConnectionName,
			"-o", "jsonpath={.status.phase}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("Active"))
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}

// cleanupSharedTestInfrastructure removes shared test resources
func cleanupSharedTestInfrastructure() {
	By("cleaning up shared VaultConnection")
	cmd := exec.Command("kubectl", "delete", "vaultconnection", sharedVaultConnectionName,
		"--ignore-not-found", "--timeout=60s")
	_, _ = utils.Run(cmd)

	// Wait for finalizers to complete
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "vaultconnection", sharedVaultConnectionName)
		_, err := utils.Run(cmd)
		g.Expect(err).To(HaveOccurred()) // Should fail when deleted
	}, 60*time.Second, 2*time.Second).Should(Succeed())

	By("cleaning up test namespace")
	cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found", "--timeout=60s")
	_, _ = utils.Run(cmd)
}

// stringReader creates an io.Reader from a string for kubectl stdin
func stringReader(s string) *stringReaderImpl {
	return &stringReaderImpl{data: []byte(s)}
}

type stringReaderImpl struct {
	data []byte
	pos  int
}

func (r *stringReaderImpl) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// createOperatorPolicy creates the operator policy in Vault using kubectl exec.
// This policy provides the minimum permissions required for the operator to function.
func createOperatorPolicy() error {
	// Write the policy to Vault using heredoc via kubectl exec
	// The policy is written to stdin of the vault policy write command
	// Note: -i flag is required to pass stdin to the pod
	cmd := exec.Command("kubectl", "exec", "-i", "-n", vaultNamespace, "vault-0", "--",
		"vault", "policy", "write", operatorPolicyName, "-")
	cmd.Stdin = stringReader(operatorPolicyHCL)
	_, err := utils.Run(cmd)
	return err
}

// getOperatorToken creates a new operator token with the operator policy.
// Returns the token string or an error if token creation fails.
func getOperatorToken() (string, error) {
	cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
		"vault", "token", "create",
		"-policy="+operatorPolicyName,
		"-ttl=24h",
		"-format=json")
	output, err := utils.Run(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to create operator token: %w", err)
	}

	// Parse the JSON response to extract the client_token
	var tokenResp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal([]byte(output), &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Auth.ClientToken == "" {
		return "", fmt.Errorf("empty token in response")
	}

	return tokenResp.Auth.ClientToken, nil
}
