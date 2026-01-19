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
	"fmt"
	"io"
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
)

var (
	// projectImage is the name of the image which will be build and loaded
	// with the code source changes to be tested.
	projectImage = "example.com/vault-access-operator:v0.0.1"
)

// TestE2E runs the end-to-end (e2e) test suite for the project. These tests execute in an isolated,
// temporary environment to validate project changes with the purposed to be used in CI jobs.
// The default setup requires Kind and builds/loads the Manager Docker image locally.
// Note: Webhooks use self-signed TLS certificates instead of cert-manager.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting vault-access-operator integration test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	By("building the manager(Operator) image")
	cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager(Operator) image")

	// TODO(user): If you want to change the e2e test vendor from Kind, ensure the image is
	// built and available before running the tests. Also, remove the following block.
	By("loading the manager(Operator) image on Kind")
	err = utils.LoadImageToKindClusterWithName(projectImage)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager(Operator) image into Kind")

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

	By("creating Vault token secret for shared VaultConnection")
	cmd = exec.Command("kubectl", "create", "secret", "generic", sharedVaultTokenSecretName,
		"-n", testNamespace,
		"--from-literal=token=root")
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
