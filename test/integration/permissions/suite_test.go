//go:build integration

/*
Package permissions provides integration tests for operator token permissions.

These tests validate that the operator token follows the Principle of Least Privilege,
having only the minimum permissions required to manage policies and Kubernetes auth roles.
*/

package permissions

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/integration"
)

func TestPermissionsSuite(t *testing.T) {
	RegisterFailHandler(Fail)

	suiteConfig, reporterConfig := GinkgoConfiguration()
	reporterConfig.Verbose = true

	RunSpecs(t, "Permissions Integration Test Suite", suiteConfig, reporterConfig)
}

var _ = BeforeSuite(func() {
	By("Checking Docker availability")
	if !integration.IsDockerAvailable() {
		Skip("Docker daemon not available - skipping integration tests. Start Docker to run integration tests.")
	}

	By("Setting up permissions test context")
	ctx, cancel := context.WithCancel(context.Background())
	integration.SetContext(ctx, cancel)

	By("Creating permissions test environment")
	// Use WithVaultOnly since permission tests don't need Kubernetes
	// Use WithOperatorPolicy to pre-configure the operator policy in Vault
	env := integration.NewTestEnvironment(
		integration.WithVaultOnly(), // Skip envtest - only need Vault
		integration.WithVaultOptions(
			integration.WithOperatorPolicy(),
			integration.WithLogLevel("info"),
		),
		integration.WithTestEnvTimeout(90*time.Second),
	)
	integration.SetTestEnv(env)

	By("Starting permissions test environment")
	Expect(env.Start()).To(Succeed(), "Failed to start test environment")

	By("Waiting for Vault to be healthy")
	Expect(env.WaitForVaultHealthy(30 * time.Second)).To(Succeed())

	DeferCleanup(func() {
		By("Stopping permissions test environment")
		testEnv := integration.GetTestEnv()
		if testEnv != nil {
			Expect(testEnv.Stop()).To(Succeed())
		}
		cancel()
	})
})
