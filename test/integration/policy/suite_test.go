/*
Package policy provides integration tests for VaultPolicy and VaultClusterPolicy resources.

This file bootstraps the Ginkgo test suite for policy tests.
*/
package policy

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/integration"
)

func TestPolicySuite(t *testing.T) {
	RegisterFailHandler(Fail)

	suiteConfig, reporterConfig := GinkgoConfiguration()
	reporterConfig.Verbose = true

	RunSpecs(t, "Policy Integration Test Suite", suiteConfig, reporterConfig)
}

var _ = BeforeSuite(func() {
	By("Checking Docker availability")
	if !integration.IsDockerAvailable() {
		Skip("Docker daemon not available - skipping integration tests. Start Docker to run integration tests.")
	}

	By("Setting up policy test context")
	ctx, cancel := context.WithCancel(context.Background())
	integration.SetContext(ctx, cancel)

	By("Creating policy test environment")
	env := integration.NewTestEnvironment(
		integration.WithVaultOptions(
			integration.WithOperatorPolicy(),
			integration.WithKV2SecretEngine("secret"),
			integration.WithLogLevel("info"),
		),
		integration.WithTestEnvTimeout(90*time.Second),
	)
	integration.SetTestEnv(env)

	By("Starting policy test environment")
	Expect(env.Start()).To(Succeed(), "Failed to start test environment")

	By("Waiting for Vault to be healthy")
	Expect(env.WaitForVaultHealthy(30 * time.Second)).To(Succeed())

	DeferCleanup(func() {
		By("Stopping policy test environment")
		testEnv := integration.GetTestEnv()
		if testEnv != nil {
			Expect(testEnv.Stop()).To(Succeed())
		}
		cancel()
	})
})
