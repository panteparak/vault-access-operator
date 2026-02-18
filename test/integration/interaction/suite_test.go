//go:build integration

/*
Package interaction provides integration tests for multi-resource interactions.

This file bootstraps the Ginkgo test suite for interaction tests.
*/

package interaction

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/integration"
)

func TestInteractionSuite(t *testing.T) {
	RegisterFailHandler(Fail)

	suiteConfig, reporterConfig := GinkgoConfiguration()
	reporterConfig.Verbose = true

	RunSpecs(t, "Multi-Resource Interaction Integration Test Suite", suiteConfig, reporterConfig)
}

var _ = BeforeSuite(func() {
	By("Checking Docker availability")
	if !integration.IsDockerAvailable() {
		Skip("Docker daemon not available - skipping integration tests. Start Docker to run integration tests.")
	}

	By("Setting up interaction test context")
	ctx, cancel := context.WithCancel(context.Background())
	integration.SetContext(ctx, cancel)

	By("Creating interaction test environment")
	env := integration.NewTestEnvironment(
		integration.WithVaultOptions(
			integration.WithOperatorPolicy(),
			integration.WithKV2SecretEngine("secret"),
			integration.WithLogLevel("info"),
		),
		integration.WithTestEnvTimeout(90*time.Second),
	)
	integration.SetTestEnv(env)

	By("Starting interaction test environment")
	Expect(env.Start()).To(Succeed(), "Failed to start test environment")

	By("Waiting for Vault to be healthy")
	Expect(env.WaitForVaultHealthy(30 * time.Second)).To(Succeed())

	DeferCleanup(func() {
		By("Stopping interaction test environment")
		testEnv := integration.GetTestEnv()
		if testEnv != nil {
			Expect(testEnv.Stop()).To(Succeed())
		}
		cancel()
	})
})
