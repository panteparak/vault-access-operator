//go:build integration

/*
Package kvsecret provides integration tests for the VaultKVSecret seeding
client surface (pkg/vault) against a real Vault container.

This file bootstraps the Ginkgo test suite. The tests only need Vault (no
envtest/K8s), so the environment is started with WithVaultOnly.
*/

package kvsecret

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/integration"
)

func TestKVSecretSuite(t *testing.T) {
	RegisterFailHandler(Fail)

	suiteConfig, reporterConfig := GinkgoConfiguration()
	reporterConfig.Verbose = true

	RunSpecs(t, "KVSecret Integration Test Suite", suiteConfig, reporterConfig)
}

var _ = BeforeSuite(func() {
	By("Checking Docker availability")
	if !integration.IsDockerAvailable() {
		Skip("Docker daemon not available - skipping integration tests. Start Docker to run integration tests.")
	}

	By("Setting up kvsecret test context")
	ctx, cancel := context.WithCancel(context.Background())
	integration.SetContext(ctx, cancel)

	By("Creating kvsecret test environment (Vault only)")
	env := integration.NewTestEnvironment(
		integration.WithVaultOnly(),
		integration.WithVaultOptions(
			integration.WithKV2SecretEngine("secret"),
			integration.WithLogLevel("info"),
		),
		integration.WithTestEnvTimeout(90*time.Second),
	)
	integration.SetTestEnv(env)

	By("Starting kvsecret test environment")
	Expect(env.Start()).To(Succeed(), "Failed to start test environment")

	By("Waiting for Vault to be healthy")
	Expect(env.WaitForVaultHealthy(30 * time.Second)).To(Succeed())

	DeferCleanup(func() {
		By("Stopping kvsecret test environment")
		testEnv := integration.GetTestEnv()
		if testEnv != nil {
			Expect(testEnv.Stop()).To(Succeed())
		}
		cancel()
	})
})
