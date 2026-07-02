//go:build integration

/*
Package markers provides integration tests for managed-marker tracking.

Tests use the naming convention: INT-MM{NN}_{Description}. They exercise the
flag-gated marker behavior end to end against a real Vault (Testcontainers),
mirroring the orphan-detection suite. Managed markers are enabled for the whole
suite; the flag-OFF case (INT-MM04) toggles it within the spec.
*/

package markers

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/shared/markers"
	"github.com/panteparak/vault-access-operator/test/integration"
)

func TestMarkersSuite(t *testing.T) {
	RegisterFailHandler(Fail)

	suiteConfig, reporterConfig := GinkgoConfiguration()
	reporterConfig.Verbose = true

	RunSpecs(t, "Managed Markers Integration Test Suite", suiteConfig, reporterConfig)
}

var _ = BeforeSuite(func() {
	By("Checking Docker availability")
	if !integration.IsDockerAvailable() {
		Skip("Docker daemon not available - skipping integration tests. Start Docker to run integration tests.")
	}

	By("Enabling managed markers for the suite")
	markers.SetEnabled(true)

	By("Setting up markers test context")
	ctx, cancel := context.WithCancel(context.Background())
	integration.SetContext(ctx, cancel)

	By("Creating markers test environment")
	env := integration.NewTestEnvironment(
		integration.WithVaultOptions(
			integration.WithOperatorPolicy(),
			integration.WithKV2SecretEngine("secret"),
			integration.WithLogLevel("info"),
		),
		integration.WithTestEnvTimeout(90*time.Second),
	)
	integration.SetTestEnv(env)

	By("Starting markers test environment")
	Expect(env.Start()).To(Succeed(), "Failed to start test environment")

	By("Waiting for Vault to be healthy")
	Expect(env.WaitForVaultHealthy(30 * time.Second)).To(Succeed())

	DeferCleanup(func() {
		By("Stopping markers test environment")
		testEnv := integration.GetTestEnv()
		if testEnv != nil {
			Expect(testEnv.Stop()).To(Succeed())
		}
		markers.SetEnabled(false)
		cancel()
	})
})
