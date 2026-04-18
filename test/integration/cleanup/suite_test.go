//go:build integration

/*
Package cleanup provides integration tests for the cleanup retry queue
(IMPROVEMENTS §1 + §2). Tests run against envtest for the ConfigMap
queue storage and a real Vault container for delete operations.
*/

package cleanup

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/integration"
)

func TestCleanupSuite(t *testing.T) {
	RegisterFailHandler(Fail)

	suiteConfig, reporterConfig := GinkgoConfiguration()
	reporterConfig.Verbose = true

	RunSpecs(t, "Cleanup Queue Integration Test Suite", suiteConfig, reporterConfig)
}

var _ = BeforeSuite(func() {
	By("Checking Docker availability")
	if !integration.IsDockerAvailable() {
		Skip("Docker daemon not available - skipping integration tests")
	}

	By("Setting up cleanup test context")
	ctx, cancel := context.WithCancel(context.Background())
	integration.SetContext(ctx, cancel)

	By("Creating cleanup test environment")
	env := integration.NewTestEnvironment(
		integration.WithVaultOptions(
			integration.WithOperatorPolicy(),
			integration.WithLogLevel("info"),
		),
		integration.WithTestEnvTimeout(90*time.Second),
	)
	integration.SetTestEnv(env)

	By("Starting cleanup test environment")
	Expect(env.Start()).To(Succeed())

	By("Waiting for Vault to be healthy")
	Expect(env.WaitForVaultHealthy(30 * time.Second)).To(Succeed())

	DeferCleanup(func() {
		By("Stopping cleanup test environment")
		testEnv := integration.GetTestEnv()
		if testEnv != nil {
			Expect(testEnv.Stop()).To(Succeed())
		}
		cancel()
	})
})
