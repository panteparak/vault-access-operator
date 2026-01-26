/*
Package integration provides testcontainers-based integration tests for the vault-access-operator.

This file sets up the main Ginkgo test suite with shared infrastructure including:
- Kubernetes API server via envtest
- Vault container via testcontainers-go
- Profiling infrastructure for performance metrics
*/
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/integration/profiling"
)

var (
	// Enable profiling via environment variable
	profilingEnabled = os.Getenv("INTEGRATION_PROFILING") == "true"
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)

	suiteConfig, reporterConfig := GinkgoConfiguration()

	// Enable verbose output for integration tests
	reporterConfig.Verbose = true

	RunSpecs(t, "Integration Test Suite", suiteConfig, reporterConfig)
}

var _ = BeforeSuite(func() {
	By("Checking Docker availability")
	if !IsDockerAvailable() {
		Skip("Docker daemon not available - skipping integration tests. Start Docker to run integration tests.")
	}

	By("Setting up test context")
	ctx, cancel := context.WithCancel(context.Background())
	SetContext(ctx, cancel)

	By("Starting profiler (if enabled)")
	if profilingEnabled {
		p := profiling.NewProfiler(profiling.ProfilerConfig{
			OutputDir:    "reports/profiling",
			EnableCPU:    true,
			EnableMemory: true,
			EnableGC:     true,
			SampleRate:   100,
			GenerateSVG:  true,
			GenerateHTML: true,
		})
		Expect(p.Start()).To(Succeed())
		SetProfiler(p)
	}

	By("Creating test environment")
	env := NewTestEnvironment(
		WithVaultOptions(
			WithOperatorPolicy(),
			WithKV2SecretEngine("secret"),
			WithLogLevel("info"),
		),
		WithTestEnvTimeout(90*time.Second),
	)
	SetTestEnv(env)

	By("Starting test environment")
	Expect(env.Start()).To(Succeed(), "Failed to start test environment")

	By("Waiting for Vault to be healthy")
	Expect(env.WaitForVaultHealthy(30 * time.Second)).To(Succeed())

	DeferCleanup(func() {
		By("Stopping test environment")
		testEnv := GetTestEnv()
		if testEnv != nil {
			Expect(testEnv.Stop()).To(Succeed())
		}

		By("Generating profiling report (if enabled)")
		profiler := GetProfiler()
		if profiler != nil {
			Expect(profiler.Stop()).To(Succeed())
			Expect(profiler.GenerateReport()).To(Succeed())
		}

		cancel()
	})
})

// BeforeEach hook for per-test setup
var _ = BeforeEach(func() {
	// Start per-test profiling if enabled
	profiler := GetProfiler()
	if profiler != nil {
		profiler.BeginTest(CurrentSpecReport().FullText())
	}
})

// AfterEach hook for per-test teardown
var _ = AfterEach(func() {
	// End per-test profiling if enabled
	profiler := GetProfiler()
	if profiler != nil {
		report := CurrentSpecReport()
		profiler.EndTest(report.FullText(), report.RunTime)
	}
})
