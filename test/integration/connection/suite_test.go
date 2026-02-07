//go:build integration

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

package connection

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/integration"
)

var (
	testEnv *integration.TestEnvironment
	ctx     context.Context
	cancel  context.CancelFunc
)

func TestConnectionIntegration(t *testing.T) {
	RegisterFailHandler(Fail)

	suiteConfig, reporterConfig := GinkgoConfiguration()
	reporterConfig.Verbose = true

	RunSpecs(t, "Connection Integration Tests", suiteConfig, reporterConfig)
}

var _ = BeforeSuite(func() {
	By("Checking Docker availability")
	if !integration.IsDockerAvailable() {
		Skip("Docker daemon not available - skipping integration tests")
	}

	By("Setting up test context")
	ctx, cancel = context.WithCancel(context.Background())

	By("Creating test environment with JWT auth support")
	testEnv = integration.NewTestEnvironment(
		integration.WithVaultOptions(
			integration.WithOperatorPolicy(),
			integration.WithKV2SecretEngine("secret"),
			integration.WithLogLevel("info"),
			// Enable JWT auth method
			integration.WithInitCommand("auth enable jwt || true"),
		),
		integration.WithTestEnvTimeout(90*time.Second),
	)

	By("Starting test environment")
	Expect(testEnv.Start()).To(Succeed(), "Failed to start test environment")

	By("Waiting for Vault to be healthy")
	Expect(testEnv.WaitForVaultHealthy(30 * time.Second)).To(Succeed())

	DeferCleanup(func() {
		By("Stopping test environment")
		if testEnv != nil {
			Expect(testEnv.Stop()).To(Succeed())
		}
		cancel()
	})
})
