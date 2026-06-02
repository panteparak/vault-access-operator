/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Shared constants and env-driven configuration for the e2e suite. Lives in
// its own file so the suite spec, infrastructure setup, and individual tests
// have a single, scannable source of truth for "what name / which mount /
// what timeout". The Ginkgo lifecycle code (BeforeSuite etc.) is in
// e2e_suite_test.go; shared infra setup is in e2e_shared_infra_test.go.

package e2e

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test resource names
// ─────────────────────────────────────────────────────────────────────────────

const (
	// vaultNamespace is where Vault dev server is deployed.
	vaultNamespace = "vault"

	// testNamespace is where namespaced test resources are created.
	testNamespace = "e2e-test"

	// sharedVaultConnectionName is the VaultConnection used by most tests.
	sharedVaultConnectionName = "e2e-vault"

	// sharedVaultTokenSecretName is the secret containing the Vault token.
	sharedVaultTokenSecretName = "vault-token"

	// operatorPolicyName is the Vault policy attached to the operator's token.
	operatorPolicyName = "vault-access-operator"
)

// ─────────────────────────────────────────────────────────────────────────────
// Dex OIDC provider — for OIDC / JWT-auth tests that need an external issuer.
// Dex runs as a Docker container alongside k3s (docker-compose) and is
// reachable:
//   - From host/tests:    http://localhost:5556 (port mapping)
//   - From k8s pods:      http://dex.default.svc.cluster.local:5556 (Service + Endpoints bridge)
//   - From Vault container: http://dex.default.svc.cluster.local:5556 (docker network alias)
// ─────────────────────────────────────────────────────────────────────────────

const (
	dexTokenEndpoint      = "http://localhost:5556/token"
	dexIssuer             = "http://dex.default.svc.cluster.local:5556"
	dexDiscoveryURL       = "http://localhost:5556/.well-known/openid-configuration"
	dexClientID           = "vault"
	dexClientSecret       = "vault-secret"
	dexCustomClientID     = "custom-audience"
	dexCustomClientSecret = "custom-audience-secret"
	dexTestEmail          = "admin@example.com"
	dexTestPassword       = "password" //nolint:gosec // Test-only static password for Dex
)

// ─────────────────────────────────────────────────────────────────────────────
// Vault address from k3s — overridable for cross-network setups.
// ─────────────────────────────────────────────────────────────────────────────

// vaultK8sAddr is the in-cluster Vault address used by VaultConnection
// resources. The operator runs inside k3s and talks to Vault through this
// address. Read from VAULT_K8S_ADDR; defaults to the bridged Service URL.
var vaultK8sAddr string

func init() {
	vaultK8sAddr = os.Getenv("VAULT_K8S_ADDR")
	if vaultK8sAddr == "" {
		vaultK8sAddr = fmt.Sprintf("http://vault.%s.svc.cluster.local:8200", vaultNamespace)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Env-driven settings — read once at package init so individual tests have
// stable values across the suite.
// ─────────────────────────────────────────────────────────────────────────────

// envTrue is the canonical string for boolean environment variables.
const envTrue = "true"

var (
	// projectImage is the operator image built and loaded into the cluster.
	// Override with E2E_OPERATOR_IMAGE.
	projectImage = "vault-access-operator:local"

	// skipBuild skips building the image (used when CI provides pre-built one).
	// Set E2E_SKIP_BUILD=true to skip.
	skipBuild = os.Getenv("E2E_SKIP_BUILD") == envTrue

	// skipImageLoad skips loading the image (used when CI pre-loads it).
	// Set E2E_SKIP_IMAGE_LOAD=true to skip.
	skipImageLoad = os.Getenv("E2E_SKIP_IMAGE_LOAD") == envTrue

	// isCI detects a CI environment (GitHub Actions, GitLab CI, etc.).
	isCI = os.Getenv("CI") == envTrue || os.Getenv("GITHUB_ACTIONS") == envTrue

	// defaultTimeout is the default Eventually() budget. CI gets a longer
	// budget because shared runners are slower than local Docker.
	defaultTimeout = func() time.Duration {
		if isCI {
			return 5 * time.Minute
		}
		return 3 * time.Minute
	}()

	// defaultPollingInterval is the default Eventually() polling rate.
	defaultPollingInterval = 2 * time.Second

	// Fuzz test configuration (overridable via environment).
	fuzzIterations = envIntOrDefault("FUZZ_ITERATIONS", 100)
	fuzzBatchSize  = envIntOrDefault("FUZZ_BATCH_SIZE", 25)
)

// envIntOrDefault reads an integer from the named env var, falling back to
// def for missing, malformed, or non-positive values.
func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func init() {
	if img := os.Getenv("E2E_OPERATOR_IMAGE"); img != "" {
		projectImage = img
	}
}
