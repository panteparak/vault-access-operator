/*
Package integration provides testcontainers-based integration tests for the vault-access-operator.

This file exports test helpers for use by subpackages (policy, security, etc.).
*/
package integration

import (
	"context"
	"os/exec"
	"sync"

	"github.com/panteparak/vault-access-operator/test/integration/profiling"
)

var (
	// sharedTestEnv is the shared test environment
	sharedTestEnv *TestEnvironment
	// sharedProfiler is the shared profiler
	sharedProfiler *profiling.Profiler
	// sharedCtx is the shared context
	sharedCtx context.Context
	// sharedCancel is the shared cancel function
	sharedCancel context.CancelFunc
	// sharedMu protects shared state
	sharedMu sync.RWMutex
)

// SetTestEnv sets the shared test environment (called from suite_test.go)
func SetTestEnv(env *TestEnvironment) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	sharedTestEnv = env
}

// GetTestEnv returns the shared test environment
func GetTestEnv() *TestEnvironment {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return sharedTestEnv
}

// SetContext sets the shared context (called from suite_test.go)
func SetContext(ctx context.Context, cancel context.CancelFunc) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	sharedCtx = ctx
	sharedCancel = cancel
}

// GetContext returns the shared context
func GetContext() context.Context {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return sharedCtx
}

// GetCancel returns the shared cancel function
func GetCancel() context.CancelFunc {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return sharedCancel
}

// SetProfiler sets the shared profiler (called from suite_test.go)
func SetProfiler(p *profiling.Profiler) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	sharedProfiler = p
}

// GetProfiler returns the shared profiler (may be nil if disabled)
func GetProfiler() *profiling.Profiler {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return sharedProfiler
}

// CreateTestNamespace creates a unique namespace name for a test
func CreateTestNamespace(baseName string) string {
	return baseName + "-" + RandomString(8)
}

// RandomString generates a random string of the given length
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		// Use a simple deterministic approach for test reproducibility
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}

// IsDockerAvailable checks if Docker daemon is running and accessible.
// Returns true if Docker is available, false otherwise.
func IsDockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	err := cmd.Run()
	return err == nil
}
