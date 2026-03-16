/*
Package integration provides testcontainers-based integration tests for the vault-access-operator.

This file exports test helpers for use by subpackages (policy, security, etc.).
*/
package integration

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"sync/atomic"
)

var (
	// sharedTestEnv is the shared test environment
	sharedTestEnv *TestEnvironment
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

// CreateTestNamespace creates a unique namespace name for a test
func CreateTestNamespace(baseName string) string {
	return baseName + "-" + RandomString(8)
}

// uniqueCounter provides monotonically increasing IDs for unique test names
var uniqueCounter atomic.Int64

// RandomString generates a unique string of the given length using an atomic counter.
func RandomString(length int) string {
	id := uniqueCounter.Add(1)
	s := fmt.Sprintf("%x", id)
	if len(s) >= length {
		return s[:length]
	}
	// Pad with leading zeros
	for len(s) < length {
		s = "0" + s
	}
	return s
}

// IsDockerAvailable checks if Docker daemon is running and accessible.
// Returns true if Docker is available, false otherwise.
func IsDockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	err := cmd.Run()
	return err == nil
}
