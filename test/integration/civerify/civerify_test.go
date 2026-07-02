//go:build integration

// Package civerify_test exists only to verify that the CI Integration Tests
// job compiles integration-tagged tests and goes red on failure.
// DELETE BEFORE MERGE.
package civerify_test

import "testing"

func TestCIVerificationIntentionalFailure(t *testing.T) {
	t.Fatal("intentional failure: verifying the CI integration job goes red")
}
