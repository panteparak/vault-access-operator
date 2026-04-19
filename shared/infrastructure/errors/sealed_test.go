/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package errors

import (
	"errors"
	"strings"
	"testing"
)

// TestVaultSealedError_MessageVariesByInitialized pins IMPROVEMENTS
// Missing Features §C: the error message should distinguish the
// uninitialized case (operator init needed) from the sealed case
// (operator unseal needed) so dashboards / logs surface the right
// remediation instructions.
func TestVaultSealedError_MessageVariesByInitialized(t *testing.T) {
	cases := []struct {
		name        string
		initialized bool
		wantSubstr  string
	}{
		{
			name:        "sealed (initialized=true)",
			initialized: true,
			wantSubstr:  "vault operator unseal",
		},
		{
			name:        "uninitialized (initialized=false)",
			initialized: false,
			wantSubstr:  "vault operator init",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := NewVaultSealedError("conn", "https://vault:8200", tc.initialized)
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error message %q should contain %q", err.Error(), tc.wantSubstr)
			}
		})
	}
}

// TestIsVaultSealedError_PositiveAndNegative covers the type-assertion
// helper that the syncerror handler and base.StatusManager use to drive
// distinct condition reasons + faster requeue.
func TestIsVaultSealedError_PositiveAndNegative(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("something"), false},
		{"VaultSealedError direct", NewVaultSealedError("c", "addr", true), true},
		{
			name: "wrapped VaultSealedError",
			// Simulates a handler wrapping the typed error in fmt.Errorf
			// — still recognized via errors.As.
			err:  &wrappedErr{inner: NewVaultSealedError("c", "addr", true)},
			want: true,
		},
		{"unrelated typed error", NewConflictError("policy", "p1", "exists"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsVaultSealedError(tc.err); got != tc.want {
				t.Errorf("IsVaultSealedError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// wrappedErr emulates a fmt.Errorf("%w", inner) wrapper without depending
// on fmt to keep the test focused on the unwrap chain semantics.
type wrappedErr struct{ inner error }

func (w *wrappedErr) Error() string { return "wrapped: " + w.inner.Error() }
func (w *wrappedErr) Unwrap() error { return w.inner }
