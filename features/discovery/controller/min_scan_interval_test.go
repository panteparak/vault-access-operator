/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/record"

	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// TestNewReconciler_HonorsConfigMinScanInterval pins IMPROVEMENTS §23: tests
// can now override the floor without mutating the package-level
// MinScanInterval global. Previously, table-driven tests that wanted a
// short scan interval had to assign-and-restore the global, which was
// flaky under -race when multiple test goroutines touched it.
func TestNewReconciler_HonorsConfigMinScanInterval(t *testing.T) {
	cases := []struct {
		name          string
		configValue   time.Duration
		expectedFloor time.Duration
	}{
		{
			name:          "explicit 1s wins over package default",
			configValue:   time.Second,
			expectedFloor: time.Second,
		},
		{
			name:          "zero falls back to package MinScanInterval",
			configValue:   0,
			expectedFloor: MinScanInterval,
		},
		{
			name:          "negative also falls back",
			configValue:   -1 * time.Second,
			expectedFloor: MinScanInterval,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReconciler(ReconcilerConfig{
				ClientCache:     vault.NewClientCache(),
				Log:             logr.Discard(),
				Recorder:        record.NewFakeRecorder(1),
				MinScanInterval: tc.configValue,
			})
			if r.minScanInterval != tc.expectedFloor {
				t.Errorf("minScanInterval = %v, want %v", r.minScanInterval, tc.expectedFloor)
			}
		})
	}
}

// TestDefaultMinScanInterval_PinnedAtFiveMinutes is a guard test against
// accidental constant-tweaking. Five minutes is the lowest interval
// considered safe for production discovery (Vault audit log volume + K8s
// API write rate). Lowering it requires explicit review.
func TestDefaultMinScanInterval_PinnedAtFiveMinutes(t *testing.T) {
	if DefaultMinScanInterval != 5*time.Minute {
		t.Errorf("DefaultMinScanInterval = %v, want 5m — "+
			"changing this affects every operator's discovery floor",
			DefaultMinScanInterval)
	}
}
