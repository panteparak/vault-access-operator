/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"errors"
	"fmt"
	"testing"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// TestWasSealedReason pins IMPROVEMENTS Missing Features §C: the
// helper that detects "the connection was sealed/uninitialized in the
// previous reconcile". Used by the connection handler to decide
// whether to emit the VaultUnsealed K8s event on the recovery moment.
func TestWasSealedReason(t *testing.T) {
	cases := []struct {
		name  string
		conds []vaultv1alpha1.Condition
		want  bool
	}{
		{
			name: "Ready condition with VaultSealed reason",
			conds: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeReady, Reason: vaultv1alpha1.ReasonVaultSealed},
			},
			want: true,
		},
		{
			name: "Ready condition with VaultNotInitialized reason",
			conds: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeReady, Reason: vaultv1alpha1.ReasonVaultNotInitialized},
			},
			want: true,
		},
		{
			name: "Ready condition with NetworkError reason — not a sealed state",
			conds: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeReady, Reason: vaultv1alpha1.ReasonNetworkError},
			},
			want: false,
		},
		{
			name: "Ready condition with Succeeded — healthy, not sealed",
			conds: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeReady, Reason: vaultv1alpha1.ReasonSucceeded},
			},
			want: false,
		},
		{
			name: "Sealed reason on a non-Ready condition is ignored",
			// Defensive: if some other condition type happens to share the
			// reason string, we don't accidentally fire the unseal event.
			conds: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeSynced, Reason: vaultv1alpha1.ReasonVaultSealed},
			},
			want: false,
		},
		{
			name:  "no conditions at all",
			conds: nil,
			want:  false,
		},
		{
			name: "multiple conditions, one matches",
			conds: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeSynced, Reason: vaultv1alpha1.ReasonFailed},
				{Type: vaultv1alpha1.ConditionTypeReady, Reason: vaultv1alpha1.ReasonVaultSealed},
				{Type: vaultv1alpha1.ConditionTypeDependencyReady, Reason: vaultv1alpha1.ReasonDependencyReady},
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := wasSealedReason(tc.conds)
			if got != tc.want {
				t.Errorf("wasSealedReason() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClassifyConnectionError pins the bug-fix from the §C-followup:
// the connection handler's `handleSyncError` was previously hard-coding
// `ReasonFailed` for every error, which meant a sealed Vault never got
// `ReasonVaultSealed` set on the Ready condition. The wasSealedReason
// helper would then never see the right reason on the next reconcile,
// so the VaultUnsealed recovery event would never fire.
//
// classifyConnectionError now mirrors syncerror.Handle's classification
// for the sealed/uninitialized/network/generic cases.
func TestClassifyConnectionError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "VaultSealedError (initialized=true) → VaultSealed",
			err:  infraerrors.NewVaultSealedError("c", "addr", true),
			want: vaultv1alpha1.ReasonVaultSealed,
		},
		{
			name: "VaultSealedError (initialized=false) → VaultNotInitialized",
			err:  infraerrors.NewVaultSealedError("c", "addr", false),
			want: vaultv1alpha1.ReasonVaultNotInitialized,
		},
		{
			name: "wrapped VaultSealedError still classifies as sealed",
			// errors.As must traverse the wrap chain — pins the contract.
			err:  fmt.Errorf("vault check failed: %w", infraerrors.NewVaultSealedError("c", "addr", true)),
			want: vaultv1alpha1.ReasonVaultSealed,
		},
		{
			name: "ConnectionError → NetworkError",
			err:  &infraerrors.ConnectionError{ConnectionName: "c", Address: "addr", Cause: errors.New("dial timeout")},
			want: vaultv1alpha1.ReasonNetworkError,
		},
		{
			name: "generic error → Failed (catch-all)",
			err:  errors.New("something else broke"),
			want: vaultv1alpha1.ReasonFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyConnectionError(tc.err)
			if got != tc.want {
				t.Errorf("classifyConnectionError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
