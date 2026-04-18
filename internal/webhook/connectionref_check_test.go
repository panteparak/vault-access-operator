/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package webhook

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// TestCheckConnectionRefExists covers the four relevant paths for IMPROVEMENTS §36.
func TestCheckConnectionRefExists(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	existingConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "existing"},
	}

	tests := []struct {
		name         string
		client       bool // whether to pass a real client or nil
		refName      string
		preload      []runtime.Object
		wantWarnings int
		wantContains string
	}{
		{
			name:         "nil client returns nothing",
			client:       false,
			refName:      "anything",
			wantWarnings: 0,
		},
		{
			name:         "empty ref returns nothing",
			client:       true,
			refName:      "",
			wantWarnings: 0,
		},
		{
			name:         "existing connection returns nothing",
			client:       true,
			refName:      "existing",
			preload:      []runtime.Object{existingConn},
			wantWarnings: 0,
		},
		{
			name:         "missing connection returns one warning",
			client:       true,
			refName:      "does-not-exist",
			wantWarnings: 1,
			wantContains: "does not currently resolve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c = fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(tt.preload...).Build()
			if !tt.client {
				warnings := checkConnectionRefExists(context.Background(), nil, tt.refName)
				if len(warnings) != tt.wantWarnings {
					t.Errorf("got %d warnings, want %d", len(warnings), tt.wantWarnings)
				}
				return
			}
			warnings := checkConnectionRefExists(context.Background(), c, tt.refName)
			if len(warnings) != tt.wantWarnings {
				t.Errorf("got %d warnings, want %d: %v", len(warnings), tt.wantWarnings, warnings)
			}
			if tt.wantContains != "" && (len(warnings) == 0 || !strings.Contains(warnings[0], tt.wantContains)) {
				t.Errorf("warning should contain %q, got %v", tt.wantContains, warnings)
			}
		})
	}
}

// TestVaultPolicyValidator_WarnsOnMissingConnection is the end-to-end §36
// assertion on the policy validator — apply a policy whose connectionRef is
// not in the cluster yet, expect a warning but NOT a rejection.
func TestVaultPolicyValidator_WarnsOnMissingConnection(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	v := &VaultPolicyValidator{client: c}

	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "not-yet-applied",
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/ok", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
			},
		},
	}
	warnings, err := v.ValidateCreate(context.Background(), policy)
	if err != nil {
		t.Fatalf("ValidateCreate unexpectedly failed: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("want 1 warning about missing connectionRef, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "not-yet-applied") {
		t.Errorf("warning should name the missing connection, got %q", warnings[0])
	}
}
