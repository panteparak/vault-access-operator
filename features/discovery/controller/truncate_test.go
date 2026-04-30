/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// makeDiscoveredResources fabricates n DiscoveredResource entries with
// distinct names for cap-related tests.
func makeDiscoveredResources(n int, kind string) []vaultv1alpha1.DiscoveredResource {
	out := make([]vaultv1alpha1.DiscoveredResource, n)
	for i := 0; i < n; i++ {
		out[i] = vaultv1alpha1.DiscoveredResource{
			Type:            kind,
			Name:            fmt.Sprintf("%s-%04d", kind, i),
			SuggestedCRName: fmt.Sprintf("%s-%04d", kind, i),
		}
	}
	return out
}

// TestUpdateDiscoveryStatus_TruncatesAtCap pins IMPROVEMENTS §5: when the
// scanner finds more than MaxDiscoveredResourcesInStatus matches, the
// controller MUST truncate before persisting. Otherwise the API server
// rejects the write under `+kubebuilder:validation:MaxItems=500` and the
// reconcile loops forever.
func TestUpdateDiscoveryStatus_TruncatesAtCap(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{Enabled: true}, nil)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	const overCap = MaxDiscoveredResourcesInStatus + 47
	scanResult := &ScanResult{
		UnmanagedPolicies:   nil,
		UnmanagedRoles:      nil,
		DiscoveredResources: makeDiscoveredResources(overCap, "policy"),
	}

	if err := r.updateDiscoveryStatus(context.Background(), testConnName, metav1.Now(), scanResult); err != nil {
		t.Fatalf("updateDiscoveryStatus returned error: %v", err)
	}

	var updated vaultv1alpha1.VaultConnection
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: testConnName}, &updated); err != nil {
		t.Fatalf("failed to get connection: %v", err)
	}

	if got := len(updated.Status.DiscoveryStatus.DiscoveredResources); got != MaxDiscoveredResourcesInStatus {
		t.Errorf("DiscoveredResources persisted = %d, want %d (cap)", got, MaxDiscoveredResourcesInStatus)
	}

	// Truncated condition must be True with a Capped reason and a message
	// that calls out how many were dropped.
	cond := findCondition(updated.Status.Conditions, "DiscoveryResultsTruncated")
	if cond == nil {
		t.Fatal("expected DiscoveryResultsTruncated condition to be set")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("condition.Status = %v, want True", cond.Status)
	}
	if cond.Reason != "Capped" {
		t.Errorf("condition.Reason = %q, want %q", cond.Reason, "Capped")
	}
	if !strings.Contains(cond.Message, "47") {
		t.Errorf("condition.Message should mention 47 omitted items, got %q", cond.Message)
	}
}

// TestUpdateDiscoveryStatus_NoTruncationWhenWithinCap is the counter-case:
// the truncation condition must be False when the count is within budget,
// otherwise a previously-True condition would linger after the user fixes
// their patterns.
func TestUpdateDiscoveryStatus_NoTruncationWhenWithinCap(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{Enabled: true}, nil)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	scanResult := &ScanResult{
		DiscoveredResources: makeDiscoveredResources(10, "policy"),
	}

	if err := r.updateDiscoveryStatus(context.Background(), testConnName, metav1.Now(), scanResult); err != nil {
		t.Fatalf("updateDiscoveryStatus returned error: %v", err)
	}

	var updated vaultv1alpha1.VaultConnection
	_ = k8sClient.Get(context.Background(), types.NamespacedName{Name: testConnName}, &updated)

	cond := findCondition(updated.Status.Conditions, "DiscoveryResultsTruncated")
	if cond == nil {
		t.Fatal("DiscoveryResultsTruncated condition should be set even when False")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("condition.Status = %v, want False (no truncation)", cond.Status)
	}
	if cond.Reason != "WithinCap" {
		t.Errorf("condition.Reason = %q, want WithinCap", cond.Reason)
	}
}

// TestUpdateDiscoveryStatus_UsesPatch_NoConflictWithConcurrentConnectionUpdate
// pins IMPROVEMENTS §9: switching from Update to Patch eliminates the
// optimistic-concurrency conflicts that previously occurred when the
// connection controller wrote Phase / AuthStatus while discovery was writing
// DiscoveryStatus. With MergeFrom, the patch only carries the discovery
// subset and tolerates concurrent changes to other fields.
//
// Strategy: simulate the race by mutating the connection's Phase out-of-band
// between Get and Patch via a patched fake client. With Update this would
// have surfaced as a 409; with Patch it should succeed.
func TestUpdateDiscoveryStatus_UsesPatch_NoConflictWithConcurrentConnectionUpdate(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{Enabled: true}, nil)
	conn.Status.Phase = vaultv1alpha1.PhaseSyncing

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	// Concurrent connection-controller update: bump the phase to Active in a
	// separate Update before discovery runs. With Update-based discovery this
	// would race; with Patch the discovery write doesn't carry Phase at all.
	var concurrent vaultv1alpha1.VaultConnection
	_ = k8sClient.Get(context.Background(), types.NamespacedName{Name: testConnName}, &concurrent)
	concurrent.Status.Phase = vaultv1alpha1.PhaseActive
	if err := k8sClient.Status().Update(context.Background(), &concurrent); err != nil {
		t.Fatalf("simulated connection-controller update failed: %v", err)
	}

	scanResult := &ScanResult{
		DiscoveredResources: makeDiscoveredResources(3, "policy"),
	}
	if err := r.updateDiscoveryStatus(context.Background(), testConnName, metav1.Now(), scanResult); err != nil {
		t.Fatalf("updateDiscoveryStatus returned error after concurrent update: %v", err)
	}

	var final vaultv1alpha1.VaultConnection
	_ = k8sClient.Get(context.Background(), types.NamespacedName{Name: testConnName}, &final)

	// Both writes must be visible: discovery's DiscoveryStatus AND the
	// connection-controller's Phase=Active. If discovery's Patch had blown
	// over Phase we'd see PhaseSyncing here.
	if final.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("Phase = %v, want Active (discovery Patch should not overwrite connection writes)",
			final.Status.Phase)
	}
	if final.Status.DiscoveryStatus == nil || len(final.Status.DiscoveryStatus.DiscoveredResources) != 3 {
		t.Errorf("DiscoveryStatus.DiscoveredResources = %v, want 3 entries", final.Status.DiscoveryStatus)
	}
}

// findCondition returns a pointer to the named condition, or nil if absent.
func findCondition(conds []vaultv1alpha1.Condition, condType string) *vaultv1alpha1.Condition {
	for i := range conds {
		if conds[i].Type == condType {
			return &conds[i]
		}
	}
	return nil
}
