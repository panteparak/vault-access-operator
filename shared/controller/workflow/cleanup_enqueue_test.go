/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package workflow

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/cleanup"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// fakeQueue records every Enqueue call. Mutex-guarded because Execute may
// spawn goroutines for event publication; the test asserts on the primary
// (synchronous) Enqueue path.
type fakeQueue struct {
	mu    sync.Mutex
	items []cleanup.Item
	err   error // if non-nil, Enqueue returns it
}

func (q *fakeQueue) Enqueue(_ context.Context, item cleanup.Item) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return q.err
	}
	q.items = append(q.items, item)
	return nil
}

func (q *fakeQueue) snapshot() []cleanup.Item {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]cleanup.Item, len(q.items))
	copy(out, q.items)
	return out
}

func newPolicyForCleanup(t *testing.T) *vaultv1alpha1.VaultPolicy {
	t.Helper()
	return &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "enqueue-test",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "conn",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
	}
}

// TestCleanupWorkflow_EnqueuesOnVaultUnreachable is the primary §2 regression
// test. Before the fix, an unreachable Vault at cleanup time would make the
// workflow silently skip delete, let the finalizer drop, and leak the Vault
// resource with no retry path.
func TestCleanupWorkflow_EnqueuesOnVaultUnreachable(t *testing.T) {
	t.Parallel()

	policy := newPolicyForCleanup(t)
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	// getVaultClient returns an error — simulates cache miss / auth failure /
	// network partition at delete time.
	getter := func(_ string) (*vault.Client, error) {
		return nil, errors.New("vault unreachable")
	}
	bus := events.NewEventBus(logr.Discard())
	queue := &fakeQueue{}
	ops := &mockOps{}

	wf := NewCleanupWorkflowWithQueue(k8sClient, getter, bus, queue, logr.Discard())
	if err := wf.Execute(context.Background(), resource, ops); err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}

	items := queue.snapshot()
	if len(items) != 1 {
		t.Fatalf("expected 1 queue item (Vault unreachable → enqueue), got %d", len(items))
	}
	if items[0].VaultName != ops.VaultResourceName() {
		t.Errorf("queue item VaultName = %q, want %q", items[0].VaultName, ops.VaultResourceName())
	}
	if items[0].ResourceType != cleanup.ResourceTypePolicy {
		t.Errorf("queue item ResourceType = %q, want Policy", items[0].ResourceType)
	}
	if items[0].ConnectionName != policy.Spec.ConnectionRef {
		t.Errorf("queue item ConnectionName = %q, want %q",
			items[0].ConnectionName, policy.Spec.ConnectionRef)
	}
	// DeleteFromVault must NOT have been called (no client available).
	if containsCall(ops.calls, "DeleteFromVault") {
		t.Error("DeleteFromVault was called even though vault client fetch failed")
	}
}

// TestCleanupWorkflow_DoesNotEnqueueOnVault404 pins the "already-gone" case:
// if Vault returns 404 for DeleteFromVault, the resource is already absent
// and the workflow should treat that as success. Enqueuing would just waste
// retry cycles hammering a non-existent resource.
func TestCleanupWorkflow_DoesNotEnqueueOnVault404(t *testing.T) {
	t.Parallel()

	policy := newPolicyForCleanup(t)
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	vc := newAuthenticatedVaultClient(t)
	getter := func(_ string) (*vault.Client, error) { return vc, nil }
	bus := events.NewEventBus(logr.Discard())
	queue := &fakeQueue{}
	ops := &mockOps{
		deleteErr: &vaultapi.ResponseError{StatusCode: 404, Errors: []string{"policy not found"}},
	}

	wf := NewCleanupWorkflowWithQueue(k8sClient, getter, bus, queue, logr.Discard())
	if err := wf.Execute(context.Background(), resource, ops); err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}

	if items := queue.snapshot(); len(items) != 0 {
		t.Errorf("expected 0 queue items (Vault 404 = success), got %d: %+v", len(items), items)
	}
	if !containsCall(ops.calls, "DeleteFromVault") {
		t.Error("expected DeleteFromVault to be called")
	}
	// Managed marker removal should still run — 404 on the primary resource
	// doesn't invalidate the cleanup attempt, just confirms the "already gone"
	// state. Orphan detection would otherwise flag a ghost marker.
	if !containsCall(ops.calls, "RemoveManaged") {
		t.Error("expected RemoveManaged to run after 404")
	}
}

// TestCleanupWorkflow_EnqueuesOnVault500 ensures generic Vault failures still
// enqueue for retry. This is the common case (Vault overloaded, restarting, etc.).
func TestCleanupWorkflow_EnqueuesOnVault500(t *testing.T) {
	t.Parallel()

	policy := newPolicyForCleanup(t)
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	vc := newAuthenticatedVaultClient(t)
	getter := func(_ string) (*vault.Client, error) { return vc, nil }
	bus := events.NewEventBus(logr.Discard())
	queue := &fakeQueue{}
	ops := &mockOps{
		deleteErr: &vaultapi.ResponseError{StatusCode: 500, Errors: []string{"internal server error"}},
	}

	wf := NewCleanupWorkflowWithQueue(k8sClient, getter, bus, queue, logr.Discard())
	if err := wf.Execute(context.Background(), resource, ops); err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}

	items := queue.snapshot()
	if len(items) != 1 {
		t.Fatalf("expected 1 queue item (Vault 500 → enqueue for retry), got %d", len(items))
	}
	if items[0].LastError == "" {
		t.Error("queue item should record LastError for diagnostics")
	}
}

// TestCleanupWorkflow_NilQueueRemainsBackwardCompatible confirms that passing
// nil for the queue keeps the pre-§2 behavior (log and continue). Existing
// unit tests that use NewCleanupWorkflow without a queue rely on this.
func TestCleanupWorkflow_NilQueueRemainsBackwardCompatible(t *testing.T) {
	t.Parallel()

	policy := newPolicyForCleanup(t)
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	getter := func(_ string) (*vault.Client, error) {
		return nil, errors.New("unreachable")
	}
	bus := events.NewEventBus(logr.Discard())
	ops := &mockOps{}

	// No queue wired → workflow must not panic and must still proceed.
	wf := NewCleanupWorkflow(k8sClient, getter, bus, logr.Discard())
	if err := wf.Execute(context.Background(), resource, ops); err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}
}

// TestCleanupWorkflow_FinalizerNotBlockedByQueueFailure ensures that even if
// the queue itself is broken (write fails), the workflow still returns nil so
// the base reconciler removes the finalizer. Better to leak (and let orphan
// detection catch it later) than to wedge the reconciler forever.
func TestCleanupWorkflow_FinalizerNotBlockedByQueueFailure(t *testing.T) {
	t.Parallel()

	policy := newPolicyForCleanup(t)
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	getter := func(_ string) (*vault.Client, error) {
		return nil, errors.New("unreachable")
	}
	bus := events.NewEventBus(logr.Discard())
	queue := &fakeQueue{err: errors.New("queue ConfigMap write failed")}
	ops := &mockOps{}

	wf := NewCleanupWorkflowWithQueue(k8sClient, getter, bus, queue, logr.Discard())
	if err := wf.Execute(context.Background(), resource, ops); err != nil {
		t.Fatalf("Execute must not propagate queue-write errors (got %v)", err)
	}
}
