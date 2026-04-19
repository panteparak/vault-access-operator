/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package workflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// newAuthenticatedVaultClient creates a Vault client marked as authenticated.
// Uses newTestVaultClient from sync_test.go and sets authenticated = true.
func newAuthenticatedVaultClient(t *testing.T) *vault.Client {
	t.Helper()
	c := newTestVaultClient(t)
	c.SetAuthenticated(true)
	return c
}

func TestCleanupWorkflow_HappyPath(t *testing.T) {
	t.Parallel()

	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "test-connection",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
	}
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	vc := newAuthenticatedVaultClient(t)
	getter := func(_ string) (*vault.Client, error) {
		return vc, nil
	}

	bus := events.NewEventBus(logr.Discard())
	ops := &mockOps{}

	wf := NewCleanupWorkflow(k8sClient, getter, bus, logr.Discard())
	err := wf.Execute(context.Background(), resource, ops)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !containsCall(ops.calls, "DeleteFromVault") {
		t.Error("expected DeleteFromVault to be called")
	}
	if !containsCall(ops.calls, "RemoveManaged") {
		t.Error("expected RemoveManaged to be called")
	}
	if !containsCall(ops.calls, "PublishDeleteEvent") {
		t.Error("expected PublishDeleteEvent to be called")
	}
	if resource.GetPhase() != vaultv1alpha1.PhaseDeleting {
		t.Errorf("expected phase %q, got %q", vaultv1alpha1.PhaseDeleting, resource.GetPhase())
	}
}

func TestCleanupWorkflow_RetainPolicy(t *testing.T) {
	t.Parallel()

	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "test-connection",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyRetain,
		},
	}
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	vc := newAuthenticatedVaultClient(t)
	getter := func(_ string) (*vault.Client, error) {
		return vc, nil
	}

	bus := events.NewEventBus(logr.Discard())
	ops := &mockOps{}

	wf := NewCleanupWorkflow(k8sClient, getter, bus, logr.Discard())
	err := wf.Execute(context.Background(), resource, ops)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if containsCall(ops.calls, "DeleteFromVault") {
		t.Error("expected DeleteFromVault NOT to be called for Retain policy")
	}
	if containsCall(ops.calls, "RemoveManaged") {
		t.Error("expected RemoveManaged NOT to be called for Retain policy")
	}
	if !containsCall(ops.calls, "PublishDeleteEvent") {
		t.Error("expected PublishDeleteEvent to still be called for Retain policy")
	}
}

func TestCleanupWorkflow_VaultClientError(t *testing.T) {
	t.Parallel()

	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "test-connection",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
	}
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	errorGetter := func(_ string) (*vault.Client, error) {
		return nil, errors.New("client not found")
	}

	bus := events.NewEventBus(logr.Discard())
	ops := &mockOps{}

	wf := NewCleanupWorkflow(k8sClient, errorGetter, bus, logr.Discard())
	err := wf.Execute(context.Background(), resource, ops)

	if err != nil {
		t.Fatalf("expected no error (best-effort), got: %v", err)
	}

	if containsCall(ops.calls, "DeleteFromVault") {
		t.Error("expected DeleteFromVault NOT to be called when client getter fails")
	}
	if !containsCall(ops.calls, "PublishDeleteEvent") {
		t.Error("expected PublishDeleteEvent to still be called despite client error")
	}
}

func TestCleanupWorkflow_UnauthenticatedClient(t *testing.T) {
	t.Parallel()

	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "test-connection",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
	}
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	// newTestVaultClient creates a client that is NOT authenticated by default
	unauthClient := newTestVaultClient(t)
	getter := func(_ string) (*vault.Client, error) {
		return unauthClient, nil
	}

	bus := events.NewEventBus(logr.Discard())
	ops := &mockOps{}

	wf := NewCleanupWorkflow(k8sClient, getter, bus, logr.Discard())
	err := wf.Execute(context.Background(), resource, ops)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if containsCall(ops.calls, "DeleteFromVault") {
		t.Error("expected DeleteFromVault NOT to be called for unauthenticated client")
	}
	if containsCall(ops.calls, "RemoveManaged") {
		t.Error("expected RemoveManaged NOT to be called for unauthenticated client")
	}
}

func TestCleanupWorkflow_DeleteFromVaultError_BestEffort(t *testing.T) {
	t.Parallel()

	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "test-connection",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
	}
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	vc := newAuthenticatedVaultClient(t)
	getter := func(_ string) (*vault.Client, error) {
		return vc, nil
	}

	bus := events.NewEventBus(logr.Discard())
	ops := &mockOps{
		deleteErr: errors.New("vault delete failed"),
	}

	wf := NewCleanupWorkflow(k8sClient, getter, bus, logr.Discard())
	err := wf.Execute(context.Background(), resource, ops)

	if err != nil {
		t.Fatalf("expected no error (best-effort), got: %v", err)
	}

	if !containsCall(ops.calls, "DeleteFromVault") {
		t.Error("expected DeleteFromVault to be called")
	}
	if !containsCall(ops.calls, "RemoveManaged") {
		t.Error("expected RemoveManaged to still be called after DeleteFromVault error")
	}
	if !containsCall(ops.calls, "PublishDeleteEvent") {
		t.Error("expected PublishDeleteEvent to still be called after DeleteFromVault error")
	}
}

func TestCleanupWorkflow_RemoveManagedError_BestEffort(t *testing.T) {
	t.Parallel()

	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "test-connection",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
	}
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	vc := newAuthenticatedVaultClient(t)
	getter := func(_ string) (*vault.Client, error) {
		return vc, nil
	}

	bus := events.NewEventBus(logr.Discard())
	ops := &mockOps{
		removeManagedErr: errors.New("failed to remove managed marker"),
	}

	wf := NewCleanupWorkflow(k8sClient, getter, bus, logr.Discard())
	err := wf.Execute(context.Background(), resource, ops)

	if err != nil {
		t.Fatalf("expected no error (best-effort), got: %v", err)
	}

	if !containsCall(ops.calls, "RemoveManaged") {
		t.Error("expected RemoveManaged to be called")
	}
	if !containsCall(ops.calls, "PublishDeleteEvent") {
		t.Error("expected PublishDeleteEvent to still be called after RemoveManaged error")
	}
}

func TestCleanupWorkflow_DeletionStartedAtPreserved(t *testing.T) {
	t.Parallel()

	existingTime := metav1.NewTime(time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC))
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "test-connection",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
		Status: vaultv1alpha1.VaultPolicyStatus{
			SyncStatus: vaultv1alpha1.SyncStatus{
				DeletionStartedAt: &existingTime,
			},
		},
	}
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	vc := newAuthenticatedVaultClient(t)
	getter := func(_ string) (*vault.Client, error) {
		return vc, nil
	}

	bus := events.NewEventBus(logr.Discard())
	ops := &mockOps{}

	wf := NewCleanupWorkflow(k8sClient, getter, bus, logr.Discard())
	err := wf.Execute(context.Background(), resource, ops)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	got := resource.GetDeletionStartedAt()
	if got == nil {
		t.Fatal("expected DeletionStartedAt to be set")
	}
	if !got.Equal(&existingTime) {
		t.Errorf("expected DeletionStartedAt to be preserved as %v, got %v", existingTime.Time, got.Time)
	}
}

func TestCleanupWorkflow_NilEventBus(t *testing.T) {
	t.Parallel()

	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "test-connection",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
	}
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	vc := newAuthenticatedVaultClient(t)
	getter := func(_ string) (*vault.Client, error) {
		return vc, nil
	}

	ops := &mockOps{}

	wf := NewCleanupWorkflow(k8sClient, getter, nil, logr.Discard())
	err := wf.Execute(context.Background(), resource, ops)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if containsCall(ops.calls, "PublishDeleteEvent") {
		t.Error("expected PublishDeleteEvent NOT to be called when eventBus is nil")
	}
	// Vault operations should still proceed normally
	if !containsCall(ops.calls, "DeleteFromVault") {
		t.Error("expected DeleteFromVault to still be called with nil eventBus")
	}
	if !containsCall(ops.calls, "RemoveManaged") {
		t.Error("expected RemoveManaged to still be called with nil eventBus")
	}
}

// TestCleanupWorkflow_DeletesDriftMetricSeries pins the bug-fix where
// the cleanup workflow's DeleteDriftDetected was using the wrong kind
// label — `label` (lowercase "policy") instead of `ops.ResourceKind()`
// ("VaultPolicy") — silently no-op-ing the metric series cleanup.
//
// The test:
//  1. Sets a drift gauge series under the same kind label that
//     finalizeSuccessfulSync uses (`ops.ResourceKind()`).
//  2. Runs Execute (cleanup workflow) for the same resource.
//  3. Asserts the series is actually gone from the registry.
//
// Without the fix, step 3 would fail because `DeleteLabelValues("policy", ...)`
// would never match a series written under `("VaultPolicy", ...)`.
func TestCleanupWorkflow_DeletesDriftMetricSeries(t *testing.T) {
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "drifty-policy",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  "test-connection",
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
	}
	k8sClient := newFakeK8sClient(t, policy)
	resource := newTestResource(policy)

	vc := newAuthenticatedVaultClient(t)
	getter := func(_ string) (*vault.Client, error) { return vc, nil }
	ops := &mockOps{} // ResourceKind() returns "VaultPolicy"

	// Pre-populate the gauge under the SAME label that
	// finalizeSuccessfulSync uses (`ops.ResourceKind()` = "VaultPolicy").
	// The cleanup must use this exact label or the delete is a no-op.
	metrics.DriftDetectedGauge.Reset()
	metrics.SetDriftDetected(ops.ResourceKind(), policy.Namespace, policy.Name, true)

	beforeCleanup := testutil.CollectAndCount(metrics.DriftDetectedGauge)
	if beforeCleanup != 1 {
		t.Fatalf("test setup wrong: expected 1 series before cleanup, got %d", beforeCleanup)
	}

	wf := NewCleanupWorkflow(k8sClient, getter, nil, logr.Discard())
	if err := wf.Execute(context.Background(), resource, ops); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	afterCleanup := testutil.CollectAndCount(metrics.DriftDetectedGauge)
	if afterCleanup != 0 {
		t.Errorf("expected drift series to be deleted; got %d series remaining "+
			"(label-mismatch bug means DeleteDriftDetected was a no-op)",
			afterCleanup)
	}
}
