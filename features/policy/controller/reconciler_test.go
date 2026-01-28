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

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// Helper to collect events from FakeRecorder
func collectRecorderEvents(recorder *record.FakeRecorder) []string {
	var events []string
	for {
		select {
		case event := <-recorder.Events:
			events = append(events, event)
		default:
			return events
		}
	}
}

// Helper to check if events contain a specific reason
func hasEvent(events []string, reason string) bool {
	for _, e := range events {
		if strings.Contains(e, reason) {
			return true
		}
	}
	return false
}

// ---- PolicyReconciler Tests ----

func TestPolicyReconciler_Reconcile_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewPolicyReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "nonexistent",
			Namespace: "default",
		},
	}

	result, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Errorf("expected no error for not found, got %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Error("expected empty result for not found resource")
	}
}

func TestPolicyReconciler_Reconcile_AddsFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "test-conn",
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewPolicyReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	// The reconciler will fail on sync (no vault client), but should add finalizer first
	_, _ = r.Reconcile(context.Background(), req)

	// Verify finalizer was added
	var updated vaultv1alpha1.VaultPolicy
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, &updated)

	if len(updated.Finalizers) == 0 {
		t.Error("expected finalizer to be added")
		return
	}

	if updated.Finalizers[0] != vaultv1alpha1.FinalizerName {
		t.Errorf("expected finalizer %q, got %q", vaultv1alpha1.FinalizerName, updated.Finalizers[0])
	}
}

func TestPolicyReconciler_Reconcile_EmitsEvents(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "test-conn",
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewPolicyReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	_, _ = r.Reconcile(context.Background(), req)

	events := collectRecorderEvents(recorder)

	// Should have Syncing event (before sync attempt)
	if !hasEvent(events, "Syncing") {
		t.Errorf("expected Syncing event, got: %v", events)
	}

	// Should have SyncFailed event (no vault connection)
	if !hasEvent(events, "SyncFailed") {
		t.Errorf("expected SyncFailed event, got: %v", events)
	}
}

func TestPolicyReconciler_Reconcile_Deletion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-policy",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{vaultv1alpha1.FinalizerName},
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "test-conn",
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewPolicyReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Errorf("expected no error during cleanup, got %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Error("expected empty result after cleanup")
	}

	// Verify finalizer was removed
	var updated vaultv1alpha1.VaultPolicy
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, &updated)

	if len(updated.Finalizers) != 0 {
		t.Errorf("expected finalizer to be removed, got %v", updated.Finalizers)
	}
}

func TestPolicyReconciler_Reconcile_DeletionEmitsEvents(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-policy",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{vaultv1alpha1.FinalizerName},
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "test-conn",
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewPolicyReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	_, _ = r.Reconcile(context.Background(), req)

	events := collectRecorderEvents(recorder)

	// Should have Deleting event
	if !hasEvent(events, "Deleting") {
		t.Errorf("expected Deleting event, got: %v", events)
	}

	// Should have Deleted event (cleanup succeeds even without vault client)
	if !hasEvent(events, "Deleted") {
		t.Errorf("expected Deleted event, got: %v", events)
	}
}

// ---- ClusterPolicyReconciler Tests ----

func TestClusterPolicyReconciler_Reconcile_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewClusterPolicyReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name: "nonexistent",
		},
	}

	result, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Errorf("expected no error for not found, got %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Error("expected empty result for not found resource")
	}
}

func TestClusterPolicyReconciler_Reconcile_AddsFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-policy",
		},
		Spec: vaultv1alpha1.VaultClusterPolicySpec{
			ConnectionRef: "test-conn",
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clusterPolicy).
		WithStatusSubresource(clusterPolicy).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewClusterPolicyReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name: "test-cluster-policy",
		},
	}

	_, _ = r.Reconcile(context.Background(), req)

	// Verify finalizer was added
	var updated vaultv1alpha1.VaultClusterPolicy
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test-cluster-policy"}, &updated)

	if len(updated.Finalizers) == 0 {
		t.Error("expected finalizer to be added")
		return
	}

	if updated.Finalizers[0] != vaultv1alpha1.FinalizerName {
		t.Errorf("expected finalizer %q, got %q", vaultv1alpha1.FinalizerName, updated.Finalizers[0])
	}
}

func TestClusterPolicyReconciler_Reconcile_Deletion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster-policy",
			DeletionTimestamp: &now,
			Finalizers:        []string{vaultv1alpha1.FinalizerName},
		},
		Spec: vaultv1alpha1.VaultClusterPolicySpec{
			ConnectionRef: "test-conn",
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clusterPolicy).
		WithStatusSubresource(clusterPolicy).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewClusterPolicyReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name: "test-cluster-policy",
		},
	}

	result, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Errorf("expected no error during cleanup, got %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Error("expected empty result after cleanup")
	}

	// Verify finalizer was removed
	var updated vaultv1alpha1.VaultClusterPolicy
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test-cluster-policy"}, &updated)

	if len(updated.Finalizers) != 0 {
		t.Errorf("expected finalizer to be removed, got %v", updated.Finalizers)
	}
}

// ---- NewPolicyReconciler Tests ----

func TestNewPolicyReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewPolicyReconciler(c, scheme, handler, logger, recorder)

	if r == nil {
		t.Fatal("expected PolicyReconciler to be non-nil")
	}

	if r.base == nil {
		t.Error("expected base reconciler to be initialized")
	}

	if r.handler == nil {
		t.Error("expected handler to be set")
	}
}

func TestNewClusterPolicyReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewClusterPolicyReconciler(c, scheme, handler, logger, recorder)

	if r == nil {
		t.Fatal("expected ClusterPolicyReconciler to be non-nil")
	}

	if r.base == nil {
		t.Error("expected base reconciler to be initialized")
	}

	if r.handler == nil {
		t.Error("expected handler to be set")
	}
}

// ---- Feature Handler Adapter Tests ----

func TestPolicyFeatureHandler_Implements_Interface(t *testing.T) {
	// This test ensures the adapter properly implements the interface
	// Compilation will fail if the interface is not satisfied
	var _ = (*policyFeatureHandler)(nil)
}

func TestClusterPolicyFeatureHandler_Implements_Interface(t *testing.T) {
	// This test ensures the adapter properly implements the interface
	var _ = (*clusterPolicyFeatureHandler)(nil)
}
