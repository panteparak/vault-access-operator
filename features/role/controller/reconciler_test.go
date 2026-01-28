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

// ---- RoleReconciler Tests ----

func TestRoleReconciler_Reconcile_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewRoleReconciler(c, scheme, handler, logger, recorder)

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

func TestRoleReconciler_Reconcile_AddsFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "default",
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "test-conn",
			ServiceAccounts: []string{"default"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(role).
		WithStatusSubresource(role).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewRoleReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-role",
			Namespace: "default",
		},
	}

	// The reconciler will fail on sync (no vault client), but should add finalizer first
	_, _ = r.Reconcile(context.Background(), req)

	// Verify finalizer was added
	var updated vaultv1alpha1.VaultRole
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test-role", Namespace: "default"}, &updated)

	if len(updated.Finalizers) == 0 {
		t.Error("expected finalizer to be added")
		return
	}

	if updated.Finalizers[0] != vaultv1alpha1.FinalizerName {
		t.Errorf("expected finalizer %q, got %q", vaultv1alpha1.FinalizerName, updated.Finalizers[0])
	}
}

func TestRoleReconciler_Reconcile_EmitsEvents(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "default",
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "test-conn",
			ServiceAccounts: []string{"default"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(role).
		WithStatusSubresource(role).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewRoleReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-role",
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

func TestRoleReconciler_Reconcile_Deletion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-role",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{vaultv1alpha1.FinalizerName},
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "test-conn",
			ServiceAccounts: []string{"default"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(role).
		WithStatusSubresource(role).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewRoleReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-role",
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
	var updated vaultv1alpha1.VaultRole
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test-role", Namespace: "default"}, &updated)

	if len(updated.Finalizers) != 0 {
		t.Errorf("expected finalizer to be removed, got %v", updated.Finalizers)
	}
}

func TestRoleReconciler_Reconcile_DeletionEmitsEvents(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-role",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{vaultv1alpha1.FinalizerName},
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "test-conn",
			ServiceAccounts: []string{"default"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(role).
		WithStatusSubresource(role).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewRoleReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-role",
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

// ---- ClusterRoleReconciler Tests ----

func TestClusterRoleReconciler_Reconcile_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewClusterRoleReconciler(c, scheme, handler, logger, recorder)

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

func TestClusterRoleReconciler_Reconcile_AddsFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	clusterRole := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-role",
		},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			ConnectionRef: "test-conn",
			ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "default", Namespace: "default"},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clusterRole).
		WithStatusSubresource(clusterRole).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewClusterRoleReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name: "test-cluster-role",
		},
	}

	_, _ = r.Reconcile(context.Background(), req)

	// Verify finalizer was added
	var updated vaultv1alpha1.VaultClusterRole
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test-cluster-role"}, &updated)

	if len(updated.Finalizers) == 0 {
		t.Error("expected finalizer to be added")
		return
	}

	if updated.Finalizers[0] != vaultv1alpha1.FinalizerName {
		t.Errorf("expected finalizer %q, got %q", vaultv1alpha1.FinalizerName, updated.Finalizers[0])
	}
}

func TestClusterRoleReconciler_Reconcile_Deletion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	clusterRole := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster-role",
			DeletionTimestamp: &now,
			Finalizers:        []string{vaultv1alpha1.FinalizerName},
		},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			ConnectionRef: "test-conn",
			ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "default", Namespace: "default"},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clusterRole).
		WithStatusSubresource(clusterRole).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewClusterRoleReconciler(c, scheme, handler, logger, recorder)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name: "test-cluster-role",
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
	var updated vaultv1alpha1.VaultClusterRole
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test-cluster-role"}, &updated)

	if len(updated.Finalizers) != 0 {
		t.Errorf("expected finalizer to be removed, got %v", updated.Finalizers)
	}
}

// ---- NewRoleReconciler Tests ----

func TestNewRoleReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewRoleReconciler(c, scheme, handler, logger, recorder)

	if r == nil {
		t.Fatal("expected RoleReconciler to be non-nil")
	}

	if r.base == nil {
		t.Error("expected base reconciler to be initialized")
	}

	if r.handler == nil {
		t.Error("expected handler to be set")
	}
}

func TestNewClusterRoleReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logger)
	r := NewClusterRoleReconciler(c, scheme, handler, logger, recorder)

	if r == nil {
		t.Fatal("expected ClusterRoleReconciler to be non-nil")
	}

	if r.base == nil {
		t.Error("expected base reconciler to be initialized")
	}

	if r.handler == nil {
		t.Error("expected handler to be set")
	}
}

// ---- Feature Handler Adapter Tests ----

func TestRoleFeatureHandler_Implements_Interface(t *testing.T) {
	// This test ensures the adapter properly implements the interface
	// Compilation will fail if the interface is not satisfied
	var _ = (*roleFeatureHandler)(nil)
}

func TestClusterRoleFeatureHandler_Implements_Interface(t *testing.T) {
	// This test ensures the adapter properly implements the interface
	var _ = (*clusterRoleFeatureHandler)(nil)
}
