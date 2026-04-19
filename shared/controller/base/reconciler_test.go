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

package base

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// mockHandler is a test implementation of FeatureHandler.
type mockHandler struct {
	syncFunc      func(ctx context.Context, resource *corev1.ConfigMap) error
	cleanupFunc   func(ctx context.Context, resource *corev1.ConfigMap) error
	syncCalled    bool
	cleanupCalled bool
}

func (m *mockHandler) Sync(ctx context.Context, resource *corev1.ConfigMap) error {
	m.syncCalled = true
	if m.syncFunc != nil {
		return m.syncFunc(ctx, resource)
	}
	return nil
}

func (m *mockHandler) Cleanup(ctx context.Context, resource *corev1.ConfigMap) error {
	m.cleanupCalled = true
	if m.cleanupFunc != nil {
		return m.cleanupFunc(ctx, resource)
	}
	return nil
}

func newConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{}
}

func TestNewBaseReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := logr.Discard()

	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, nil)

	if r == nil {
		t.Fatal("expected BaseReconciler to be non-nil")
		return
	}

	if r.Client != c {
		t.Error("expected Client to be set")
	}

	if r.Scheme != scheme {
		t.Error("expected Scheme to be set")
	}

	if r.Finalizer == nil {
		t.Error("expected Finalizer to be initialized")
	}

	if r.Status == nil {
		t.Error("expected Status to be initialized")
	}
}

func TestBaseReconciler_Reconcile_ResourceNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := logr.Discard()

	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, nil)
	handler := &mockHandler{}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "nonexistent",
			Namespace: "default",
		},
	}

	result, err := r.Reconcile(context.Background(), req, handler, newConfigMap)

	if err != nil {
		t.Errorf("expected no error for not found, got %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Error("expected empty result for not found resource")
	}

	if handler.syncCalled || handler.cleanupCalled {
		t.Error("handler should not be called for not found resource")
	}
}

func TestBaseReconciler_Reconcile_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	logger := logr.Discard()
	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, nil)

	handler := &mockHandler{}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	result, err := r.Reconcile(context.Background(), req, handler, newConfigMap)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if !handler.syncCalled {
		t.Error("expected Sync to be called")
	}

	if handler.cleanupCalled {
		t.Error("expected Cleanup to not be called")
	}

	if result.RequeueAfter != DefaultRequeueSuccess {
		t.Errorf("expected RequeueAfter %v, got %v", DefaultRequeueSuccess, result.RequeueAfter)
	}

	// Verify finalizer was added
	var updated corev1.ConfigMap
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, &updated)
	if len(updated.Finalizers) != 1 || updated.Finalizers[0] != "test.finalizer" {
		t.Errorf("expected finalizer to be added, got %v", updated.Finalizers)
	}
}

func TestBaseReconciler_Reconcile_SyncError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	logger := logr.Discard()
	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, nil)

	syncErr := errors.New("sync failed")
	handler := &mockHandler{
		syncFunc: func(_ context.Context, _ *corev1.ConfigMap) error {
			return syncErr
		},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	result, err := r.Reconcile(context.Background(), req, handler, newConfigMap)

	if err != syncErr {
		t.Errorf("expected error %v, got %v", syncErr, err)
	}

	if result.RequeueAfter != DefaultRequeueError {
		t.Errorf("expected RequeueAfter %v, got %v", DefaultRequeueError, result.RequeueAfter)
	}
}

func TestBaseReconciler_Reconcile_Deletion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{"test.finalizer"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	logger := logr.Discard()
	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, nil)

	handler := &mockHandler{}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	result, err := r.Reconcile(context.Background(), req, handler, newConfigMap)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if handler.syncCalled {
		t.Error("expected Sync to not be called during deletion")
	}

	if !handler.cleanupCalled {
		t.Error("expected Cleanup to be called during deletion")
	}

	if result.RequeueAfter != 0 {
		t.Error("expected empty result after successful cleanup")
	}

	// Verify finalizer was removed
	var updated corev1.ConfigMap
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, &updated)
	if len(updated.Finalizers) != 0 {
		t.Errorf("expected finalizer to be removed, got %v", updated.Finalizers)
	}
}

func TestBaseReconciler_Reconcile_DeletionNoOurFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// When our finalizer isn't present but another one is, we should skip cleanup.
	// In K8s, an object with deletionTimestamp must have at least one finalizer,
	// otherwise it would be immediately garbage collected.
	now := metav1.NewTime(time.Now())
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{"other.controller/finalizer"}, // Not our finalizer
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	logger := logr.Discard()
	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, nil)

	handler := &mockHandler{}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	result, err := r.Reconcile(context.Background(), req, handler, newConfigMap)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if handler.cleanupCalled {
		t.Error("expected Cleanup to not be called when our finalizer is missing")
	}

	if result.RequeueAfter != 0 {
		t.Error("expected empty result when our finalizer is missing")
	}

	// Verify we didn't modify the other finalizer
	var updated corev1.ConfigMap
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, &updated)
	if len(updated.Finalizers) != 1 || updated.Finalizers[0] != "other.controller/finalizer" {
		t.Errorf("expected other finalizer to remain, got %v", updated.Finalizers)
	}
}

func TestBaseReconciler_Reconcile_CleanupError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{"test.finalizer"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	logger := logr.Discard()
	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, nil)

	cleanupErr := errors.New("cleanup failed")
	handler := &mockHandler{
		cleanupFunc: func(_ context.Context, _ *corev1.ConfigMap) error {
			return cleanupErr
		},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	result, err := r.Reconcile(context.Background(), req, handler, newConfigMap)

	if err != cleanupErr {
		t.Errorf("expected error %v, got %v", cleanupErr, err)
	}

	if result.RequeueAfter != DefaultRequeueError {
		t.Errorf("expected RequeueAfter %v, got %v", DefaultRequeueError, result.RequeueAfter)
	}

	// Verify finalizer was NOT removed (cleanup failed)
	var updated corev1.ConfigMap
	_ = c.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, &updated)
	if len(updated.Finalizers) != 1 {
		t.Error("expected finalizer to remain after cleanup failure")
	}
}

func TestBaseReconciler_WithStatusUpdater(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	statusUpdateCalled := false
	statusUpdater := func(_ context.Context, _ *corev1.ConfigMap, err error) error {
		statusUpdateCalled = true
		return nil
	}

	logger := logr.Discard()
	r := NewBaseReconciler(c, scheme, logger, "test.finalizer", statusUpdater, nil)

	handler := &mockHandler{}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	_, _ = r.Reconcile(context.Background(), req, handler, newConfigMap)

	if !statusUpdateCalled {
		t.Error("expected status updater to be called")
	}
}

// Ensure FeatureHandler interface is properly defined.
var _ FeatureHandler[*corev1.ConfigMap] = (*mockHandler)(nil)

// Ensure BaseReconciler works with different client.Object types.
func TestBaseReconciler_GenericType(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Test with Secret instead of ConfigMap
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	logger := logr.Discard()

	// Create reconciler for Secret type
	r := NewBaseReconciler[*corev1.Secret](c, scheme, logger, "test.finalizer", nil, nil)

	secretHandler := &secretMockHandler{}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-secret",
			Namespace: "default",
		},
	}

	newSecret := func() *corev1.Secret { return &corev1.Secret{} }
	result, err := r.Reconcile(context.Background(), req, secretHandler, newSecret)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if !secretHandler.syncCalled {
		t.Error("expected Sync to be called")
	}

	if result.RequeueAfter != DefaultRequeueSuccess {
		t.Errorf("expected RequeueAfter %v, got %v", DefaultRequeueSuccess, result.RequeueAfter)
	}
}

type secretMockHandler struct {
	syncCalled    bool
	cleanupCalled bool
}

func (m *secretMockHandler) Sync(_ context.Context, _ *corev1.Secret) error {
	m.syncCalled = true
	return nil
}

func (m *secretMockHandler) Cleanup(_ context.Context, _ *corev1.Secret) error {
	m.cleanupCalled = true
	return nil
}

var _ FeatureHandler[*corev1.Secret] = (*secretMockHandler)(nil)
var _ client.Object = (*corev1.Secret)(nil)

// Helper functions for EventRecorder tests

// collectEvents drains all events from a FakeRecorder's channel.
func collectEvents(recorder *record.FakeRecorder) []string {
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

// containsEvent checks if any event contains the specified reason.
func containsEvent(events []string, reason string) bool {
	for _, e := range events {
		if strings.Contains(e, reason) {
			return true
		}
	}
	return false
}

// EventRecorder Tests

func TestBaseReconciler_EventRecording_Sync(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()

	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, recorder)
	handler := &mockHandler{}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	_, err := r.Reconcile(context.Background(), req, handler, newConfigMap)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	events := collectEvents(recorder)

	if !containsEvent(events, EventReasonSyncing) {
		t.Errorf("expected %s event, got events: %v", EventReasonSyncing, events)
	}

	if !containsEvent(events, EventReasonSynced) {
		t.Errorf("expected %s event, got events: %v", EventReasonSynced, events)
	}
}

func TestBaseReconciler_EventRecording_SyncError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()

	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, recorder)

	syncErr := errors.New("sync failed")
	handler := &mockHandler{
		syncFunc: func(_ context.Context, _ *corev1.ConfigMap) error {
			return syncErr
		},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	_, _ = r.Reconcile(context.Background(), req, handler, newConfigMap)

	events := collectEvents(recorder)

	if !containsEvent(events, EventReasonSyncing) {
		t.Errorf("expected %s event, got events: %v", EventReasonSyncing, events)
	}

	if !containsEvent(events, EventReasonSyncFailed) {
		t.Errorf("expected %s event, got events: %v", EventReasonSyncFailed, events)
	}

	// SyncFailed event should contain the error message
	for _, e := range events {
		if strings.Contains(e, EventReasonSyncFailed) {
			if !strings.Contains(e, "sync failed") {
				t.Errorf("expected SyncFailed event to contain error message, got: %s", e)
			}
		}
	}
}

func TestBaseReconciler_EventRecording_Deletion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{"test.finalizer"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()

	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, recorder)
	handler := &mockHandler{}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	_, err := r.Reconcile(context.Background(), req, handler, newConfigMap)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	events := collectEvents(recorder)

	if !containsEvent(events, EventReasonDeleting) {
		t.Errorf("expected %s event, got events: %v", EventReasonDeleting, events)
	}

	if !containsEvent(events, EventReasonDeleted) {
		t.Errorf("expected %s event, got events: %v", EventReasonDeleted, events)
	}
}

func TestBaseReconciler_EventRecording_DeletionError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{"test.finalizer"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()

	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, recorder)

	cleanupErr := errors.New("cleanup failed")
	handler := &mockHandler{
		cleanupFunc: func(_ context.Context, _ *corev1.ConfigMap) error {
			return cleanupErr
		},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	_, _ = r.Reconcile(context.Background(), req, handler, newConfigMap)

	events := collectEvents(recorder)

	if !containsEvent(events, EventReasonDeleting) {
		t.Errorf("expected %s event, got events: %v", EventReasonDeleting, events)
	}

	if !containsEvent(events, EventReasonDeleteFailed) {
		t.Errorf("expected %s event, got events: %v", EventReasonDeleteFailed, events)
	}

	// DeleteFailed event should contain the error message
	for _, e := range events {
		if strings.Contains(e, EventReasonDeleteFailed) {
			if !strings.Contains(e, "cleanup failed") {
				t.Errorf("expected DeleteFailed event to contain error message, got: %s", e)
			}
		}
	}
}

func TestBaseReconciler_DeletionStuck_EmitsWarning(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Deletion timestamp 10 minutes ago — should trigger stuck warning
	staleTime := metav1.NewTime(time.Now().Add(-10 * time.Minute))
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			DeletionTimestamp: &staleTime,
			Finalizers:        []string{"test.finalizer"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()

	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, recorder)

	cleanupErr := errors.New("vault unreachable")
	handler := &mockHandler{
		cleanupFunc: func(_ context.Context, _ *corev1.ConfigMap) error {
			return cleanupErr
		},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	_, _ = r.Reconcile(context.Background(), req, handler, newConfigMap)

	events := collectEvents(recorder)

	if !containsEvent(events, EventReasonDeletionStuck) {
		t.Errorf("expected %s event for deletion pending > 5 min, got events: %v",
			EventReasonDeletionStuck, events)
	}

	// Should also have DeleteFailed
	if !containsEvent(events, EventReasonDeleteFailed) {
		t.Errorf("expected %s event, got events: %v", EventReasonDeleteFailed, events)
	}
}

func TestBaseReconciler_DeletionRecent_NoStuckWarning(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Deletion timestamp 1 minute ago — should NOT trigger stuck warning
	recentTime := metav1.NewTime(time.Now().Add(-1 * time.Minute))
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			DeletionTimestamp: &recentTime,
			Finalizers:        []string{"test.finalizer"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := logr.Discard()

	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, recorder)

	cleanupErr := errors.New("vault unreachable")
	handler := &mockHandler{
		cleanupFunc: func(_ context.Context, _ *corev1.ConfigMap) error {
			return cleanupErr
		},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	_, _ = r.Reconcile(context.Background(), req, handler, newConfigMap)

	events := collectEvents(recorder)

	if containsEvent(events, EventReasonDeletionStuck) {
		t.Errorf("did NOT expect %s event for deletion pending < 5 min, got events: %v",
			EventReasonDeletionStuck, events)
	}

	// Should still have DeleteFailed
	if !containsEvent(events, EventReasonDeleteFailed) {
		t.Errorf("expected %s event, got events: %v", EventReasonDeleteFailed, events)
	}
}

func TestBaseReconciler_EventRecording_NilRecorder(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	logger := logr.Discard()

	// Pass nil recorder - should not panic
	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, nil)
	handler := &mockHandler{}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	// This should not panic even with nil recorder
	result, err := r.Reconcile(context.Background(), req, handler, newConfigMap)

	if err != nil {
		t.Errorf("expected no error with nil recorder, got %v", err)
	}

	if result.RequeueAfter != DefaultRequeueSuccess {
		t.Errorf("expected RequeueAfter %v, got %v", DefaultRequeueSuccess, result.RequeueAfter)
	}
}

func TestBaseReconciler_EventRecording_NilRecorder_Deletion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{"test.finalizer"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	logger := logr.Discard()

	// Pass nil recorder - should not panic during deletion
	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logger, "test.finalizer", nil, nil)
	handler := &mockHandler{}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test",
			Namespace: "default",
		},
	}

	// This should not panic even with nil recorder during deletion
	result, err := r.Reconcile(context.Background(), req, handler, newConfigMap)

	if err != nil {
		t.Errorf("expected no error with nil recorder, got %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Error("expected empty result after successful cleanup")
	}
}

// TestBaseReconciler_Reconcile_ClearsReconcileNowAnnotation pins
// IMPROVEMENTS Missing Features §H: after a successful Sync, the base
// reconciler patches the `vault.platform.io/reconcile-now` annotation off
// the resource so the watch predicate doesn't re-fire on every reconcile.
func TestBaseReconciler_Reconcile_ClearsReconcileNowAnnotation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			Annotations: map[string]string{
				"vault.platform.io/reconcile-now": "2026-04-18T10:00:00Z",
				"other":                           "keep-me",
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()

	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logr.Discard(), "test.finalizer", nil, nil)
	handler := &mockHandler{}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}}
	if _, err := r.Reconcile(context.Background(), req, handler, newConfigMap); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated corev1.ConfigMap
	if err := c.Get(context.Background(), req.NamespacedName, &updated); err != nil {
		t.Fatalf("failed to re-fetch: %v", err)
	}
	if _, stillSet := updated.Annotations["vault.platform.io/reconcile-now"]; stillSet {
		t.Error("reconcile-now annotation should be cleared after successful sync")
	}
	if updated.Annotations["other"] != "keep-me" {
		t.Errorf("unrelated annotations must survive the patch; got %+v", updated.Annotations)
	}
}

// TestKindLabelForResource pins the bug-fix from the §K-followup: the
// reconcile-duration histogram's `kind` label must be a clean type name
// like "ConfigMap" or "VaultPolicy", not "*v1alpha1.VaultPolicy" which
// the original `fmt.Sprintf("%T")` fallback produced. Operators looking
// at Prometheus would have seen `kind="*v1alpha1.VaultPolicy"` which is
// ugly, breaks dashboard labels, and includes the package qualifier.
//
// The fix uses reflect.TypeOf().Elem().Name() to strip both the pointer
// prefix and the package path. Tests against ConfigMap (a builtin from
// corev1) since that's what BaseReconciler_test_helpers uses.
func TestKindLabelForResource(t *testing.T) {
	got := kindLabelForResource(newConfigMap)
	if got != "ConfigMap" {
		t.Errorf("expected clean type name 'ConfigMap', got %q", got)
	}
}

func TestKindLabelForResource_Nil(t *testing.T) {
	got := kindLabelForResource[*corev1.ConfigMap](nil)
	if got != "" {
		t.Errorf("expected empty string for nil factory, got %q", got)
	}
}

// TestBaseReconciler_Reconcile_KeepsReconcileNowAnnotation_OnSyncError
// pins that a failing Sync does NOT clear the annotation — the user's
// forced-sync intent should outlive a transient failure so the next
// reconcile still honors it.
func TestBaseReconciler_Reconcile_KeepsReconcileNowAnnotation_OnSyncError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			Annotations: map[string]string{
				"vault.platform.io/reconcile-now": "2026-04-18T10:00:00Z",
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()

	r := NewBaseReconciler[*corev1.ConfigMap](c, scheme, logr.Discard(), "test.finalizer", nil, nil)
	handler := &mockHandler{
		syncFunc: func(ctx context.Context, resource *corev1.ConfigMap) error {
			return errors.New("vault unreachable")
		},
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "default"}}
	// The BaseReconciler.Status.Error path returns nil error but sets a
	// requeue — we don't care about the exact result, only that the
	// annotation is intact.
	_, _ = r.Reconcile(context.Background(), req, handler, newConfigMap)

	var updated corev1.ConfigMap
	if err := c.Get(context.Background(), req.NamespacedName, &updated); err != nil {
		t.Fatalf("failed to re-fetch: %v", err)
	}
	if _, stillSet := updated.Annotations["vault.platform.io/reconcile-now"]; !stillSet {
		t.Error("reconcile-now annotation must survive a failed sync — " +
			"the user's intent to force-reconcile outlives a transient error")
	}
}
