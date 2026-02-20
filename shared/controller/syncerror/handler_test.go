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

package syncerror

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// mockTarget implements StatusTarget for testing.
type mockTarget struct {
	object     client.Object
	generation int64
	phase      vaultv1alpha1.Phase
	message    string
	conditions []vaultv1alpha1.Condition
}

func (m *mockTarget) GetObject() client.Object                  { return m.object }
func (m *mockTarget) GetGeneration() int64                      { return m.generation }
func (m *mockTarget) SetPhase(p vaultv1alpha1.Phase)            { m.phase = p }
func (m *mockTarget) SetMessage(msg string)                     { m.message = msg }
func (m *mockTarget) GetConditions() []vaultv1alpha1.Condition  { return m.conditions }
func (m *mockTarget) SetConditions(c []vaultv1alpha1.Condition) { m.conditions = c }

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(s)
	return s
}

func newMockTarget() *mockTarget {
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Generation: 2,
		},
	}
	return &mockTarget{
		object:     policy,
		generation: 2,
		conditions: nil,
	}
}

func newFakeClient() client.Client {
	scheme := newTestScheme()
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultPolicy{}).
		Build()
}

func TestHandle_ConflictError(t *testing.T) {
	target := newMockTarget()
	k8sClient := newFakeClient()
	conflictErr := infraerrors.NewConflictError("policy", "test-policy", "managed by terraform")

	// Pre-create the object so Status().Update() can find it
	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	result := Handle(ctx, k8sClient, logr.Discard(), target, conflictErr)

	if result != conflictErr {
		t.Errorf("expected Handle to return original error, got %v", result)
	}
	if target.phase != vaultv1alpha1.PhaseConflict {
		t.Errorf("expected PhaseConflict, got %s", target.phase)
	}
	if len(target.conditions) < 2 {
		t.Fatalf("expected at least 2 conditions, got %d", len(target.conditions))
	}

	readyCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeReady)
	if readyCond == nil {
		t.Fatal("expected Ready condition")
	}
	if readyCond.Reason != vaultv1alpha1.ReasonConflict {
		t.Errorf("expected Ready reason %s, got %s", vaultv1alpha1.ReasonConflict, readyCond.Reason)
	}
	if readyCond.Status != metav1.ConditionFalse {
		t.Errorf("expected Ready status False, got %s", readyCond.Status)
	}
}

func TestHandle_ValidationError(t *testing.T) {
	target := newMockTarget()
	k8sClient := newFakeClient()
	validationErr := infraerrors.NewValidationError("spec.rules", "[]", "at least one rule required")

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, validationErr)

	if target.phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected PhaseError, got %s", target.phase)
	}

	readyCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeReady)
	if readyCond == nil {
		t.Fatal("expected Ready condition")
	}
	if readyCond.Reason != vaultv1alpha1.ReasonValidationFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonValidationFailed, readyCond.Reason)
	}
}

func TestHandle_DependencyError(t *testing.T) {
	target := newMockTarget()
	k8sClient := newFakeClient()
	depErr := infraerrors.NewDependencyError("VaultRole/my-role", "VaultConnection", "vault-conn", "not ready")

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, depErr)

	if target.phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected PhaseError, got %s", target.phase)
	}

	readyCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeReady)
	if readyCond == nil {
		t.Fatal("expected Ready condition")
	}
	if readyCond.Reason != vaultv1alpha1.ReasonConnectionNotReady {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonConnectionNotReady, readyCond.Reason)
	}
}

func TestHandle_GenericError(t *testing.T) {
	target := newMockTarget()
	k8sClient := newFakeClient()
	genericErr := errors.New("something unexpected happened")

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, genericErr)

	if target.phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected PhaseError, got %s", target.phase)
	}

	readyCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeReady)
	if readyCond == nil {
		t.Fatal("expected Ready condition")
	}
	if readyCond.Reason != vaultv1alpha1.ReasonFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonFailed, readyCond.Reason)
	}
}

func TestHandle_TransientError(t *testing.T) {
	// TransientError does not have its own classification in Handle —
	// it falls through to the generic "Failed" case. This test documents that behavior.
	target := newMockTarget()
	k8sClient := newFakeClient()
	transientErr := infraerrors.NewTransientError("write policy", errors.New("connection refused"))

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, transientErr)

	if target.phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected PhaseError, got %s", target.phase)
	}

	readyCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeReady)
	if readyCond == nil {
		t.Fatal("expected Ready condition")
	}
	// TransientError falls through to generic handler
	if readyCond.Reason != vaultv1alpha1.ReasonFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonFailed, readyCond.Reason)
	}
}

func TestHandle_NotFoundError(t *testing.T) {
	// NotFoundError also falls through to generic "Failed" case.
	target := newMockTarget()
	k8sClient := newFakeClient()
	notFoundErr := infraerrors.NewNotFoundError("VaultPolicy", "missing-policy", "default")

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, notFoundErr)

	if target.phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected PhaseError, got %s", target.phase)
	}

	readyCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeReady)
	if readyCond == nil {
		t.Fatal("expected Ready condition")
	}
	if readyCond.Reason != vaultv1alpha1.ReasonFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonFailed, readyCond.Reason)
	}
}

func TestHandle_ConnectionError(t *testing.T) {
	target := newMockTarget()
	k8sClient := newFakeClient()
	connErr := infraerrors.NewConnectionError("vault-conn", "https://vault:8200", errors.New("TLS failed"))

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, connErr)

	if target.phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected PhaseError, got %s", target.phase)
	}

	readyCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeReady)
	if readyCond == nil {
		t.Fatal("expected Ready condition")
	}
	if readyCond.Reason != vaultv1alpha1.ReasonFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonFailed, readyCond.Reason)
	}
}

func TestHandle_WrappedError(t *testing.T) {
	// Verify that errors.As works through wrapping — a wrapped ConflictError
	// should still be classified as a conflict.
	target := newMockTarget()
	k8sClient := newFakeClient()
	conflictErr := infraerrors.NewConflictError("policy", "wrapped-policy", "")
	wrappedErr := fmt.Errorf("sync failed: %w", conflictErr)

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	result := Handle(ctx, k8sClient, logr.Discard(), target, wrappedErr)

	if result != wrappedErr {
		t.Error("expected Handle to return the wrapped error, not the inner error")
	}
	if target.phase != vaultv1alpha1.PhaseConflict {
		t.Errorf("expected PhaseConflict for wrapped ConflictError, got %s", target.phase)
	}
}

func TestHandle_SyncedConditionAlwaysFailed(t *testing.T) {
	// Regardless of error type, Synced condition should always have ReasonFailed.
	target := newMockTarget()
	k8sClient := newFakeClient()
	conflictErr := infraerrors.NewConflictError("policy", "test", "")

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, conflictErr)

	syncedCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeSynced)
	if syncedCond == nil {
		t.Fatal("expected Synced condition")
	}
	if syncedCond.Reason != vaultv1alpha1.ReasonFailed {
		t.Errorf("expected Synced reason %s, got %s", vaultv1alpha1.ReasonFailed, syncedCond.Reason)
	}
	if syncedCond.Status != metav1.ConditionFalse {
		t.Errorf("expected Synced status False, got %s", syncedCond.Status)
	}
}

func TestHandle_StatusUpdateFails(t *testing.T) {
	// When the status update fails, Handle should still return the original error
	// and not panic. Using a client without the object pre-created triggers the update failure.
	target := newMockTarget()
	k8sClient := newFakeClient()
	// Intentionally NOT creating the object in K8s — Status().Update() will fail
	genericErr := errors.New("original error")

	result := Handle(context.Background(), k8sClient, logr.Discard(), target, genericErr)

	// Handle should return the original error, not the status update error
	if result != genericErr {
		t.Errorf("expected original error returned, got %v", result)
	}
	// Phase should still be set even if status update fails
	if target.phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase to be set even on update failure, got %s", target.phase)
	}
}

func TestHandle_MessageSetFromError(t *testing.T) {
	target := newMockTarget()
	k8sClient := newFakeClient()
	expectedMsg := "detailed error explanation"
	err := errors.New(expectedMsg)

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, err)

	if target.message != expectedMsg {
		t.Errorf("expected message %q, got %q", expectedMsg, target.message)
	}
}

func TestHandle_ObservedGeneration(t *testing.T) {
	target := newMockTarget()
	target.generation = 5
	k8sClient := newFakeClient()
	err := errors.New("test error")

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, err)

	readyCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeReady)
	if readyCond == nil {
		t.Fatal("expected Ready condition")
	}
	if readyCond.ObservedGeneration != 5 {
		t.Errorf("expected ObservedGeneration 5, got %d", readyCond.ObservedGeneration)
	}
}

func TestHandle_DependencyError_SetsDependencyReadyCondition(t *testing.T) {
	target := newMockTarget()
	k8sClient := newFakeClient()
	depErr := infraerrors.NewDependencyError("default/my-role", "VaultConnection", "vault-conn", "not ready")

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, depErr)

	depCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeDependencyReady)
	if depCond == nil {
		t.Fatal("expected DependencyReady condition for DependencyError")
	}
	if depCond.Status != metav1.ConditionFalse {
		t.Errorf("expected DependencyReady status False, got %s", depCond.Status)
	}
	if depCond.Reason != vaultv1alpha1.ReasonDependencyNotReady {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonDependencyNotReady, depCond.Reason)
	}
	// Message should reference the blocking dependency
	expectedSubstr := "VaultConnection/vault-conn"
	if depCond.Message == "" {
		t.Fatal("expected non-empty DependencyReady message")
	}
	if !strings.Contains(depCond.Message, expectedSubstr) {
		t.Errorf("expected DependencyReady message to contain %q, got %q", expectedSubstr, depCond.Message)
	}
}

func TestHandle_NonDependencyError_NoDependencyReadyCondition(t *testing.T) {
	target := newMockTarget()
	k8sClient := newFakeClient()
	genericErr := errors.New("something broke")

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	_ = Handle(ctx, k8sClient, logr.Discard(), target, genericErr)

	depCond := findCondition(target.conditions, vaultv1alpha1.ConditionTypeDependencyReady)
	if depCond != nil {
		t.Errorf("expected no DependencyReady condition for non-dependency error, "+
			"but found one with reason %s", depCond.Reason)
	}
}

func TestHandle_NilRecorder_NoPanic(t *testing.T) {
	// Verify that passing no recorder (backward compat) doesn't panic on dependency errors
	target := newMockTarget()
	k8sClient := newFakeClient()
	depErr := infraerrors.NewDependencyError("ns/role", "VaultConnection", "conn", "not ready")

	ctx := context.Background()
	_ = k8sClient.Create(ctx, target.object.DeepCopyObject().(client.Object))

	// Call without recorder — should not panic
	result := Handle(ctx, k8sClient, logr.Discard(), target, depErr)
	if result != depErr {
		t.Errorf("expected original error returned, got %v", result)
	}
}

// findCondition returns the first condition matching the given type.
func findCondition(conditions []vaultv1alpha1.Condition, condType string) *vaultv1alpha1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}
