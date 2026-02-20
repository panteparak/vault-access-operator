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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// Helper functions for creating test objects
func newScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	return scheme
}

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(objs...).
		WithStatusSubresource(&vaultv1alpha1.VaultRole{}, &vaultv1alpha1.VaultClusterRole{}).
		Build()
}

func newVaultRole(name, namespace string) *vaultv1alpha1.VaultRole {
	return &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "test-connection",
			ServiceAccounts: []string{"default", "app"},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "read-secrets"},
				{Kind: "VaultClusterPolicy", Name: "global-policy"},
			},
			TokenTTL:    "1h",
			TokenMaxTTL: "24h",
		},
	}
}

func newVaultClusterRole(name string) *vaultv1alpha1.VaultClusterRole {
	return &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			ConnectionRef: "test-connection",
			ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "default", Namespace: "ns1"},
				{Name: "app", Namespace: "ns2"},
			},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "read-secrets", Namespace: "production"},
				{Kind: "VaultClusterPolicy", Name: "global-policy"},
			},
		},
	}
}

const (
	testConnectionName = "test-connection"
	testVaultRoleName  = "default-test-role"
)

func newActiveVaultConnection() *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testConnectionName,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault.example.com:8200",
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseActive,
			Healthy: true,
			Conditions: []vaultv1alpha1.Condition{
				{
					Type:               vaultv1alpha1.ConditionTypeReady,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1,
				},
			},
		},
	}
}

// Tests for NewHandler
func TestNewHandler(t *testing.T) {
	fakeClient := newFakeClient()
	cache := vault.NewClientCache()
	eventBus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(fakeClient, cache, eventBus, logger)

	if handler == nil {
		t.Fatal("expected handler to be non-nil")
		return
	}
	if handler.client == nil {
		t.Error("expected client to be set")
	}
	if handler.clientCache == nil {
		t.Error("expected clientCache to be set")
	}
	if handler.eventBus == nil {
		t.Error("expected eventBus to be set")
	}
}

func TestNewHandler_WithNilEventBus(t *testing.T) {
	fakeClient := newFakeClient()
	cache := vault.NewClientCache()
	logger := logr.Discard()

	handler := NewHandler(fakeClient, cache, nil, logger)

	if handler == nil {
		t.Fatal("expected handler to be non-nil")
		return
	}
	if handler.eventBus != nil {
		t.Error("expected eventBus to be nil")
	}
}

// Tests for resolvePolicyNames
func TestResolvePolicyNames_VaultPolicy(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "read-secrets"},
		{Kind: "VaultPolicy", Name: "write-data", Namespace: "production"},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	policyNames, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"default-read-secrets", "production-write-data"}
	if len(policyNames) != len(expected) {
		t.Fatalf("expected %d policies, got %d", len(expected), len(policyNames))
	}
	for i, exp := range expected {
		if policyNames[i] != exp {
			t.Errorf("policy[%d]: expected %q, got %q", i, exp, policyNames[i])
		}
	}
}

func TestResolvePolicyNames_VaultClusterPolicy(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultClusterPolicy", Name: "admin-policy"},
		{Kind: "VaultClusterPolicy", Name: "readonly-policy"},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	policyNames, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"admin-policy", "readonly-policy"}
	if len(policyNames) != len(expected) {
		t.Fatalf("expected %d policies, got %d", len(expected), len(policyNames))
	}
	for i, exp := range expected {
		if policyNames[i] != exp {
			t.Errorf("policy[%d]: expected %q, got %q", i, exp, policyNames[i])
		}
	}
}

func TestResolvePolicyNames_MixedPolicies(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "myns")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "ns-policy"},
		{Kind: "VaultClusterPolicy", Name: "cluster-policy"},
		{Kind: "VaultPolicy", Name: "other-policy", Namespace: "other"},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	policyNames, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"myns-ns-policy", "cluster-policy", "other-other-policy"}
	if len(policyNames) != len(expected) {
		t.Fatalf("expected %d policies, got %d", len(expected), len(policyNames))
	}
	for i, exp := range expected {
		if policyNames[i] != exp {
			t.Errorf("policy[%d]: expected %q, got %q", i, exp, policyNames[i])
		}
	}
}

func TestResolvePolicyNames_InvalidKind(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "InvalidKind", Name: "policy"},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_, err := handler.resolvePolicyNames(ctx, adapter)
	if err == nil {
		t.Fatal("expected error for invalid policy kind")
	}
	if !infraerrors.IsValidationError(err) {
		t.Errorf("expected ValidationError, got %T", err)
	}
}

func TestResolvePolicyNames_ClusterRoleMissingNamespace(t *testing.T) {
	ctx := context.Background()
	clusterRole := newVaultClusterRole("test-cluster-role")
	clusterRole.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "policy-without-namespace"},
	}

	fakeClient := newFakeClient(clusterRole)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	_, err := handler.resolvePolicyNames(ctx, adapter)
	if err == nil {
		t.Fatal("expected error for missing namespace in cluster-scoped role")
	}
	if !infraerrors.IsValidationError(err) {
		t.Errorf("expected ValidationError, got %T", err)
	}
}

func TestResolvePolicyNames_EmptyPolicies(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	policyNames, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policyNames) != 0 {
		t.Errorf("expected 0 policies, got %d", len(policyNames))
	}
}

// Tests for buildRoleData
func TestBuildRoleData_VaultRole(t *testing.T) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	policyNames := []string{"default-policy", "global-policy"}
	serviceAccountBindings := adapter.GetServiceAccountBindings()

	roleData := handler.buildRoleData(adapter, policyNames, serviceAccountBindings)

	// Check policies
	policies, ok := roleData["policies"].([]string)
	if !ok {
		t.Fatal("expected policies to be []string")
	}
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}

	// Check bound service account names
	saNames, ok := roleData["bound_service_account_names"].([]string)
	if !ok {
		t.Fatal("expected bound_service_account_names to be []string")
	}
	if len(saNames) != 2 {
		t.Errorf("expected 2 service account names, got %d", len(saNames))
	}
	expectedNames := []string{"default", "app"}
	for i, expected := range expectedNames {
		if saNames[i] != expected {
			t.Errorf("sa name[%d]: expected %q, got %q", i, expected, saNames[i])
		}
	}

	// Check bound service account namespaces
	saNamespaces, ok := roleData["bound_service_account_namespaces"].([]string)
	if !ok {
		t.Fatal("expected bound_service_account_namespaces to be []string")
	}
	if len(saNamespaces) != 1 {
		t.Errorf("expected 1 namespace, got %d", len(saNamespaces))
	}
	if saNamespaces[0] != "default" {
		t.Errorf("expected namespace 'default', got %q", saNamespaces[0])
	}

	// Check TTL settings
	if roleData["token_ttl"] != "1h" {
		t.Errorf("expected token_ttl '1h', got %v", roleData["token_ttl"])
	}
	if roleData["token_max_ttl"] != "24h" {
		t.Errorf("expected token_max_ttl '24h', got %v", roleData["token_max_ttl"])
	}
}

func TestBuildRoleData_VaultClusterRole(t *testing.T) {
	clusterRole := newVaultClusterRole("test-cluster-role")
	fakeClient := newFakeClient(clusterRole)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	policyNames := []string{"cluster-policy"}
	serviceAccountBindings := adapter.GetServiceAccountBindings()

	roleData := handler.buildRoleData(adapter, policyNames, serviceAccountBindings)

	// Check bound service account namespaces (should have 2 different namespaces)
	saNamespaces, ok := roleData["bound_service_account_namespaces"].([]string)
	if !ok {
		t.Fatal("expected bound_service_account_namespaces to be []string")
	}
	if len(saNamespaces) != 2 {
		t.Errorf("expected 2 namespaces, got %d", len(saNamespaces))
	}
}

func TestBuildRoleData_NoTTL(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.TokenTTL = ""
	role.Spec.TokenMaxTTL = ""

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData := handler.buildRoleData(adapter, []string{}, []string{"default/app"})

	if _, exists := roleData["token_ttl"]; exists {
		t.Error("expected token_ttl to not be set")
	}
	if _, exists := roleData["token_max_ttl"]; exists {
		t.Error("expected token_max_ttl to not be set")
	}
}

func TestBuildRoleData_MultipleNamespaces(t *testing.T) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	bindings := []string{"ns1/sa1", "ns2/sa2", "ns1/sa3", "ns3/sa4"}
	roleData := handler.buildRoleData(adapter, []string{"policy"}, bindings)

	saNamespaces, ok := roleData["bound_service_account_namespaces"].([]string)
	if !ok {
		t.Fatal("expected bound_service_account_namespaces to be []string")
	}
	// Should deduplicate namespaces
	if len(saNamespaces) != 3 {
		t.Errorf("expected 3 unique namespaces, got %d: %v", len(saNamespaces), saNamespaces)
	}
}

func TestBuildRoleData_EmptyBindings(t *testing.T) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData := handler.buildRoleData(adapter, []string{"policy"}, []string{})

	saNames, ok := roleData["bound_service_account_names"].([]string)
	if !ok {
		t.Fatal("expected bound_service_account_names to be []string")
	}
	if len(saNames) != 0 {
		t.Errorf("expected 0 service account names, got %d", len(saNames))
	}
}

// Tests for handleSyncError
func TestHandleSyncError_ConflictError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	conflictErr := infraerrors.NewConflictError("role", "test-role", "already managed by other")

	err := handler.handleSyncError(ctx, adapter, conflictErr)
	if err == nil {
		t.Fatal("expected error to be returned")
	}

	if adapter.GetPhase() != vaultv1alpha1.PhaseConflict {
		t.Errorf("expected phase Conflict, got %s", adapter.GetPhase())
	}

	// Check condition was set
	conditions := adapter.GetConditions()
	var readyCondition *vaultv1alpha1.Condition
	for i := range conditions {
		if conditions[i].Type == vaultv1alpha1.ConditionTypeReady {
			readyCondition = &conditions[i]
			break
		}
	}
	if readyCondition == nil {
		t.Fatal("expected Ready condition to be set")
		return
	}
	if readyCondition.Status != metav1.ConditionFalse {
		t.Errorf("expected Ready condition status False, got %s", readyCondition.Status)
	}
	if readyCondition.Reason != vaultv1alpha1.ReasonConflict {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonConflict, readyCondition.Reason)
	}
}

func TestHandleSyncError_DependencyError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	depErr := infraerrors.NewDependencyError("role", "VaultConnection", "test-conn", "not ready")

	err := handler.handleSyncError(ctx, adapter, depErr)
	if err == nil {
		t.Fatal("expected error to be returned")
	}

	if adapter.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", adapter.GetPhase())
	}

	conditions := adapter.GetConditions()
	var readyCondition *vaultv1alpha1.Condition
	for i := range conditions {
		if conditions[i].Type == vaultv1alpha1.ConditionTypeReady {
			readyCondition = &conditions[i]
			break
		}
	}
	if readyCondition == nil {
		t.Fatal("expected Ready condition to be set")
		return
	}
	if readyCondition.Reason != vaultv1alpha1.ReasonConnectionNotReady {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonConnectionNotReady, readyCondition.Reason)
	}
}

func TestHandleSyncError_ValidationError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	validationErr := infraerrors.NewValidationError("policies", "invalid", "invalid policy kind")

	err := handler.handleSyncError(ctx, adapter, validationErr)
	if err == nil {
		t.Fatal("expected error to be returned")
	}

	if adapter.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", adapter.GetPhase())
	}

	conditions := adapter.GetConditions()
	var readyCondition *vaultv1alpha1.Condition
	for i := range conditions {
		if conditions[i].Type == vaultv1alpha1.ConditionTypeReady {
			readyCondition = &conditions[i]
			break
		}
	}
	if readyCondition == nil {
		t.Fatal("expected Ready condition to be set")
		return
	}
	if readyCondition.Reason != vaultv1alpha1.ReasonValidationFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonValidationFailed, readyCondition.Reason)
	}
}

func TestHandleSyncError_GenericError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	genericErr := errors.New("some generic error")

	err := handler.handleSyncError(ctx, adapter, genericErr)
	if err == nil {
		t.Fatal("expected error to be returned")
	}

	if adapter.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", adapter.GetPhase())
	}

	conditions := adapter.GetConditions()
	var readyCondition *vaultv1alpha1.Condition
	for i := range conditions {
		if conditions[i].Type == vaultv1alpha1.ConditionTypeReady {
			readyCondition = &conditions[i]
			break
		}
	}
	if readyCondition == nil {
		t.Fatal("expected Ready condition to be set")
		return
	}
	if readyCondition.Reason != vaultv1alpha1.ReasonFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonFailed, readyCondition.Reason)
	}
}

func TestHandleSyncError_SetsMessage(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	testErr := errors.New("test error message")

	_ = handler.handleSyncError(ctx, adapter, testErr)

	// Message should be set from error
	// The adapter's message is set internally
	conditions := adapter.GetConditions()
	var syncedCondition *vaultv1alpha1.Condition
	for i := range conditions {
		if conditions[i].Type == vaultv1alpha1.ConditionTypeSynced {
			syncedCondition = &conditions[i]
			break
		}
	}
	if syncedCondition == nil {
		t.Fatal("expected Synced condition to be set")
		return
	}
	if syncedCondition.Status != metav1.ConditionFalse {
		t.Errorf("expected Synced condition status False, got %s", syncedCondition.Status)
	}
}

func TestHandleSyncError_TransientError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	transientErr := infraerrors.NewTransientError("write role", errors.New("network error"))

	err := handler.handleSyncError(ctx, adapter, transientErr)
	if err == nil {
		t.Fatal("expected error to be returned")
	}

	if adapter.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", adapter.GetPhase())
	}

	conditions := adapter.GetConditions()
	var readyCondition *vaultv1alpha1.Condition
	for i := range conditions {
		if conditions[i].Type == vaultv1alpha1.ConditionTypeReady {
			readyCondition = &conditions[i]
			break
		}
	}
	if readyCondition == nil {
		t.Fatal("expected Ready condition to be set")
		return
	}
	// Transient errors should get ReasonFailed (not a specific reason for transient)
	if readyCondition.Reason != vaultv1alpha1.ReasonFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonFailed, readyCondition.Reason)
	}
}

// Tests for setCondition
func TestSetCondition_NewCondition(t *testing.T) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "test message")

	conditions := adapter.GetConditions()
	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conditions))
	}

	cond := conditions[0]
	if cond.Type != vaultv1alpha1.ConditionTypeReady {
		t.Errorf("expected type %s, got %s", vaultv1alpha1.ConditionTypeReady, cond.Type)
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("expected status True, got %s", cond.Status)
	}
	if cond.Reason != vaultv1alpha1.ReasonSucceeded {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonSucceeded, cond.Reason)
	}
	if cond.Message != "test message" {
		t.Errorf("expected message 'test message', got %s", cond.Message)
	}
}

func TestSetCondition_UpdateExisting(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Status.Conditions = []vaultv1alpha1.Condition{
		{
			Type:    vaultv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionFalse,
			Reason:  vaultv1alpha1.ReasonFailed,
			Message: "old message",
		},
	}
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "new message")

	conditions := adapter.GetConditions()
	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conditions))
	}

	cond := conditions[0]
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("expected status True, got %s", cond.Status)
	}
	if cond.Reason != vaultv1alpha1.ReasonSucceeded {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonSucceeded, cond.Reason)
	}
	if cond.Message != "new message" {
		t.Errorf("expected message 'new message', got %s", cond.Message)
	}
}

func TestSetCondition_UpdateSameStatus(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Status.Conditions = []vaultv1alpha1.Condition{
		{
			Type:               vaultv1alpha1.ConditionTypeReady,
			Status:             metav1.ConditionTrue,
			Reason:             vaultv1alpha1.ReasonSucceeded,
			Message:            "old message",
			LastTransitionTime: metav1.Now(),
		},
	}
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "new message")

	conditions := adapter.GetConditions()
	cond := conditions[0]
	// When status doesn't change, reason and message are updated
	if cond.Message != "new message" {
		t.Errorf("expected message 'new message', got %s", cond.Message)
	}
}

func TestSetCondition_MultipleConditions(t *testing.T) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "ready")
	handler.setCondition(adapter, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "synced")

	conditions := adapter.GetConditions()
	if len(conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(conditions))
	}
}

func TestSetCondition_ObservedGeneration(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Generation = 5
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "test")

	conditions := adapter.GetConditions()
	if conditions[0].ObservedGeneration != 5 {
		t.Errorf("expected ObservedGeneration 5, got %d", conditions[0].ObservedGeneration)
	}
}

// Tests for getVaultClient
func TestGetVaultClient_ConnectionNotFound(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role) // No connection

	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_, err := handler.getVaultClient(ctx, adapter)
	if err == nil {
		t.Fatal("expected error for missing connection")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T", err)
	}
}

func TestGetVaultClient_ConnectionNotActive(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	conn := newActiveVaultConnection()
	conn.Status.Phase = vaultv1alpha1.PhasePending // Not active

	fakeClient := newFakeClient(role, conn)

	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_, err := handler.getVaultClient(ctx, adapter)
	if err == nil {
		t.Fatal("expected error for non-active connection")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T", err)
	}
}

func TestGetVaultClient_ClientNotInCache(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	emptyCache := vault.NewClientCache() // Empty cache

	handler := NewHandler(fakeClient, emptyCache, nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_, err := handler.getVaultClient(ctx, adapter)
	if err == nil {
		t.Fatal("expected error for client not in cache")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T", err)
	}
}

func TestGetVaultClient_ConnectionPhaseError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	conn := newActiveVaultConnection()
	conn.Status.Phase = vaultv1alpha1.PhaseError

	fakeClient := newFakeClient(role, conn)

	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_, err := handler.getVaultClient(ctx, adapter)
	if err == nil {
		t.Fatal("expected error for error phase connection")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T", err)
	}
}

// Tests for CleanupRole
func TestCleanupRole_PublishesRoleDeletedEvent(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Status.VaultRoleName = testVaultRoleName
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	eventBus := events.NewEventBus(logr.Discard())

	var receivedEvent events.RoleDeleted
	var eventReceived bool
	var mu sync.Mutex
	events.Subscribe[events.RoleDeleted](eventBus, func(_ context.Context, e events.RoleDeleted) error {
		mu.Lock()
		defer mu.Unlock()
		receivedEvent = e
		eventReceived = true
		return nil
	})

	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, eventBus, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_ = handler.CleanupRole(ctx, adapter)

	// Wait for async event
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if !eventReceived {
		t.Error("expected RoleDeleted event to be published")
	}
	if receivedEvent.RoleName != testVaultRoleName {
		t.Errorf("expected role name 'testVaultRoleName', got %q", receivedEvent.RoleName)
	}
	if receivedEvent.Resource.Name != "test-role" {
		t.Errorf("expected resource name 'test-role', got %q", receivedEvent.Resource.Name)
	}
	if receivedEvent.Resource.Namespace != "default" {
		t.Errorf("expected namespace 'default', got %q", receivedEvent.Resource.Namespace)
	}
}

func TestCleanupRole_NoEventBus(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Status.VaultRoleName = testVaultRoleName
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, nil, logr.Discard()) // nil event bus
	adapter := domain.NewVaultRoleAdapter(role)

	// Should not panic with nil event bus
	err := handler.CleanupRole(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCleanupRole_SetsPhaseToDeleting(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Status.VaultRoleName = testVaultRoleName
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_ = handler.CleanupRole(ctx, adapter)

	if adapter.GetPhase() != vaultv1alpha1.PhaseDeleting {
		t.Errorf("expected phase Deleting, got %s", adapter.GetPhase())
	}
}

func TestCleanupRole_DefaultAuthPath(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.AuthPath = "" // Empty to use default
	role.Status.VaultRoleName = testVaultRoleName
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	eventBus := events.NewEventBus(logr.Discard())

	var receivedEvent events.RoleDeleted
	events.Subscribe[events.RoleDeleted](eventBus, func(_ context.Context, e events.RoleDeleted) error {
		receivedEvent = e
		return nil
	})

	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, eventBus, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_ = handler.CleanupRole(ctx, adapter)

	// Wait for async event
	time.Sleep(100 * time.Millisecond)

	if receivedEvent.AuthPath != vault.DefaultKubernetesAuthPath {
		t.Errorf("expected auth path %q, got %q", vault.DefaultKubernetesAuthPath, receivedEvent.AuthPath)
	}
}

func TestCleanupRole_CustomAuthPath(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.AuthPath = "auth/custom-k8s"
	role.Status.VaultRoleName = testVaultRoleName
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	eventBus := events.NewEventBus(logr.Discard())

	var receivedEvent events.RoleDeleted
	events.Subscribe[events.RoleDeleted](eventBus, func(_ context.Context, e events.RoleDeleted) error {
		receivedEvent = e
		return nil
	})

	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, eventBus, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_ = handler.CleanupRole(ctx, adapter)

	// Wait for async event
	time.Sleep(100 * time.Millisecond)

	if receivedEvent.AuthPath != "auth/custom-k8s" {
		t.Errorf("expected auth path 'auth/custom-k8s', got %q", receivedEvent.AuthPath)
	}
}

func TestCleanupRole_ClusterRole(t *testing.T) {
	ctx := context.Background()
	clusterRole := newVaultClusterRole("test-cluster-role")
	clusterRole.Status.VaultRoleName = "test-cluster-role"
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(clusterRole, conn)
	eventBus := events.NewEventBus(logr.Discard())

	var receivedEvent events.RoleDeleted
	var eventReceived bool
	events.Subscribe[events.RoleDeleted](eventBus, func(_ context.Context, e events.RoleDeleted) error {
		receivedEvent = e
		eventReceived = true
		return nil
	})

	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, eventBus, logr.Discard())
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	_ = handler.CleanupRole(ctx, adapter)

	// Wait for async event
	time.Sleep(100 * time.Millisecond)

	if !eventReceived {
		t.Error("expected RoleDeleted event to be published")
	}
	if receivedEvent.Resource.ClusterScoped != true {
		t.Error("expected ClusterScoped to be true for VaultClusterRole")
	}
	if receivedEvent.Resource.Namespace != "" {
		t.Errorf("expected empty namespace for cluster role, got %q", receivedEvent.Resource.Namespace)
	}
}

// Test service account binding extraction
func TestGetServiceAccountBindings_VaultRole(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	bindings := adapter.GetServiceAccountBindings()

	expected := []string{"default/default", "default/app"}
	if len(bindings) != len(expected) {
		t.Fatalf("expected %d bindings, got %d", len(expected), len(bindings))
	}
	for i, exp := range expected {
		if bindings[i] != exp {
			t.Errorf("binding[%d]: expected %q, got %q", i, exp, bindings[i])
		}
	}
}

func TestGetServiceAccountBindings_VaultClusterRole(t *testing.T) {
	clusterRole := newVaultClusterRole("test-cluster-role")
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	bindings := adapter.GetServiceAccountBindings()

	expected := []string{"ns1/default", "ns2/app"}
	if len(bindings) != len(expected) {
		t.Fatalf("expected %d bindings, got %d", len(expected), len(bindings))
	}
	for i, exp := range expected {
		if bindings[i] != exp {
			t.Errorf("binding[%d]: expected %q, got %q", i, exp, bindings[i])
		}
	}
}

// Test default auth path
func TestDefaultAuthPath(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.AuthPath = "" // Empty auth path

	adapter := domain.NewVaultRoleAdapter(role)
	authPath := adapter.GetAuthPath()

	if authPath != "" {
		t.Errorf("expected empty auth path from adapter, got %q", authPath)
	}

	// The handler should use the default
	if vault.DefaultKubernetesAuthPath != "auth/kubernetes" {
		t.Errorf("expected default auth path 'auth/kubernetes', got %q", vault.DefaultKubernetesAuthPath)
	}
}

func TestCustomAuthPath(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.AuthPath = "auth/custom-kubernetes"

	adapter := domain.NewVaultRoleAdapter(role)
	authPath := adapter.GetAuthPath()

	if authPath != "auth/custom-kubernetes" {
		t.Errorf("expected auth path 'auth/custom-kubernetes', got %q", authPath)
	}
}

// Test vault role name generation
func TestVaultRoleName_VaultRole(t *testing.T) {
	role := newVaultRole("my-role", "production")
	adapter := domain.NewVaultRoleAdapter(role)

	vaultRoleName := adapter.GetVaultRoleName()
	if vaultRoleName != "production-my-role" {
		t.Errorf("expected 'production-my-role', got %q", vaultRoleName)
	}
}

func TestVaultRoleName_VaultClusterRole(t *testing.T) {
	clusterRole := newVaultClusterRole("global-role")
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	vaultRoleName := adapter.GetVaultRoleName()
	if vaultRoleName != "global-role" {
		t.Errorf("expected 'global-role', got %q", vaultRoleName)
	}
}

// Test K8s resource identifier
func TestK8sResourceIdentifier_VaultRole(t *testing.T) {
	role := newVaultRole("my-role", "production")
	adapter := domain.NewVaultRoleAdapter(role)

	identifier := adapter.GetK8sResourceIdentifier()
	if identifier != "production/my-role" {
		t.Errorf("expected 'production/my-role', got %q", identifier)
	}
}

func TestK8sResourceIdentifier_VaultClusterRole(t *testing.T) {
	clusterRole := newVaultClusterRole("global-role")
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	identifier := adapter.GetK8sResourceIdentifier()
	if identifier != "global-role" {
		t.Errorf("expected 'global-role', got %q", identifier)
	}
}

// Test IsNamespaced
func TestIsNamespaced_VaultRole(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	if !adapter.IsNamespaced() {
		t.Error("expected VaultRole to be namespaced")
	}
}

func TestIsNamespaced_VaultClusterRole(t *testing.T) {
	clusterRole := newVaultClusterRole("test-cluster-role")
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	if adapter.IsNamespaced() {
		t.Error("expected VaultClusterRole to NOT be namespaced")
	}
}

// Test conflict policy accessor
func TestGetConflictPolicy_Default(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.ConflictPolicy = "" // Empty to test default behavior
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetConflictPolicy()
	if policy != "" {
		t.Errorf("expected empty conflict policy, got %q", policy)
	}
}

func TestGetConflictPolicy_Fail(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.ConflictPolicy = vaultv1alpha1.ConflictPolicyFail
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetConflictPolicy()
	if policy != vaultv1alpha1.ConflictPolicyFail {
		t.Errorf("expected ConflictPolicyFail, got %q", policy)
	}
}

func TestGetConflictPolicy_Adopt(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.ConflictPolicy = vaultv1alpha1.ConflictPolicyAdopt
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetConflictPolicy()
	if policy != vaultv1alpha1.ConflictPolicyAdopt {
		t.Errorf("expected ConflictPolicyAdopt, got %q", policy)
	}
}

// Test deletion policy accessor
func TestGetDeletionPolicy_Default(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.DeletionPolicy = "" // Empty
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetDeletionPolicy()
	if policy != "" {
		t.Errorf("expected empty deletion policy, got %q", policy)
	}
}

func TestGetDeletionPolicy_Delete(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyDelete
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetDeletionPolicy()
	if policy != vaultv1alpha1.DeletionPolicyDelete {
		t.Errorf("expected DeletionPolicyDelete, got %q", policy)
	}
}

func TestGetDeletionPolicy_Retain(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyRetain
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetDeletionPolicy()
	if policy != vaultv1alpha1.DeletionPolicyRetain {
		t.Errorf("expected DeletionPolicyRetain, got %q", policy)
	}
}

// Test TTL accessors
func TestGetTokenTTL(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.TokenTTL = "2h"
	adapter := domain.NewVaultRoleAdapter(role)

	ttl := adapter.GetTokenTTL()
	if ttl != "2h" {
		t.Errorf("expected '2h', got %q", ttl)
	}
}

func TestGetTokenMaxTTL(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.TokenMaxTTL = "48h"
	adapter := domain.NewVaultRoleAdapter(role)

	maxTTL := adapter.GetTokenMaxTTL()
	if maxTTL != "48h" {
		t.Errorf("expected '48h', got %q", maxTTL)
	}
}

// Test status mutators
func TestSetPhase(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	if adapter.GetPhase() != vaultv1alpha1.PhaseActive {
		t.Errorf("expected PhaseActive, got %s", adapter.GetPhase())
	}

	adapter.SetPhase(vaultv1alpha1.PhaseError)
	if adapter.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("expected PhaseError, got %s", adapter.GetPhase())
	}
}

func TestSetVaultRoleName(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetVaultRoleName(testVaultRoleName)
	if role.Status.VaultRoleName != testVaultRoleName {
		t.Errorf("expected 'testVaultRoleName', got %q", role.Status.VaultRoleName)
	}
}

func TestSetManaged(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetManaged(true)
	if !role.Status.Managed {
		t.Error("expected Managed to be true")
	}

	adapter.SetManaged(false)
	if role.Status.Managed {
		t.Error("expected Managed to be false")
	}
}

func TestSetBoundServiceAccounts(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	accounts := []string{"default/sa1", "default/sa2"}
	adapter.SetBoundServiceAccounts(accounts)

	if len(role.Status.BoundServiceAccounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(role.Status.BoundServiceAccounts))
	}
	if role.Status.BoundServiceAccounts[0] != "default/sa1" {
		t.Errorf("expected 'default/sa1', got %q", role.Status.BoundServiceAccounts[0])
	}
}

func TestSetResolvedPolicies(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	policies := []string{"policy1", "policy2"}
	adapter.SetResolvedPolicies(policies)

	if len(role.Status.ResolvedPolicies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(role.Status.ResolvedPolicies))
	}
	if role.Status.ResolvedPolicies[0] != "policy1" {
		t.Errorf("expected 'policy1', got %q", role.Status.ResolvedPolicies[0])
	}
}

func TestSetLastSyncedAt(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	now := metav1.Now()
	adapter.SetLastSyncedAt(&now)

	if role.Status.LastSyncedAt == nil {
		t.Fatal("expected LastSyncedAt to be set")
	}
	if !role.Status.LastSyncedAt.Equal(&now) {
		t.Error("expected LastSyncedAt to match")
	}
}

func TestSetRetryCount(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetRetryCount(5)
	if adapter.GetRetryCount() != 5 {
		t.Errorf("expected retry count 5, got %d", adapter.GetRetryCount())
	}
}

func TestSetMessage(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetMessage("test message")
	if role.Status.Message != "test message" {
		t.Errorf("expected 'test message', got %q", role.Status.Message)
	}
}

// Benchmark tests
func BenchmarkResolvePolicyNames(b *testing.B) {
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "policy1"},
		{Kind: "VaultPolicy", Name: "policy2"},
		{Kind: "VaultClusterPolicy", Name: "cluster-policy"},
	}
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.resolvePolicyNames(ctx, adapter)
	}
}

func BenchmarkBuildRoleData(b *testing.B) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)
	policyNames := []string{"policy1", "policy2"}
	bindings := []string{"default/sa1", "default/sa2", "other/sa3"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.buildRoleData(adapter, policyNames, bindings)
	}
}

func BenchmarkSetCondition(b *testing.B) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			vaultv1alpha1.ReasonSucceeded, "test message")
	}
}

// Tests for updateStatusWithRetry
func TestUpdateStatusWithRetry_Success_VaultRole(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	// Update status using retry
	err := handler.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
		a.SetPhase(vaultv1alpha1.PhaseActive)
		a.SetMessage("sync completed")
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the status was updated in the API server
	var updatedRole vaultv1alpha1.VaultRole
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	if updatedRole.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", updatedRole.Status.Phase)
	}
	if updatedRole.Status.Message != "sync completed" {
		t.Errorf("expected message 'sync completed', got %q", updatedRole.Status.Message)
	}
}

func TestUpdateStatusWithRetry_Success_VaultClusterRole(t *testing.T) {
	ctx := context.Background()
	clusterRole := newVaultClusterRole("test-cluster-role")
	fakeClient := newFakeClient(clusterRole)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	// Update status using retry
	err := handler.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
		a.SetPhase(vaultv1alpha1.PhaseActive)
		a.SetVaultRoleName("test-cluster-role")
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the status was updated in the API server
	var updatedRole vaultv1alpha1.VaultClusterRole
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(clusterRole), &updatedRole); err != nil {
		t.Fatalf("failed to get updated cluster role: %v", err)
	}

	if updatedRole.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", updatedRole.Status.Phase)
	}
	if updatedRole.Status.VaultRoleName != "test-cluster-role" {
		t.Errorf("expected vault role name 'test-cluster-role', got %q", updatedRole.Status.VaultRoleName)
	}
}

func TestUpdateStatusWithRetry_UpdatesLatestVersion(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	// First update
	err := handler.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
		a.SetPhase(vaultv1alpha1.PhaseSyncing)
	})
	if err != nil {
		t.Fatalf("first update failed: %v", err)
	}

	// Second update (adapter still has old resourceVersion, but retry should handle it)
	err = handler.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
		a.SetPhase(vaultv1alpha1.PhaseActive)
		a.SetMessage("second update")
	})
	if err != nil {
		t.Fatalf("second update failed: %v", err)
	}

	// Verify final status
	var updatedRole vaultv1alpha1.VaultRole
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	if updatedRole.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", updatedRole.Status.Phase)
	}
	if updatedRole.Status.Message != "second update" {
		t.Errorf("expected message 'second update', got %q", updatedRole.Status.Message)
	}
}

func TestUpdateStatusWithRetry_PreservesExistingStatus(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Status.VaultRoleName = "existing-vault-role"
	role.Status.Managed = true
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	// Update only the phase, keeping other fields
	err := handler.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
		a.SetPhase(vaultv1alpha1.PhaseActive)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify existing status is preserved
	var updatedRole vaultv1alpha1.VaultRole
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	if updatedRole.Status.VaultRoleName != "existing-vault-role" {
		t.Errorf("expected vault role name 'existing-vault-role', got %q", updatedRole.Status.VaultRoleName)
	}
	if !updatedRole.Status.Managed {
		t.Error("expected Managed to remain true")
	}
}

func TestUpdateStatusWithRetry_NotFound(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("non-existent-role", "default")
	fakeClient := newFakeClient() // Empty client, role doesn't exist
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
		a.SetPhase(vaultv1alpha1.PhaseActive)
	})

	if err == nil {
		t.Fatal("expected error for non-existent role")
	}
}

func TestUpdateStatusWithRetry_MultipleFields(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	now := metav1.Now()
	err := handler.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
		a.SetPhase(vaultv1alpha1.PhaseActive)
		a.SetVaultRoleName("default-test-role")
		a.SetManaged(true)
		a.SetResolvedPolicies([]string{"policy1", "policy2"})
		a.SetBoundServiceAccounts([]string{"default/sa1", "default/sa2"})
		a.SetLastSyncedAt(&now)
		a.SetMessage("all fields updated")
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all fields
	var updatedRole vaultv1alpha1.VaultRole
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	if updatedRole.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", updatedRole.Status.Phase)
	}
	if updatedRole.Status.VaultRoleName != "default-test-role" {
		t.Errorf("expected vault role name 'default-test-role', got %q", updatedRole.Status.VaultRoleName)
	}
	if !updatedRole.Status.Managed {
		t.Error("expected Managed to be true")
	}
	if len(updatedRole.Status.ResolvedPolicies) != 2 {
		t.Errorf("expected 2 resolved policies, got %d", len(updatedRole.Status.ResolvedPolicies))
	}
	if len(updatedRole.Status.BoundServiceAccounts) != 2 {
		t.Errorf("expected 2 bound service accounts, got %d", len(updatedRole.Status.BoundServiceAccounts))
	}
	if updatedRole.Status.LastSyncedAt == nil {
		t.Error("expected LastSyncedAt to be set")
	}
	if updatedRole.Status.Message != "all fields updated" {
		t.Errorf("expected message 'all fields updated', got %q", updatedRole.Status.Message)
	}
}

// --- Cross-namespace binding validation tests (Gap 5) ---

func TestResolvePolicyNames_DuplicatePolicyRefs(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "read-secrets"},
		{Kind: "VaultPolicy", Name: "read-secrets"}, // duplicate
		{Kind: "VaultClusterPolicy", Name: "global"},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	policyNames, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Current implementation doesn't deduplicate — document this behavior.
	// Both references resolve to "default-read-secrets".
	if len(policyNames) != 3 {
		t.Errorf("expected 3 policy names (duplicates not deduped), got %d: %v", len(policyNames), policyNames)
	}
}

func TestResolvePolicyNames_EmptyPolicyName(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: ""},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	policyNames, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Empty name still resolves (to "default-"), documenting the behavior
	if len(policyNames) != 1 {
		t.Errorf("expected 1 policy name, got %d", len(policyNames))
	}
}

func TestResolvePolicyNames_ClusterRoleWithNamespacedPolicyExplicitNamespace(t *testing.T) {
	ctx := context.Background()
	role := newVaultClusterRole("cluster-role")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "read-secrets", Namespace: "production"},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultClusterRoleAdapter(role)

	policyNames, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policyNames) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policyNames))
	}
	if policyNames[0] != "production-read-secrets" {
		t.Errorf("expected 'production-read-secrets', got %q", policyNames[0])
	}
}

func TestResolvePolicyNames_NamespacedRoleCrossNamespace(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "read-secrets", Namespace: "other-ns"},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	policyNames, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Namespaced role can reference policies in other namespaces
	if len(policyNames) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policyNames))
	}
	if policyNames[0] != "other-ns-read-secrets" {
		t.Errorf("expected 'other-ns-read-secrets', got %q", policyNames[0])
	}
}
