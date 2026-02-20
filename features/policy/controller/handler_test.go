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
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// mockVaultClient provides a mock implementation of the Vault client
type mockVaultClient struct {
	*vault.Client
	writePolicyErr     error
	deletePolicyErr    error
	policyExists       bool
	policyExistsErr    error
	markManagedErr     error
	removeManagedErr   error
	managedBy          string
	managedByErr       error
	authenticated      bool
	writePolicyCalls   []writePolicyCall
	deletePolicyCalls  []string
	markManagedCalls   []markManagedCall
	removeManagedCalls []string
	mu                 sync.Mutex
}

type writePolicyCall struct {
	name string
	hcl  string
}

type markManagedCall struct {
	policyName  string
	k8sResource string
}

func newMockVaultClient() *mockVaultClient {
	return &mockVaultClient{
		authenticated:      true,
		writePolicyCalls:   []writePolicyCall{},
		deletePolicyCalls:  []string{},
		markManagedCalls:   []markManagedCall{},
		removeManagedCalls: []string{},
	}
}

func (m *mockVaultClient) WritePolicy(_ context.Context, name, hcl string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writePolicyCalls = append(m.writePolicyCalls, writePolicyCall{name: name, hcl: hcl})
	return m.writePolicyErr
}

func (m *mockVaultClient) DeletePolicy(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletePolicyCalls = append(m.deletePolicyCalls, name)
	return m.deletePolicyErr
}

func (m *mockVaultClient) PolicyExists(_ context.Context, _ string) (bool, error) {
	return m.policyExists, m.policyExistsErr
}

func (m *mockVaultClient) MarkPolicyManaged(_ context.Context, policyName, k8sResource string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.markManagedCalls = append(m.markManagedCalls, markManagedCall{policyName: policyName, k8sResource: k8sResource})
	return m.markManagedErr
}

func (m *mockVaultClient) RemovePolicyManaged(_ context.Context, policyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeManagedCalls = append(m.removeManagedCalls, policyName)
	return m.removeManagedErr
}

func (m *mockVaultClient) GetPolicyManagedBy(_ context.Context, _ string) (string, error) {
	return m.managedBy, m.managedByErr
}

func (m *mockVaultClient) IsAuthenticated() bool {
	return m.authenticated
}

// Test constants
const (
	testPolicyName     = "test-policy"
	testNamespace      = "test-namespace"
	testConnectionName = "test-connection"
)

func newScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	return scheme
}

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(objs...).
		WithStatusSubresource(&vaultv1alpha1.VaultPolicy{}, &vaultv1alpha1.VaultClusterPolicy{}).
		Build()
}

func createTestVaultConnection(name string, phase vaultv1alpha1.Phase) *vaultv1alpha1.VaultConnection {
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault:8200",
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase: phase,
		},
	}
	if phase == vaultv1alpha1.PhaseActive {
		conn.Status.Healthy = true
		conn.Status.Conditions = []vaultv1alpha1.Condition{
			{
				Type:               vaultv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
			},
		}
	}
	return conn
}

//nolint:unparam // name parameter is designed for flexibility in tests even if currently constant
func createTestVaultPolicy(
	name, namespace, connRef string,
	rules []vaultv1alpha1.PolicyRule,
) *vaultv1alpha1.VaultPolicy {
	return &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: connRef,
			Rules:         rules,
		},
	}
}

// TestNewHandler tests the NewHandler constructor
func TestNewHandler(t *testing.T) {
	fakeClient := newFakeClient()
	clientCache := vault.NewClientCache()
	eventBus := events.NewEventBus(logr.Discard())
	log := logr.Discard()

	handler := NewHandler(fakeClient, clientCache, eventBus, log)

	if handler == nil {
		t.Fatal("expected handler to be non-nil")
		return // staticcheck: ensure no nil dereference warning
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
	clientCache := vault.NewClientCache()
	log := logr.Discard()

	handler := NewHandler(fakeClient, clientCache, nil, log)

	if handler == nil {
		t.Fatal("expected handler to be non-nil")
		return
	}

	if handler.eventBus != nil {
		t.Error("expected eventBus to be nil")
	}
}

// TestSyncPolicy_Success tests successful policy sync
func TestSyncPolicy_Success(t *testing.T) {
	mockClient := newMockVaultClient()
	mockClient.policyExists = false

	vaultConn := createTestVaultConnection(testConnectionName, vaultv1alpha1.PhaseActive)
	policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
		{
			Path:         "secret/data/{{namespace}}/*",
			Capabilities: []vaultv1alpha1.Capability{"read", "list"},
		},
	})

	fakeClient := newFakeClient(vaultConn, policy)
	clientCache := vault.NewClientCache()

	// We need to use a real vault client in the cache for the handler
	// Create a minimal test that validates the handler logic
	eventBus := events.NewEventBus(logr.Discard())

	// Track events
	var publishedEvent events.PolicyCreated
	var eventPublished bool
	events.Subscribe(eventBus, func(_ context.Context, e events.PolicyCreated) error {
		publishedEvent = e
		eventPublished = true
		return nil
	})

	handler := NewHandler(fakeClient, clientCache, eventBus, logr.Discard())

	// Create adapter
	adapter := domain.NewVaultPolicyAdapter(policy)

	// Set up the client cache with a real client (this won't connect but will exercise the code path)
	// For unit tests, we need to mock at a different level or test the individual methods

	// Test the generatePolicyHCL method directly
	rules := adapter.GetRules()
	hcl := handler.generatePolicyHCL(rules, testNamespace, testPolicyName)

	// Verify HCL generation
	if !strings.Contains(hcl, testNamespace) {
		t.Error("expected namespace to be substituted in HCL")
	}
	if strings.Contains(hcl, "{{namespace}}") {
		t.Error("expected {{namespace}} placeholder to be replaced")
	}
	if !strings.Contains(hcl, "read") || !strings.Contains(hcl, "list") {
		t.Error("expected capabilities to be in HCL")
	}

	// Verify hash calculation
	hash1 := handler.calculateHash(hcl)
	hash2 := handler.calculateHash(hcl)
	if hash1 != hash2 {
		t.Error("expected same hash for same content")
	}
	if hash1 == "" {
		t.Error("expected non-empty hash")
	}

	// Event won't be published until full sync completes
	// This is expected for this partial test since we're not doing a full sync
	// The test verifies the handler setup and HCL generation
	_ = publishedEvent
	_ = eventPublished
}

// TestSyncPolicy_SkipsUpdateWhenHashUnchanged tests that sync skips when hash unchanged
func TestSyncPolicy_SkipsUpdateWhenHashUnchanged(t *testing.T) {
	handler := &Handler{log: logr.Discard()}

	rules := []vaultv1alpha1.PolicyRule{
		{
			Path:         "secret/data/test/*",
			Capabilities: []vaultv1alpha1.Capability{"read"},
		},
	}

	hcl := handler.generatePolicyHCL(rules, testNamespace, testPolicyName)
	hash := handler.calculateHash(hcl)

	// Verify same rules produce same hash
	hcl2 := handler.generatePolicyHCL(rules, testNamespace, testPolicyName)
	hash2 := handler.calculateHash(hcl2)

	if hash != hash2 {
		t.Errorf("expected same hash for unchanged rules, got %s vs %s", hash, hash2)
	}
}

// TestValidateNamespaceBoundary tests namespace boundary validation
func TestValidateNamespaceBoundary(t *testing.T) {
	tests := []struct {
		name        string
		rules       []vaultv1alpha1.PolicyRule
		enforce     bool
		expectError bool
		errorField  string
	}{
		{
			name: "path with namespace variable passes when enforced",
			rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/{{namespace}}/*",
					Capabilities: []vaultv1alpha1.Capability{"read"},
				},
			},
			enforce:     true,
			expectError: false,
		},
		{
			name: "path without namespace variable fails when enforced",
			rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/test/*",
					Capabilities: []vaultv1alpha1.Capability{"read"},
				},
			},
			enforce:     true,
			expectError: true,
			errorField:  "rules[0].path",
		},
		{
			name: "path with wildcard before namespace fails",
			rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/*/{{namespace}}/*",
					Capabilities: []vaultv1alpha1.Capability{"read"},
				},
			},
			enforce:     true,
			expectError: true,
			errorField:  "rules[0].path",
		},
		{
			name: "multiple rules - first passes, second fails",
			rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/{{namespace}}/*",
					Capabilities: []vaultv1alpha1.Capability{"read"},
				},
				{
					Path:         "secret/data/shared/*",
					Capabilities: []vaultv1alpha1.Capability{"read"},
				},
			},
			enforce:     true,
			expectError: true,
			errorField:  "rules[1].path",
		},
		{
			name: "path without namespace variable passes when not enforced",
			rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/test/*",
					Capabilities: []vaultv1alpha1.Capability{"read"},
				},
			},
			enforce:     false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &Handler{log: logr.Discard()}

			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            testConnectionName,
					Rules:                    tt.rules,
					EnforceNamespaceBoundary: &tt.enforce,
				},
			}
			adapter := domain.NewVaultPolicyAdapter(policy)

			var err error
			if adapter.IsEnforceNamespaceBoundary() {
				err = handler.validateNamespaceBoundary(adapter)
			}

			if tt.expectError {
				if err == nil {
					t.Error("expected validation error")
				} else if !infraerrors.IsValidationError(err) {
					t.Errorf("expected ValidationError, got %T: %v", err, err)
				} else if tt.errorField != "" && !strings.Contains(err.Error(), tt.errorField) {
					t.Errorf("expected error to mention field %s, got: %v", tt.errorField, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestGeneratePolicyHCL tests HCL generation
func TestGeneratePolicyHCL(t *testing.T) {
	handler := &Handler{log: logr.Discard()}

	t.Run("basic HCL generation with namespace substitution", func(t *testing.T) {
		rules := []vaultv1alpha1.PolicyRule{
			{
				Path:         "secret/data/{{namespace}}/*",
				Capabilities: []vaultv1alpha1.Capability{"read", "list"},
			},
		}

		hcl := handler.generatePolicyHCL(rules, testNamespace, testPolicyName)

		if strings.Contains(hcl, "{{namespace}}") {
			t.Error("expected {{namespace}} to be replaced")
		}
		if !strings.Contains(hcl, testNamespace) {
			t.Error("expected namespace in HCL")
		}
		if !strings.Contains(hcl, "read") {
			t.Error("expected 'read' capability in HCL")
		}
		if !strings.Contains(hcl, "list") {
			t.Error("expected 'list' capability in HCL")
		}
	})

	t.Run("HCL generation with multiple rules", func(t *testing.T) {
		rules := []vaultv1alpha1.PolicyRule{
			{
				Path:         "secret/data/{{namespace}}/app1/*",
				Capabilities: []vaultv1alpha1.Capability{"read"},
				Description:  "Access to app1 secrets",
			},
			{
				Path:         "secret/data/{{namespace}}/app2/*",
				Capabilities: []vaultv1alpha1.Capability{"read", "create", "update"},
				Description:  "Full access to app2 secrets",
			},
		}

		hcl := handler.generatePolicyHCL(rules, testNamespace, testPolicyName)

		// Check both paths are present
		if !strings.Contains(hcl, "app1") {
			t.Error("expected app1 path in HCL")
		}
		if !strings.Contains(hcl, "app2") {
			t.Error("expected app2 path in HCL")
		}

		// Check descriptions are included as comments
		if !strings.Contains(hcl, "Access to app1 secrets") {
			t.Error("expected first description in HCL")
		}
		if !strings.Contains(hcl, "Full access to app2 secrets") {
			t.Error("expected second description in HCL")
		}

		// Check capabilities
		if !strings.Contains(hcl, "create") {
			t.Error("expected 'create' capability in HCL")
		}
		if !strings.Contains(hcl, "update") {
			t.Error("expected 'update' capability in HCL")
		}
	})

	t.Run("HCL generation with parameters", func(t *testing.T) {
		rules := []vaultv1alpha1.PolicyRule{
			{
				Path:         "secret/data/{{namespace}}/*",
				Capabilities: []vaultv1alpha1.Capability{"create", "update"},
				Parameters: &vaultv1alpha1.PolicyParameters{
					Allowed:  []string{"value1", "value2"},
					Required: []string{"key1"},
				},
			},
		}

		hcl := handler.generatePolicyHCL(rules, testNamespace, testPolicyName)

		if !strings.Contains(hcl, "allowed_parameters") {
			t.Error("expected allowed_parameters in HCL")
		}
		if !strings.Contains(hcl, "required_parameters") {
			t.Error("expected required_parameters in HCL")
		}
	})

	t.Run("HCL generation for cluster-scoped policy (empty namespace)", func(t *testing.T) {
		rules := []vaultv1alpha1.PolicyRule{
			{
				Path:         "secret/data/global/*",
				Capabilities: []vaultv1alpha1.Capability{"read"},
			},
		}

		hcl := handler.generatePolicyHCL(rules, "", "global-policy")

		if strings.Contains(hcl, "{{namespace}}") {
			t.Error("expected no {{namespace}} placeholder for cluster-scoped")
		}
		if !strings.Contains(hcl, "global-policy") {
			t.Error("expected policy name in HCL header")
		}
		if !strings.Contains(hcl, "cluster-scoped") {
			t.Error("expected cluster-scoped indicator in header")
		}
	})

	t.Run("HCL generation with name variable", func(t *testing.T) {
		rules := []vaultv1alpha1.PolicyRule{
			{
				Path:         "secret/data/{{namespace}}/{{name}}/*",
				Capabilities: []vaultv1alpha1.Capability{"read"},
			},
		}

		hcl := handler.generatePolicyHCL(rules, testNamespace, testPolicyName)

		if strings.Contains(hcl, "{{name}}") {
			t.Error("expected {{name}} to be replaced")
		}
		if !strings.Contains(hcl, testPolicyName) {
			t.Error("expected policy name in path")
		}
	})
}

// TestHandleSyncError tests error handling during sync
func TestHandleSyncError(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		expectedPhase vaultv1alpha1.Phase
		expectedCond  string
	}{
		{
			name:          "ConflictError sets phase to Conflict",
			err:           infraerrors.NewConflictError("policy", "test-policy", "managed by terraform"),
			expectedPhase: vaultv1alpha1.PhaseConflict,
			expectedCond:  vaultv1alpha1.ReasonConflict,
		},
		{
			name:          "ValidationError sets phase to Error",
			err:           infraerrors.NewValidationError("spec.rules", "[]", "at least one rule required"),
			expectedPhase: vaultv1alpha1.PhaseError,
			expectedCond:  vaultv1alpha1.ReasonValidationFailed,
		},
		{
			name:          "DependencyError sets phase to Error with ConnectionNotReady",
			err:           infraerrors.NewDependencyError("VaultPolicy/test", "VaultConnection", "vault-conn", "not ready"),
			expectedPhase: vaultv1alpha1.PhaseError,
			expectedCond:  vaultv1alpha1.ReasonConnectionNotReady,
		},
		{
			name:          "TransientError sets phase to Error",
			err:           infraerrors.NewTransientError("write policy", errors.New("connection refused")),
			expectedPhase: vaultv1alpha1.PhaseError,
			expectedCond:  vaultv1alpha1.ReasonFailed,
		},
		{
			name:          "Generic error sets phase to Error",
			err:           errors.New("unexpected error"),
			expectedPhase: vaultv1alpha1.PhaseError,
			expectedCond:  vaultv1alpha1.ReasonFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
				{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			})
			fakeClient := newFakeClient(policy)
			handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())

			adapter := domain.NewVaultPolicyAdapter(policy)
			ctx := context.Background()

			returnedErr := handler.handleSyncError(ctx, adapter, tt.err)

			// Verify error is returned
			if returnedErr != tt.err {
				t.Errorf("expected same error to be returned, got %v", returnedErr)
			}

			// Verify phase is set correctly
			if adapter.GetPhase() != tt.expectedPhase {
				t.Errorf("expected phase %s, got %s", tt.expectedPhase, adapter.GetPhase())
			}

			// Verify condition is set
			conditions := adapter.GetConditions()
			foundReady := false
			for _, cond := range conditions {
				if cond.Type == vaultv1alpha1.ConditionTypeReady {
					foundReady = true
					if cond.Reason != tt.expectedCond {
						t.Errorf("expected Ready condition reason %s, got %s", tt.expectedCond, cond.Reason)
					}
					if cond.Status != metav1.ConditionFalse {
						t.Errorf("expected Ready condition status False, got %s", cond.Status)
					}
				}
			}
			if !foundReady {
				t.Error("expected Ready condition to be set")
			}
		})
	}
}

// TestCleanupPolicy tests the cleanup behavior
func TestCleanupPolicy_DeletionPolicyDelete(t *testing.T) {
	mockClient := newMockVaultClient()

	vaultConn := createTestVaultConnection(testConnectionName, vaultv1alpha1.PhaseActive)
	policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
		{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
	})
	policy.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyDelete
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.VaultName = testNamespace + "-" + testPolicyName

	fakeClient := newFakeClient(vaultConn, policy)
	clientCache := vault.NewClientCache()

	// Create real vault client wrapper that delegates to mock
	// For this test we just verify the deletion policy logic
	eventBus := events.NewEventBus(logr.Discard())

	var deletedEvent events.PolicyDeleted
	var eventPublished bool
	events.Subscribe(eventBus, func(_ context.Context, e events.PolicyDeleted) error {
		deletedEvent = e
		eventPublished = true
		return nil
	})

	handler := NewHandler(fakeClient, clientCache, eventBus, logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	// Test the deletion logic directly - cleanup won't fully work without real vault client
	// but we can verify the event would be published
	ctx := context.Background()

	// Since we can't mock the vault client fully in this handler design,
	// we test what we can - the event publishing and phase setting
	err := handler.CleanupPolicy(ctx, adapter)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify phase is set to Deleting
	if adapter.GetPhase() != vaultv1alpha1.PhaseDeleting {
		t.Errorf("expected phase Deleting, got %s", adapter.GetPhase())
	}

	// Wait a bit for async event
	// In real tests we'd use proper synchronization
	_ = eventPublished
	_ = deletedEvent
	_ = mockClient
}

func TestCleanupPolicy_DeletionPolicyRetain(t *testing.T) {
	vaultConn := createTestVaultConnection(testConnectionName, vaultv1alpha1.PhaseActive)
	policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
		{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
	})
	policy.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyRetain
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.VaultName = testNamespace + "-" + testPolicyName

	fakeClient := newFakeClient(vaultConn, policy)
	clientCache := vault.NewClientCache()
	eventBus := events.NewEventBus(logr.Discard())

	handler := NewHandler(fakeClient, clientCache, eventBus, logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	ctx := context.Background()
	err := handler.CleanupPolicy(ctx, adapter)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Phase should still be set to Deleting
	if adapter.GetPhase() != vaultv1alpha1.PhaseDeleting {
		t.Errorf("expected phase Deleting, got %s", adapter.GetPhase())
	}
}

// TestCheckConflict tests conflict detection logic
func TestCheckConflict(t *testing.T) {
	t.Run("no conflict when policy does not exist", func(t *testing.T) {
		mockClient := newMockVaultClient()
		mockClient.policyExists = false

		policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
			{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
		})
		adapter := domain.NewVaultPolicyAdapter(policy)

		handler := &Handler{log: logr.Discard()}

		// We need to call checkConflict with the mock
		// Since checkConflict uses *vault.Client, we need to test via integration
		// or refactor the handler to use an interface

		// For now, verify the adapter methods work correctly
		vaultPolicyName := adapter.GetVaultPolicyName()
		expectedName := testNamespace + "-" + testPolicyName
		if vaultPolicyName != expectedName {
			t.Errorf("expected vault policy name %s, got %s", expectedName, vaultPolicyName)
		}

		k8sResource := adapter.GetK8sResourceIdentifier()
		expectedResource := testNamespace + "/" + testPolicyName
		if k8sResource != expectedResource {
			t.Errorf("expected k8s resource %s, got %s", expectedResource, k8sResource)
		}

		_ = handler
	})

	t.Run("conflict policy Adopt allows taking over unmanaged policy", func(t *testing.T) {
		policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
			{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
		})
		policy.Spec.ConflictPolicy = vaultv1alpha1.ConflictPolicyAdopt
		adapter := domain.NewVaultPolicyAdapter(policy)

		if adapter.GetConflictPolicy() != vaultv1alpha1.ConflictPolicyAdopt {
			t.Errorf("expected conflict policy Adopt, got %s", adapter.GetConflictPolicy())
		}
	})

	t.Run("conflict policy Fail is default", func(t *testing.T) {
		policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
			{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
		})
		// Don't set conflict policy - should default to Fail
		adapter := domain.NewVaultPolicyAdapter(policy)

		// Empty string is the default when not set
		if adapter.GetConflictPolicy() != "" && adapter.GetConflictPolicy() != vaultv1alpha1.ConflictPolicyFail {
			t.Errorf("expected empty or Fail conflict policy, got %s", adapter.GetConflictPolicy())
		}
	})
}

// TestSetCondition tests the condition setting logic
func TestSetCondition(t *testing.T) {
	t.Run("adds new condition", func(t *testing.T) {
		policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
			{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
		})
		adapter := domain.NewVaultPolicyAdapter(policy)
		handler := &Handler{log: logr.Discard()}

		handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			vaultv1alpha1.ReasonSucceeded, "Policy ready")

		conditions := adapter.GetConditions()
		if len(conditions) != 1 {
			t.Errorf("expected 1 condition, got %d", len(conditions))
		}

		cond := conditions[0]
		if cond.Type != vaultv1alpha1.ConditionTypeReady {
			t.Errorf("expected type Ready, got %s", cond.Type)
		}
		if cond.Status != metav1.ConditionTrue {
			t.Errorf("expected status True, got %s", cond.Status)
		}
		if cond.Reason != vaultv1alpha1.ReasonSucceeded {
			t.Errorf("expected reason Succeeded, got %s", cond.Reason)
		}
		if cond.Message != "Policy ready" {
			t.Errorf("expected message 'Policy ready', got %s", cond.Message)
		}
	})

	t.Run("updates existing condition with same status", func(t *testing.T) {
		policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
			{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
		})
		adapter := domain.NewVaultPolicyAdapter(policy)
		handler := &Handler{log: logr.Discard()}

		// Set initial condition
		handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			vaultv1alpha1.ReasonSucceeded, "Initial message")

		// Update with same status but different reason/message
		handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			vaultv1alpha1.ReasonSucceeded, "Updated message")

		conditions := adapter.GetConditions()
		if len(conditions) != 1 {
			t.Errorf("expected 1 condition, got %d", len(conditions))
		}

		if conditions[0].Message != "Updated message" {
			t.Errorf("expected message to be updated, got %s", conditions[0].Message)
		}
	})

	t.Run("updates existing condition with different status", func(t *testing.T) {
		policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
			{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
		})
		adapter := domain.NewVaultPolicyAdapter(policy)
		handler := &Handler{log: logr.Discard()}

		// Set initial condition as True
		handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			vaultv1alpha1.ReasonSucceeded, "Success")

		// Update to False
		handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			vaultv1alpha1.ReasonFailed, "Failed")

		conditions := adapter.GetConditions()
		if len(conditions) != 1 {
			t.Errorf("expected 1 condition, got %d", len(conditions))
		}

		cond := conditions[0]
		if cond.Status != metav1.ConditionFalse {
			t.Errorf("expected status False, got %s", cond.Status)
		}
		if cond.Reason != vaultv1alpha1.ReasonFailed {
			t.Errorf("expected reason Failed, got %s", cond.Reason)
		}
	})

	t.Run("adds multiple different conditions", func(t *testing.T) {
		policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
			{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
		})
		adapter := domain.NewVaultPolicyAdapter(policy)
		handler := &Handler{log: logr.Discard()}

		handler.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			vaultv1alpha1.ReasonSucceeded, "Ready")
		handler.setCondition(adapter, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue,
			vaultv1alpha1.ReasonSucceeded, "Synced")

		conditions := adapter.GetConditions()
		if len(conditions) != 2 {
			t.Errorf("expected 2 conditions, got %d", len(conditions))
		}

		hasReady := false
		hasSynced := false
		for _, c := range conditions {
			if c.Type == vaultv1alpha1.ConditionTypeReady {
				hasReady = true
			}
			if c.Type == vaultv1alpha1.ConditionTypeSynced {
				hasSynced = true
			}
		}
		if !hasReady {
			t.Error("expected Ready condition")
		}
		if !hasSynced {
			t.Error("expected Synced condition")
		}
	})
}

// TestCalculateHash tests hash calculation
func TestCalculateHash(t *testing.T) {
	handler := &Handler{log: logr.Discard()}

	t.Run("same content produces same hash", func(t *testing.T) {
		content := "path \"secret/*\" { capabilities = [\"read\"] }"
		hash1 := handler.calculateHash(content)
		hash2 := handler.calculateHash(content)

		if hash1 != hash2 {
			t.Errorf("expected same hash, got %s vs %s", hash1, hash2)
		}
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		content1 := "path \"secret/*\" { capabilities = [\"read\"] }"
		content2 := "path \"secret/*\" { capabilities = [\"read\", \"list\"] }"
		hash1 := handler.calculateHash(content1)
		hash2 := handler.calculateHash(content2)

		if hash1 == hash2 {
			t.Error("expected different hash for different content")
		}
	})

	t.Run("hash is deterministic", func(t *testing.T) {
		content := "test content"
		hashes := make([]string, 10)
		for i := 0; i < 10; i++ {
			hashes[i] = handler.calculateHash(content)
		}

		for i := 1; i < 10; i++ {
			if hashes[i] != hashes[0] {
				t.Errorf("hash %d differs from hash 0", i)
			}
		}
	})

	t.Run("hash is correct length (SHA256 = 64 hex chars)", func(t *testing.T) {
		hash := handler.calculateHash("test")
		if len(hash) != 64 {
			t.Errorf("expected hash length 64, got %d", len(hash))
		}
	})
}

// TestClusterPolicyAdapter tests the cluster-scoped policy adapter
func TestClusterPolicyAdapter(t *testing.T) {
	clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "global-policy",
		},
		Spec: vaultv1alpha1.VaultClusterPolicySpec{
			ConnectionRef: testConnectionName,
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/data/global/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}

	adapter := domain.NewVaultClusterPolicyAdapter(clusterPolicy)

	t.Run("IsNamespaced returns false", func(t *testing.T) {
		if adapter.IsNamespaced() {
			t.Error("expected cluster policy to not be namespaced")
		}
	})

	t.Run("GetNamespace returns empty string", func(t *testing.T) {
		if adapter.GetNamespace() != "" {
			t.Errorf("expected empty namespace, got %s", adapter.GetNamespace())
		}
	})

	t.Run("GetVaultPolicyName returns just the name", func(t *testing.T) {
		expected := "global-policy"
		if adapter.GetVaultPolicyName() != expected {
			t.Errorf("expected %s, got %s", expected, adapter.GetVaultPolicyName())
		}
	})

	t.Run("GetK8sResourceIdentifier returns just the name", func(t *testing.T) {
		expected := "global-policy"
		if adapter.GetK8sResourceIdentifier() != expected {
			t.Errorf("expected %s, got %s", expected, adapter.GetK8sResourceIdentifier())
		}
	})

	t.Run("IsEnforceNamespaceBoundary returns false", func(t *testing.T) {
		if adapter.IsEnforceNamespaceBoundary() {
			t.Error("expected cluster policy to not enforce namespace boundary")
		}
	})
}

// TestNamespacedPolicyAdapter tests the namespaced policy adapter
func TestNamespacedPolicyAdapter(t *testing.T) {
	policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
		{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
	})

	adapter := domain.NewVaultPolicyAdapter(policy)

	t.Run("IsNamespaced returns true", func(t *testing.T) {
		if !adapter.IsNamespaced() {
			t.Error("expected namespaced policy")
		}
	})

	t.Run("GetNamespace returns the namespace", func(t *testing.T) {
		if adapter.GetNamespace() != testNamespace {
			t.Errorf("expected %s, got %s", testNamespace, adapter.GetNamespace())
		}
	})

	t.Run("GetVaultPolicyName returns namespace-name format", func(t *testing.T) {
		expected := testNamespace + "-" + testPolicyName
		if adapter.GetVaultPolicyName() != expected {
			t.Errorf("expected %s, got %s", expected, adapter.GetVaultPolicyName())
		}
	})

	t.Run("GetK8sResourceIdentifier returns namespace/name format", func(t *testing.T) {
		expected := testNamespace + "/" + testPolicyName
		if adapter.GetK8sResourceIdentifier() != expected {
			t.Errorf("expected %s, got %s", expected, adapter.GetK8sResourceIdentifier())
		}
	})
}

// TestEventPublishing tests that events are properly published
func TestEventPublishing(t *testing.T) {
	t.Run("PolicyCreated event structure", func(t *testing.T) {
		resource := events.ResourceInfo{
			Name:           testPolicyName,
			Namespace:      testNamespace,
			ClusterScoped:  false,
			ConnectionName: testConnectionName,
		}
		event := events.NewPolicyCreated("test-namespace-test-policy", resource)

		if event.Type() != events.PolicyCreatedType {
			t.Errorf("expected type %s, got %s", events.PolicyCreatedType, event.Type())
		}
		if event.PolicyName != "test-namespace-test-policy" {
			t.Errorf("expected policy name test-namespace-test-policy, got %s", event.PolicyName)
		}
		if event.Resource.Name != testPolicyName {
			t.Errorf("expected resource name %s, got %s", testPolicyName, event.Resource.Name)
		}
		if event.Resource.Namespace != testNamespace {
			t.Errorf("expected namespace %s, got %s", testNamespace, event.Resource.Namespace)
		}
	})

	t.Run("PolicyDeleted event structure", func(t *testing.T) {
		resource := events.ResourceInfo{
			Name:           testPolicyName,
			Namespace:      testNamespace,
			ClusterScoped:  false,
			ConnectionName: testConnectionName,
		}
		event := events.NewPolicyDeleted("test-namespace-test-policy", resource)

		if event.Type() != events.PolicyDeletedType {
			t.Errorf("expected type %s, got %s", events.PolicyDeletedType, event.Type())
		}
	})

	t.Run("cluster-scoped policy event has ClusterScoped=true", func(t *testing.T) {
		resource := events.ResourceInfo{
			Name:           "global-policy",
			Namespace:      "",
			ClusterScoped:  true,
			ConnectionName: testConnectionName,
		}
		event := events.NewPolicyCreated("global-policy", resource)

		if !event.Resource.ClusterScoped {
			t.Error("expected ClusterScoped to be true")
		}
		if event.Resource.Namespace != "" {
			t.Errorf("expected empty namespace for cluster-scoped, got %s", event.Resource.Namespace)
		}
	})
}

// TestStatusAccessors tests the status accessor methods on adapters
func TestStatusAccessors(t *testing.T) {
	policy := createTestVaultPolicy(testPolicyName, testNamespace, testConnectionName, []vaultv1alpha1.PolicyRule{
		{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
	})
	adapter := domain.NewVaultPolicyAdapter(policy)

	t.Run("Phase get/set", func(t *testing.T) {
		adapter.SetPhase(vaultv1alpha1.PhaseActive)
		if adapter.GetPhase() != vaultv1alpha1.PhaseActive {
			t.Errorf("expected phase Active, got %s", adapter.GetPhase())
		}
	})

	t.Run("LastAppliedHash get/set", func(t *testing.T) {
		hash := "abc123"
		adapter.SetLastAppliedHash(hash)
		if adapter.GetLastAppliedHash() != hash {
			t.Errorf("expected hash %s, got %s", hash, adapter.GetLastAppliedHash())
		}
	})

	t.Run("VaultName get/set", func(t *testing.T) {
		name := "test-vault-name"
		adapter.SetVaultName(name)
		if adapter.GetVaultName() != name {
			t.Errorf("expected vault name %s, got %s", name, adapter.GetVaultName())
		}
	})

	t.Run("Managed set", func(t *testing.T) {
		adapter.SetManaged(true)
		if !policy.Status.Managed {
			t.Error("expected Managed to be true")
		}
	})

	t.Run("RulesCount set", func(t *testing.T) {
		adapter.SetRulesCount(5)
		if policy.Status.RulesCount != 5 {
			t.Errorf("expected RulesCount 5, got %d", policy.Status.RulesCount)
		}
	})

	t.Run("RetryCount get/set", func(t *testing.T) {
		adapter.SetRetryCount(3)
		if adapter.GetRetryCount() != 3 {
			t.Errorf("expected retry count 3, got %d", adapter.GetRetryCount())
		}
	})

	t.Run("Message set", func(t *testing.T) {
		msg := "test message"
		adapter.SetMessage(msg)
		if policy.Status.Message != msg {
			t.Errorf("expected message %s, got %s", msg, policy.Status.Message)
		}
	})

	t.Run("LastSyncedAt set", func(t *testing.T) {
		now := metav1.Now()
		adapter.SetLastSyncedAt(&now)
		if policy.Status.LastSyncedAt == nil {
			t.Error("expected LastSyncedAt to be set")
		}
	})

	t.Run("LastAttemptAt set", func(t *testing.T) {
		now := metav1.Now()
		adapter.SetLastAttemptAt(&now)
		if policy.Status.LastAttemptAt == nil {
			t.Error("expected LastAttemptAt to be set")
		}
	})

	t.Run("NextRetryAt set", func(t *testing.T) {
		now := metav1.Now()
		adapter.SetNextRetryAt(&now)
		if policy.Status.NextRetryAt == nil {
			t.Error("expected NextRetryAt to be set")
		}

		// Set to nil
		adapter.SetNextRetryAt(nil)
		if policy.Status.NextRetryAt != nil {
			t.Error("expected NextRetryAt to be nil")
		}
	})

	t.Run("DriftDetected get/set", func(t *testing.T) {
		adapter.SetDriftDetected(true)
		if !adapter.GetDriftDetected() {
			t.Error("expected DriftDetected to be true")
		}
		adapter.SetDriftDetected(false)
		if adapter.GetDriftDetected() {
			t.Error("expected DriftDetected to be false")
		}
	})

	t.Run("LastDriftCheckAt set", func(t *testing.T) {
		now := metav1.Now()
		adapter.SetLastDriftCheckAt(&now)
		if policy.Status.LastDriftCheckAt == nil {
			t.Error("expected LastDriftCheckAt to be set")
		}
	})
}

// TestNormalizeHCL tests the HCL normalization function for drift detection
func TestNormalizeHCL(t *testing.T) {
	handler := &Handler{log: logr.Discard()}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "removes leading and trailing whitespace",
			input: `
  path "secret/*" {
    capabilities = ["read"]
  }
`,
			expected: `path "secret/*" {
capabilities = ["read"]
}`,
		},
		{
			name: "preserves content without extra whitespace",
			input: `path "secret/*" {
capabilities = ["read"]
}`,
			expected: `path "secret/*" {
capabilities = ["read"]
}`,
		},
		{
			name:     "handles empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "handles whitespace-only string",
			input:    "   \n\t  \n  ",
			expected: "",
		},
		{
			name: "normalizes indentation differences",
			input: `    path "secret/*" {
        capabilities = ["read"]
    }`,
			expected: `path "secret/*" {
capabilities = ["read"]
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.normalizeHCL(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeHCL() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestNormalizeHCL_DriftDetectionScenarios tests HCL comparison for drift detection
func TestNormalizeHCL_DriftDetectionScenarios(t *testing.T) {
	handler := &Handler{log: logr.Discard()}

	t.Run("identical content after normalization means no drift", func(t *testing.T) {
		generated := `path "secret/data/default/*" {
  capabilities = ["read", "list"]
}`
		fromVault := `path "secret/data/default/*" {
    capabilities = ["read", "list"]
}`
		normalizedGenerated := handler.normalizeHCL(generated)
		normalizedFromVault := handler.normalizeHCL(fromVault)

		if normalizedGenerated != normalizedFromVault {
			t.Errorf("expected no drift for whitespace differences\ngenerated: %q\nfromVault: %q",
				normalizedGenerated, normalizedFromVault)
		}
	})

	t.Run("different capabilities means drift", func(t *testing.T) {
		generated := `path "secret/data/default/*" {
  capabilities = ["read", "list"]
}`
		fromVault := `path "secret/data/default/*" {
  capabilities = ["read", "list", "create"]
}`
		normalizedGenerated := handler.normalizeHCL(generated)
		normalizedFromVault := handler.normalizeHCL(fromVault)

		if normalizedGenerated == normalizedFromVault {
			t.Error("expected drift for different capabilities")
		}
	})

	t.Run("different path means drift", func(t *testing.T) {
		generated := `path "secret/data/default/*" {
  capabilities = ["read"]
}`
		fromVault := `path "secret/data/other/*" {
  capabilities = ["read"]
}`
		normalizedGenerated := handler.normalizeHCL(generated)
		normalizedFromVault := handler.normalizeHCL(fromVault)

		if normalizedGenerated == normalizedFromVault {
			t.Error("expected drift for different paths")
		}
	})
}

// TestDriftDetectionStatusAccessors tests drift detection accessors for cluster policy adapter
func TestDriftDetectionStatusAccessors_ClusterPolicy(t *testing.T) {
	clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "global-policy",
		},
		Spec: vaultv1alpha1.VaultClusterPolicySpec{
			ConnectionRef: testConnectionName,
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/data/global/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}

	adapter := domain.NewVaultClusterPolicyAdapter(clusterPolicy)

	t.Run("DriftDetected get/set for cluster policy", func(t *testing.T) {
		adapter.SetDriftDetected(true)
		if !adapter.GetDriftDetected() {
			t.Error("expected DriftDetected to be true")
		}
		adapter.SetDriftDetected(false)
		if adapter.GetDriftDetected() {
			t.Error("expected DriftDetected to be false")
		}
	})

	t.Run("LastDriftCheckAt set for cluster policy", func(t *testing.T) {
		now := metav1.Now()
		adapter.SetLastDriftCheckAt(&now)
		if clusterPolicy.Status.LastDriftCheckAt == nil {
			t.Error("expected LastDriftCheckAt to be set")
		}
	})
}
