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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// --- Mock Vault HTTP server for policy tests ---

// policyMockState holds the mock Vault server state.
type policyMockState struct {
	mu       sync.Mutex
	policies map[string]string                 // policyName → HCL
	managed  map[string]map[string]interface{} // full API path → managed metadata
	roles    map[string]map[string]interface{} // full API path → role data (unused for policy tests)
}

func newPolicyMockState() *policyMockState {
	return &policyMockState{
		policies: make(map[string]string),
		managed:  make(map[string]map[string]interface{}),
		roles:    make(map[string]map[string]interface{}),
	}
}

type policyMockConfig struct {
	state          *policyMockState
	writePolicyErr bool
	readPolicyErr  bool
}

func newPolicyMockServer(cfg policyMockConfig) *httptest.Server {
	if cfg.state == nil {
		cfg.state = newPolicyMockState()
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiPath := strings.TrimPrefix(r.URL.Path, "/v1/")

		switch {
		// --- Managed metadata (KV v2) --- must come before generic paths
		case strings.HasPrefix(apiPath, "secret/data/vault-access-operator/managed/"):
			cfg.state.mu.Lock()
			defer cfg.state.mu.Unlock()

			switch r.Method {
			case http.MethodPut, http.MethodPost:
				var body map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&body)
				cfg.state.managed[apiPath] = body
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{"version": 1},
				})

			case http.MethodGet:
				data, exists := cfg.state.managed[apiPath]
				if !exists {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})

			case http.MethodDelete:
				delete(cfg.state.managed, apiPath)
				w.WriteHeader(http.StatusNoContent)
			}

		// --- Policy CRUD via sys/policies/acl ---
		case strings.HasPrefix(apiPath, "sys/policies/acl/"):
			policyName := strings.TrimPrefix(apiPath, "sys/policies/acl/")
			cfg.state.mu.Lock()
			defer cfg.state.mu.Unlock()

			switch r.Method {
			case http.MethodPut, http.MethodPost:
				if cfg.writePolicyErr {
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"internal error"},
					})
					return
				}
				var data map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&data)
				if policy, ok := data["policy"].(string); ok {
					cfg.state.policies[policyName] = policy
				}
				w.WriteHeader(http.StatusNoContent)

			case http.MethodGet:
				if cfg.readPolicyErr {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				hcl, exists := cfg.state.policies[policyName]
				if !exists {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"name":   policyName,
						"policy": hcl,
					},
				})

			case http.MethodDelete:
				delete(cfg.state.policies, policyName)
				w.WriteHeader(http.StatusNoContent)
			}

		// --- Policy list (Vault SDK v1.22 uses GET /v1/sys/policies/acl?list=true) ---
		case apiPath == "sys/policies/acl" && r.URL.Query().Get("list") == "true":
			cfg.state.mu.Lock()
			defer cfg.state.mu.Unlock()

			names := []string{"default", "root"}
			for name := range cfg.state.policies {
				names = append(names, name)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": names,
				},
			})

		// --- Default: health ---
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"initialized": true,
				"sealed":      false,
				"version":     "1.15.0",
			})
		}
	}))
}

// --- Test helpers ---

const (
	policyTestConnName  = "test-connection"
	policyTestNamespace = "test-ns"
	policyTestName      = "app-read"

	existingPolicyHCL = `path "secret/*" { capabilities = ["read"] }`
	driftedPolicyHCL  = `path "DRIFTED/*" { capabilities = ["delete"] }`
)

func newPolicyTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = vaultv1alpha1.AddToScheme(scheme)
	return scheme
}

func newPolicyTestConnection() *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       policyTestConnName,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Token: &vaultv1alpha1.TokenAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name: "vault-token",
						Key:  "token",
					},
				},
			},
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

func newTestVaultPolicy() *vaultv1alpha1.VaultPolicy {
	return &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       policyTestName,
			Namespace:  policyTestNamespace,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: policyTestConnName,
			Rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/{{namespace}}/*",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead, vaultv1alpha1.CapabilityList},
				},
			},
		},
	}
}

func newPolicyCachedVaultClient(t *testing.T, serverURL string) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: serverURL})
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	c.SetAuthenticated(true)
	c.SetToken("s.test-token")
	return c
}

// setupPolicySyncTest creates all dependencies for testing SyncPolicy.
func setupPolicySyncTest(
	t *testing.T,
	policy *vaultv1alpha1.VaultPolicy,
	conn *vaultv1alpha1.VaultConnection,
	cfg policyMockConfig,
) (*Handler, *httptest.Server, client.Client) {
	t.Helper()

	server := newPolicyMockServer(cfg)

	scheme := newPolicyTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, policy).
		WithStatusSubresource(conn, policy).
		Build()

	cache := vault.NewClientCache()
	vaultClient := newPolicyCachedVaultClient(t, server.URL)
	cache.Set(conn.Name, vaultClient)

	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(k8sClient, cache, bus, logr.Discard())

	return handler, server, k8sClient
}

// --- SyncPolicy Tests ---

func TestSyncPolicy_Success_NewPolicy(t *testing.T) {
	state := newPolicyMockState()
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()

	handler, server, _ := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.SyncPolicy(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncPolicy failed: %v", err)
	}

	// Verify policy was written to Vault
	expectedName := policyTestNamespace + "-" + policyTestName
	state.mu.Lock()
	hcl, exists := state.policies[expectedName]
	state.mu.Unlock()

	if !exists {
		t.Fatalf("policy not written to Vault; policies: %v", policyKeys(state.policies))
	}

	// Verify HCL contains the path
	if !strings.Contains(hcl, "secret/data/") {
		t.Errorf("expected HCL to contain secret path, got: %s", hcl)
	}
}

func TestSyncPolicy_Success_ClusterPolicy(t *testing.T) {
	state := newPolicyMockState()
	conn := newPolicyTestConnection()

	clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "admin-base",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultClusterPolicySpec{
			ConnectionRef: policyTestConnName,
			Rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/shared/*",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
				},
			},
		},
	}

	scheme := newPolicyTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, clusterPolicy).
		WithStatusSubresource(conn, clusterPolicy).
		Build()

	cache := vault.NewClientCache()
	server := newPolicyMockServer(policyMockConfig{state: state})
	defer server.Close()

	vaultClient := newPolicyCachedVaultClient(t, server.URL)
	cache.Set(policyTestConnName, vaultClient)

	handler := NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultClusterPolicyAdapter(clusterPolicy)

	err := handler.SyncPolicy(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncPolicy failed: %v", err)
	}

	// Cluster policies use just the name
	state.mu.Lock()
	_, exists := state.policies["admin-base"]
	state.mu.Unlock()

	if !exists {
		t.Fatalf("cluster policy not written to Vault; policies: %v", policyKeys(state.policies))
	}
}

func TestSyncPolicy_Success_WithNamespaceSubstitution(t *testing.T) {
	state := newPolicyMockState()
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()

	handler, server, _ := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.SyncPolicy(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncPolicy failed: %v", err)
	}

	// Verify {{namespace}} was substituted
	expectedName := policyTestNamespace + "-" + policyTestName
	state.mu.Lock()
	hcl := state.policies[expectedName]
	state.mu.Unlock()

	if strings.Contains(hcl, "{{namespace}}") {
		t.Errorf("expected {{namespace}} to be substituted, but it remains in HCL: %s", hcl)
	}

	if !strings.Contains(hcl, policyTestNamespace) {
		t.Errorf("expected HCL to contain namespace '%s', got: %s", policyTestNamespace, hcl)
	}
}

func TestSyncPolicy_NamespaceBoundaryViolation(t *testing.T) {
	conn := newPolicyTestConnection()
	enforced := true
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       policyTestName,
			Namespace:  policyTestNamespace,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:            policyTestConnName,
			EnforceNamespaceBoundary: &enforced,
			Rules: []vaultv1alpha1.PolicyRule{
				{
					// Missing {{namespace}} in path — should be rejected
					Path:         "secret/data/other-ns/*",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
				},
			},
		},
	}

	handler, server, _ := setupPolicySyncTest(t, policy, conn, policyMockConfig{})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.SyncPolicy(ctx, adapter)
	if err == nil {
		t.Fatal("expected namespace boundary validation error, got nil")
	}

	if !strings.Contains(err.Error(), "namespace") {
		t.Errorf("expected namespace-related error, got: %v", err)
	}
}

func TestSyncPolicy_ConflictError_Adopt(t *testing.T) {
	state := newPolicyMockState()
	vaultPolicyName := policyTestNamespace + "-" + policyTestName
	// Pre-populate an existing policy (unmanaged)
	state.policies[vaultPolicyName] = existingPolicyHCL

	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	policy.Annotations = map[string]string{
		vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue,
	}

	handler, server, _ := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.SyncPolicy(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncPolicy with adopt should succeed: %v", err)
	}
}

func TestSyncPolicy_ConflictError_Fail(t *testing.T) {
	state := newPolicyMockState()
	vaultPolicyName := policyTestNamespace + "-" + policyTestName
	// Pre-populate an existing policy managed by someone else
	state.policies[vaultPolicyName] = existingPolicyHCL

	managedKey := fmt.Sprintf("secret/data/vault-access-operator/managed/policies/%s", vaultPolicyName)
	state.managed[managedKey] = map[string]interface{}{
		"data": map[string]interface{}{
			"metadata": `{"k8sResource":"other-ns/other-policy",` +
				`"managedAt":"2026-01-01T00:00:00Z",` +
				`"lastUpdated":"2026-01-01T00:00:00Z"}`,
		},
	}

	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()

	handler, server, _ := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.SyncPolicy(ctx, adapter)
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}

	if !strings.Contains(err.Error(), "conflict") {
		t.Errorf("expected conflict error, got: %v", err)
	}
}

func TestSyncPolicy_VaultWriteError(t *testing.T) {
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()

	handler, server, _ := setupPolicySyncTest(t, policy, conn, policyMockConfig{
		writePolicyErr: true,
	})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.SyncPolicy(ctx, adapter)
	if err == nil {
		t.Fatal("expected write error, got nil")
	}
}

func TestSyncPolicy_SkipWhenHashUnchanged(t *testing.T) {
	state := newPolicyMockState()
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	policy.Spec.DriftMode = vaultv1alpha1.DriftModeIgnore

	handler, server, k8sClient := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	// First sync
	if err := handler.SyncPolicy(ctx, adapter); err != nil {
		t.Fatalf("initial SyncPolicy failed: %v", err)
	}

	// Re-fetch to get hash
	var updatedPolicy vaultv1alpha1.VaultPolicy
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &updatedPolicy); err != nil {
		t.Fatalf("failed to get updated policy: %v", err)
	}

	if updatedPolicy.Status.LastAppliedHash == "" {
		t.Fatal("expected LastAppliedHash to be set after first sync")
	}

	// Second sync with same spec + Active + no drift → should skip write
	updatedPolicy.Status.Phase = vaultv1alpha1.PhaseActive
	adapter2 := domain.NewVaultPolicyAdapter(&updatedPolicy)

	err := handler.SyncPolicy(ctx, adapter2)
	if err != nil {
		t.Fatalf("second SyncPolicy failed: %v", err)
	}
}

func TestSyncPolicy_DriftDetect_ContentDiffers(t *testing.T) {
	state := newPolicyMockState()
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	policy.Spec.DriftMode = vaultv1alpha1.DriftModeDetect

	handler, server, k8sClient := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	// First sync
	if err := handler.SyncPolicy(ctx, adapter); err != nil {
		t.Fatalf("initial SyncPolicy failed: %v", err)
	}

	// Re-fetch to get hash
	var updatedPolicy vaultv1alpha1.VaultPolicy
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &updatedPolicy); err != nil {
		t.Fatalf("failed to get updated policy: %v", err)
	}

	// Simulate drift by changing the HCL in Vault
	vaultPolicyName := policyTestNamespace + "-" + policyTestName
	state.mu.Lock()
	state.policies[vaultPolicyName] = driftedPolicyHCL
	state.mu.Unlock()

	// Second sync with detect mode and same hash → should detect drift but not correct
	updatedPolicy.Status.Phase = vaultv1alpha1.PhaseActive
	adapter2 := domain.NewVaultPolicyAdapter(&updatedPolicy)

	err := handler.SyncPolicy(ctx, adapter2)
	if err != nil {
		t.Fatalf("SyncPolicy should not error in detect mode: %v", err)
	}

	// Verify Vault was NOT overwritten
	state.mu.Lock()
	hcl := state.policies[vaultPolicyName]
	state.mu.Unlock()

	if !strings.Contains(hcl, "DRIFTED") {
		t.Error("detect mode should NOT overwrite drifted policy")
	}
}

func TestSyncPolicy_DriftCorrect_WithAnnotation(t *testing.T) {
	state := newPolicyMockState()
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	policy.Spec.DriftMode = vaultv1alpha1.DriftModeCorrect
	policy.Annotations = map[string]string{
		vaultv1alpha1.AnnotationAllowDestructive: vaultv1alpha1.AnnotationValueTrue,
	}

	handler, server, k8sClient := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	// First sync
	if err := handler.SyncPolicy(ctx, adapter); err != nil {
		t.Fatalf("initial SyncPolicy failed: %v", err)
	}

	// Re-fetch to get hash
	var updatedPolicy vaultv1alpha1.VaultPolicy
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &updatedPolicy); err != nil {
		t.Fatalf("failed to get updated policy: %v", err)
	}

	// Simulate drift
	vaultPolicyName := policyTestNamespace + "-" + policyTestName
	state.mu.Lock()
	state.policies[vaultPolicyName] = driftedPolicyHCL
	state.mu.Unlock()

	// Second sync with correct mode + annotation → should overwrite
	updatedPolicy.Status.Phase = vaultv1alpha1.PhaseActive
	adapter2 := domain.NewVaultPolicyAdapter(&updatedPolicy)

	err := handler.SyncPolicy(ctx, adapter2)
	if err != nil {
		t.Fatalf("SyncPolicy should correct drift with annotation: %v", err)
	}

	// Verify Vault WAS overwritten
	state.mu.Lock()
	hcl := state.policies[vaultPolicyName]
	state.mu.Unlock()

	if strings.Contains(hcl, "DRIFTED") {
		t.Error("correct mode with annotation should overwrite drifted policy")
	}
}

func TestSyncPolicy_DriftCorrect_Blocked(t *testing.T) {
	state := newPolicyMockState()
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	policy.Spec.DriftMode = vaultv1alpha1.DriftModeCorrect
	// No AnnotationAllowDestructive

	handler, server, k8sClient := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	// First sync
	if err := handler.SyncPolicy(ctx, adapter); err != nil {
		t.Fatalf("initial SyncPolicy failed: %v", err)
	}

	// Re-fetch to get hash
	var updatedPolicy vaultv1alpha1.VaultPolicy
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &updatedPolicy); err != nil {
		t.Fatalf("failed to get updated policy: %v", err)
	}

	// Simulate drift
	vaultPolicyName := policyTestNamespace + "-" + policyTestName
	state.mu.Lock()
	state.policies[vaultPolicyName] = driftedPolicyHCL
	state.mu.Unlock()

	// Second sync without annotation → should block
	updatedPolicy.Status.Phase = vaultv1alpha1.PhaseActive
	adapter2 := domain.NewVaultPolicyAdapter(&updatedPolicy)

	err := handler.SyncPolicy(ctx, adapter2)
	if err != nil {
		t.Fatalf("SyncPolicy should return nil when drift is blocked: %v", err)
	}

	// Verify Vault was NOT overwritten
	state.mu.Lock()
	hcl := state.policies[vaultPolicyName]
	state.mu.Unlock()

	if !strings.Contains(hcl, "DRIFTED") {
		t.Error("blocked correction should NOT overwrite drifted policy")
	}
}

func TestSyncPolicy_EventPublished(t *testing.T) {
	state := newPolicyMockState()
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()

	scheme := newPolicyTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, policy).
		WithStatusSubresource(conn, policy).
		Build()

	cache := vault.NewClientCache()
	server := newPolicyMockServer(policyMockConfig{state: state})
	defer server.Close()

	vaultClient := newPolicyCachedVaultClient(t, server.URL)
	cache.Set(policyTestConnName, vaultClient)

	bus := events.NewEventBus(logr.Discard())

	// Subscribe to PolicyCreated events using a channel
	eventCh := make(chan events.PolicyCreated, 1)
	events.Subscribe(bus, func(_ context.Context, e events.PolicyCreated) error {
		eventCh <- e
		return nil
	})

	handler := NewHandler(k8sClient, cache, bus, logr.Discard())

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.SyncPolicy(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncPolicy failed: %v", err)
	}

	// Wait for async event delivery
	select {
	case e := <-eventCh:
		expectedPolicyName := policyTestNamespace + "-" + policyTestName
		if e.PolicyName != expectedPolicyName {
			t.Errorf("expected PolicyName=%s, got %s", expectedPolicyName, e.PolicyName)
		}
		if e.Resource.Name != policyTestName {
			t.Errorf("expected Resource.Name=%s, got %s", policyTestName, e.Resource.Name)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for PolicyCreated event")
	}
}

// --- Error recovery transitions (Gap 9) ---

func TestSyncPolicy_RecoveryAfterVaultError(t *testing.T) {
	state := newPolicyMockState()
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()

	// Simulate previous error state
	policy.Status.Phase = vaultv1alpha1.PhaseError
	policy.Status.Message = "previous vault error"
	policy.Status.RetryCount = 3

	handler, server, _ := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.SyncPolicy(ctx, adapter)
	if err != nil {
		t.Fatalf("expected recovery to succeed, got: %v", err)
	}

	// After successful sync, phase should be Active
	if policy.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected PhaseActive after recovery, got %s", policy.Status.Phase)
	}
}

// --- CleanupPolicy tests (Gap 7) ---

func TestCleanupPolicy_VaultClientUnavailable(t *testing.T) {
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	policy.Status.Phase = vaultv1alpha1.PhaseActive

	scheme := newPolicyTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, policy).
		WithStatusSubresource(conn, policy).
		Build()

	// Empty cache — no Vault client available
	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(k8sClient, cache, bus, logr.Discard())

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.CleanupPolicy(ctx, adapter)
	// CleanupPolicy should succeed even when Vault is unavailable
	// (it logs the error and continues with finalizer removal)
	if err != nil {
		t.Errorf("CleanupPolicy should succeed even without Vault client, got: %v", err)
	}
}

func TestCleanupPolicy_PolicyNotInVault(t *testing.T) {
	state := newPolicyMockState()
	// State is empty — no policies in Vault
	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	policy.Status.Phase = vaultv1alpha1.PhaseActive

	handler, server, _ := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.CleanupPolicy(ctx, adapter)
	// Should succeed — deleting a non-existent policy is a no-op
	if err != nil {
		t.Errorf("CleanupPolicy should succeed for non-existent policy, got: %v", err)
	}
}

func TestCleanupPolicy_RetainPolicy(t *testing.T) {
	state := newPolicyMockState()
	policyName := policyTestNamespace + "-" + policyTestName
	state.policies[policyName] = existingPolicyHCL

	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	policy.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyRetain
	policy.Status.Phase = vaultv1alpha1.PhaseActive

	handler, server, _ := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.CleanupPolicy(ctx, adapter)
	if err != nil {
		t.Fatalf("CleanupPolicy failed: %v", err)
	}

	// Policy should still exist in Vault (Retain)
	state.mu.Lock()
	_, exists := state.policies[policyName]
	state.mu.Unlock()

	if !exists {
		t.Error("expected policy to be retained in Vault with DeletionPolicy=Retain")
	}
}

func TestCleanupPolicy_DeletePolicy(t *testing.T) {
	state := newPolicyMockState()
	policyName := policyTestNamespace + "-" + policyTestName
	state.policies[policyName] = existingPolicyHCL

	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	policy.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyDelete
	policy.Status.Phase = vaultv1alpha1.PhaseActive

	handler, server, _ := setupPolicySyncTest(t, policy, conn, policyMockConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultPolicyAdapter(policy)

	err := handler.CleanupPolicy(ctx, adapter)
	if err != nil {
		t.Fatalf("CleanupPolicy failed: %v", err)
	}

	// Policy should be removed from Vault (Delete)
	state.mu.Lock()
	_, exists := state.policies[policyName]
	state.mu.Unlock()

	if exists {
		t.Error("expected policy to be deleted from Vault with DeletionPolicy=Delete")
	}
}

// policyKeys returns the keys of a string map.
func policyKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
