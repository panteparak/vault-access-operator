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
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// --- Mock Vault HTTP server infrastructure ---

// mockVaultState holds the in-memory state of the mock Vault server.
type mockVaultState struct {
	mu sync.Mutex
	// roles maps authPath/roleName to role data
	roles map[string]map[string]interface{}
	// policies maps policyName to HCL content
	policies map[string]string
	// managed maps resourcePath to managed metadata
	managed map[string]map[string]interface{}
}

func newMockVaultState() *mockVaultState {
	return &mockVaultState{
		roles:    make(map[string]map[string]interface{}),
		policies: make(map[string]string),
		managed:  make(map[string]map[string]interface{}),
	}
}

// mockNormalizeTTLFields simulates Vault's TTL normalization: duration strings → integer seconds.
func mockNormalizeTTLFields(data map[string]interface{}) {
	for _, field := range []string{"token_ttl", "token_max_ttl"} {
		if v, ok := data[field]; ok {
			if s, ok := v.(string); ok {
				if d, err := time.ParseDuration(s); err == nil {
					data[field] = json.Number(fmt.Sprintf("%d", int(d.Seconds())))
				}
			}
		}
	}
}

// mockVaultServerConfig configures the mock Vault server behavior.
type mockVaultServerConfig struct {
	state        *mockVaultState
	writeRoleErr bool // simulate role write failure
	readRoleErr  bool // simulate role read failure
	listPolicies []string
}

// newMockVaultServer creates an httptest.Server that handles Vault API endpoints
// needed by SyncRole and SyncPolicy.
func newMockVaultServer(cfg mockVaultServerConfig) *httptest.Server {
	if cfg.state == nil {
		cfg.state = newMockVaultState()
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Strip /v1/ prefix
		apiPath := strings.TrimPrefix(path, "/v1/")

		switch {
		// --- Managed metadata (KV v2) --- must match before role CRUD
		case strings.HasPrefix(apiPath, "secret/data/vault-access-operator/managed/"):
			metadataPath := apiPath
			cfg.state.mu.Lock()
			defer cfg.state.mu.Unlock()

			switch r.Method {
			case http.MethodPut, http.MethodPost:
				var body map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&body)
				cfg.state.managed[metadataPath] = body
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"version": 1,
					},
				})

			case http.MethodGet:
				data, exists := cfg.state.managed[metadataPath]
				if !exists {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": data,
				})

			case http.MethodDelete:
				delete(cfg.state.managed, metadataPath)
				w.WriteHeader(http.StatusNoContent)
			}

		// --- List managed metadata (KV v2) ---
		case strings.HasPrefix(apiPath, "secret/metadata/vault-access-operator/managed/"):
			cfg.state.mu.Lock()
			defer cfg.state.mu.Unlock()

			prefix := strings.Replace(apiPath, "secret/metadata/", "secret/data/", 1) + "/"

			var keys []interface{}
			for k := range cfg.state.managed {
				if strings.HasPrefix(k, prefix) {
					name := strings.TrimPrefix(k, prefix)
					keys = append(keys, name)
				}
			}

			if len(keys) == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": keys,
				},
			})

		// --- Kubernetes auth role CRUD ---
		// Path format: auth/{mount}/role/{name}
		case strings.Contains(apiPath, "/role/") &&
			!strings.HasPrefix(apiPath, "secret/") &&
			!strings.HasPrefix(apiPath, "sys/"):
			// Use the full API path as the state key (e.g. "auth/kubernetes/role/my-role")
			key := apiPath
			cfg.state.mu.Lock()
			defer cfg.state.mu.Unlock()

			switch r.Method {
			case http.MethodPut, http.MethodPost:
				if cfg.writeRoleErr {
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"internal error"},
					})
					return
				}
				var data map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&data)
				mockNormalizeTTLFields(data)
				cfg.state.roles[key] = data
				w.WriteHeader(http.StatusNoContent)

			case http.MethodGet:
				if cfg.readRoleErr {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				data, exists := cfg.state.roles[key]
				if !exists {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": data,
				})

			case http.MethodDelete:
				delete(cfg.state.roles, key)
				w.WriteHeader(http.StatusNoContent)
			}

		// --- Policy CRUD ---
		case strings.HasPrefix(apiPath, "sys/policies/acl/"):
			policyName := strings.TrimPrefix(apiPath, "sys/policies/acl/")
			cfg.state.mu.Lock()
			defer cfg.state.mu.Unlock()

			switch r.Method {
			case http.MethodPut, http.MethodPost:
				var data map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&data)
				if policy, ok := data["policy"].(string); ok {
					cfg.state.policies[policyName] = policy
				}
				w.WriteHeader(http.StatusNoContent)

			case http.MethodGet:
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
			}

		// --- Policy list (Vault SDK v1.22 uses GET /v1/sys/policies/acl?list=true) ---
		case apiPath == "sys/policies/acl" && r.URL.Query().Get("list") == "true":
			cfg.state.mu.Lock()
			defer cfg.state.mu.Unlock()

			names := cfg.listPolicies
			if names == nil {
				names = []string{"default", "root"}
				for name := range cfg.state.policies {
					names = append(names, name)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": names,
				},
			})

		// --- Default: health/other ---
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
	testConnName      = "test-connection"
	testNamespace     = "test-ns"
	testRoleName      = "test-role"
	testTokenMaxTTL   = "24h"
	testDriftedPolicy = "DRIFTED-policy"
)

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = vaultv1alpha1.AddToScheme(scheme)
	return scheme
}

// newTestVaultConnection creates a VaultConnection for testing with Active phase.
func newTestVaultConnection() *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testConnName,
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

// newTestVaultRole creates a VaultRole for testing.
func newTestVaultRole() *vaultv1alpha1.VaultRole {
	return &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testRoleName,
			Namespace:  testNamespace,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef: testConnName,
			ServiceAccounts: []string{
				"app-sa",
			},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "app-read"},
			},
		},
	}
}

// newTestCachedVaultClient creates a real *vault.Client pointed at the test server.
func newTestCachedVaultClient(t *testing.T, serverURL string) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: serverURL})
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	c.SetAuthenticated(true)
	c.SetToken("s.test-token")
	return c
}

// setupSyncRoleTest creates all dependencies for testing SyncRole.
func setupSyncRoleTest(
	t *testing.T,
	role *vaultv1alpha1.VaultRole,
	conn *vaultv1alpha1.VaultConnection,
	serverCfg mockVaultServerConfig,
) (*Handler, *httptest.Server, *events.EventBus) {
	t.Helper()

	server := newMockVaultServer(serverCfg)

	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, role).
		WithStatusSubresource(conn, role).
		Build()

	cache := vault.NewClientCache()
	vaultClient := newTestCachedVaultClient(t, server.URL)
	cache.Set(conn.Name, vaultClient)

	bus := events.NewEventBus(logr.Discard())

	handler := NewHandler(k8sClient, cache, bus, logr.Discard())

	return handler, server, bus
}

// --- SyncRole Tests ---

func TestSyncRole_Success_NewRole(t *testing.T) {
	state := newMockVaultState()
	conn := newTestVaultConnection()
	role := newTestVaultRole()

	handler, server, _ := setupSyncRoleTest(t, role, conn, mockVaultServerConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.SyncRole(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncRole failed: %v", err)
	}

	// Verify role was written to mock Vault
	expectedKey := "auth/kubernetes/role/" + testNamespace + "-" + testRoleName
	state.mu.Lock()
	roleData, exists := state.roles[expectedKey]
	state.mu.Unlock()

	if !exists {
		t.Fatalf("role not written to Vault; keys: %v", keysOf(state.roles))
	}

	// Verify role data contains expected fields
	policies, _ := roleData["policies"].([]interface{})
	if len(policies) == 0 {
		t.Error("expected policies in role data")
	}

	saNames, _ := roleData["bound_service_account_names"].([]interface{})
	if len(saNames) == 0 {
		t.Error("expected bound_service_account_names in role data")
	}

	saNamespaces, _ := roleData["bound_service_account_namespaces"].([]interface{})
	if len(saNamespaces) == 0 {
		t.Error("expected bound_service_account_namespaces in role data")
	}
}

func TestSyncRole_Success_WithTTL(t *testing.T) {
	state := newMockVaultState()
	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Spec.TokenTTL = "1h"
	role.Spec.TokenMaxTTL = testTokenMaxTTL

	handler, server, _ := setupSyncRoleTest(t, role, conn, mockVaultServerConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.SyncRole(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncRole failed: %v", err)
	}

	// Verify TTL fields
	expectedKey := "auth/kubernetes/role/" + testNamespace + "-" + testRoleName
	state.mu.Lock()
	roleData := state.roles[expectedKey]
	state.mu.Unlock()

	// Mock normalizes TTLs to integer seconds (like real Vault): "1h" → json.Number("3600")
	if fmt.Sprintf("%v", roleData["token_ttl"]) != "3600" {
		t.Errorf("expected token_ttl=3600 (1h in seconds), got %v", roleData["token_ttl"])
	}
	if fmt.Sprintf("%v", roleData["token_max_ttl"]) != "86400" {
		t.Errorf("expected token_max_ttl=86400 (24h in seconds), got %v", roleData["token_max_ttl"])
	}
}

func TestSyncRole_Success_ClusterRole(t *testing.T) {
	state := newMockVaultState()
	conn := newTestVaultConnection()

	clusterRole := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cluster-reader",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			ConnectionRef: testConnName,
			ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "sa-1", Namespace: "ns-a"},
				{Name: "sa-2", Namespace: "ns-b"},
			},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultClusterPolicy", Name: "admin-base"},
			},
		},
	}

	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, clusterRole).
		WithStatusSubresource(conn, clusterRole).
		Build()

	cache := vault.NewClientCache()
	server := newMockVaultServer(mockVaultServerConfig{state: state})
	defer server.Close()

	vaultClient := newTestCachedVaultClient(t, server.URL)
	cache.Set(testConnName, vaultClient)

	handler := NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	err := handler.SyncRole(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncRole failed: %v", err)
	}

	// Cluster roles use just the name, not namespace-name
	expectedKey := "auth/kubernetes/role/cluster-reader"
	state.mu.Lock()
	roleData, exists := state.roles[expectedKey]
	state.mu.Unlock()

	if !exists {
		t.Fatalf("cluster role not written to Vault; keys: %v", keysOf(state.roles))
	}

	// Verify multi-namespace bindings
	saNamespaces, _ := roleData["bound_service_account_namespaces"].([]interface{})
	if len(saNamespaces) < 2 {
		t.Errorf("expected at least 2 namespaces, got %d: %v", len(saNamespaces), saNamespaces)
	}
}

func TestSyncRole_ConflictError_Adopt(t *testing.T) {
	state := newMockVaultState()
	// Pre-populate an existing role in Vault (unmanaged)
	state.roles["auth/kubernetes/role/"+testNamespace+"-"+testRoleName] = map[string]interface{}{
		"policies": []interface{}{"old-policy"},
	}

	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Annotations = map[string]string{
		vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue,
	}

	handler, server, _ := setupSyncRoleTest(t, role, conn, mockVaultServerConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.SyncRole(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncRole with adopt should succeed: %v", err)
	}
}

func TestSyncRole_ConflictError_Fail(t *testing.T) {
	state := newMockVaultState()
	vaultRoleName := testNamespace + "-" + testRoleName
	// Pre-populate an existing role managed by someone else
	state.roles["auth/kubernetes/role/"+vaultRoleName] = map[string]interface{}{
		"policies": []interface{}{"old-policy"},
	}
	// Mark as managed by a different resource
	// The managed path uses full API path: secret/data/vault-access-operator/managed/roles/{name}
	managedKey := fmt.Sprintf("secret/data/vault-access-operator/managed/roles/%s", vaultRoleName)
	state.managed[managedKey] = map[string]interface{}{
		"data": map[string]interface{}{
			"metadata": `{"k8sResource":"other-ns/other-role",` +
				`"managedAt":"2026-01-01T00:00:00Z",` +
				`"lastUpdated":"2026-01-01T00:00:00Z"}`,
		},
	}

	conn := newTestVaultConnection()
	role := newTestVaultRole()

	handler, server, _ := setupSyncRoleTest(t, role, conn, mockVaultServerConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.SyncRole(ctx, adapter)
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}

	if !strings.Contains(err.Error(), "conflict") {
		t.Errorf("expected conflict error, got: %v", err)
	}
}

func TestSyncRole_VaultWriteError(t *testing.T) {
	conn := newTestVaultConnection()
	role := newTestVaultRole()

	handler, server, _ := setupSyncRoleTest(t, role, conn, mockVaultServerConfig{
		writeRoleErr: true,
	})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.SyncRole(ctx, adapter)
	if err == nil {
		t.Fatal("expected write error, got nil")
	}
}

func TestSyncRole_ConnectionNotReady(t *testing.T) {
	conn := newTestVaultConnection()
	conn.Status.Phase = vaultv1alpha1.PhasePending // Not Active

	role := newTestVaultRole()

	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, role).
		WithStatusSubresource(conn, role).
		Build()

	cache := vault.NewClientCache()
	// Don't put a client in cache - the connection is not ready

	handler := NewHandler(k8sClient, cache, nil, logr.Discard())

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.SyncRole(ctx, adapter)
	if err == nil {
		t.Fatal("expected dependency error, got nil")
	}

	if !strings.Contains(err.Error(), "not ready") {
		t.Errorf("expected 'not ready' error, got: %v", err)
	}
}

func TestSyncRole_DriftDetect_NoDrift(t *testing.T) {
	state := newMockVaultState()
	vaultRoleName := testNamespace + "-" + testRoleName

	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Spec.DriftMode = vaultv1alpha1.DriftModeDetect

	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, role).
		WithStatusSubresource(conn, role).
		Build()

	cache := vault.NewClientCache()
	server := newMockVaultServer(mockVaultServerConfig{state: state})
	defer server.Close()

	vaultClient := newTestCachedVaultClient(t, server.URL)
	cache.Set(testConnName, vaultClient)

	handler := NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	ctx := logr.NewContext(context.Background(), logr.Discard())

	// First sync to populate Vault and get a hash
	adapter := domain.NewVaultRoleAdapter(role)
	if err := handler.SyncRole(ctx, adapter); err != nil {
		t.Fatalf("initial SyncRole failed: %v", err)
	}

	// Re-fetch the role from K8s to get updated status with hash
	var updatedRole vaultv1alpha1.VaultRole
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	// Second sync with same spec, Vault unchanged → no drift
	updatedRole.Status.Phase = vaultv1alpha1.PhaseActive
	adapter2 := domain.NewVaultRoleAdapter(&updatedRole)

	err := handler.SyncRole(ctx, adapter2)
	if err != nil {
		t.Fatalf("SyncRole failed on second sync: %v", err)
	}

	// Verify role still exists in Vault
	state.mu.Lock()
	_, exists := state.roles["auth/kubernetes/role/"+vaultRoleName]
	state.mu.Unlock()

	if !exists {
		t.Error("role should still exist in Vault")
	}
}

func TestSyncRole_DriftDetect_WithDrift(t *testing.T) {
	state := newMockVaultState()
	vaultRoleName := testNamespace + "-" + testRoleName

	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Spec.DriftMode = vaultv1alpha1.DriftModeDetect

	// Build the expected roleData and compute its hash to pre-seed the status.
	// This simulates a role that was previously synced successfully.
	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, role).
		WithStatusSubresource(conn, role).
		Build()

	cache := vault.NewClientCache()
	server := newMockVaultServer(mockVaultServerConfig{state: state})
	defer server.Close()

	vaultClient := newTestCachedVaultClient(t, server.URL)
	cache.Set(testConnName, vaultClient)

	handler := NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	ctx := logr.NewContext(context.Background(), logr.Discard())

	// First sync to establish hash and write to Vault
	adapter := domain.NewVaultRoleAdapter(role)
	if err := handler.SyncRole(ctx, adapter); err != nil {
		t.Fatalf("initial SyncRole failed: %v", err)
	}

	// Re-fetch the role from the fake K8s client to get the status with hash
	var updatedRole vaultv1alpha1.VaultRole
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	// Verify hash was set
	if updatedRole.Status.LastAppliedHash == "" {
		t.Fatal("expected LastAppliedHash to be set after first sync")
	}

	// Now mutate the Vault state to simulate drift
	roleKey := "auth/kubernetes/role/" + vaultRoleName
	state.mu.Lock()
	state.roles[roleKey] = map[string]interface{}{
		"policies":                         []interface{}{testDriftedPolicy},
		"bound_service_account_names":      []interface{}{"app-sa"},
		"bound_service_account_namespaces": []interface{}{testNamespace},
	}
	state.mu.Unlock()

	// Second sync: use the updated role with hash set
	updatedRole.Status.Phase = vaultv1alpha1.PhaseActive
	adapter2 := domain.NewVaultRoleAdapter(&updatedRole)

	err := handler.SyncRole(ctx, adapter2)
	// In detect mode with same hash, drift is reported but not corrected → nil error
	if err != nil {
		t.Fatalf("SyncRole should not error in detect mode: %v", err)
	}

	// Verify Vault was NOT overwritten (detect mode)
	state.mu.Lock()
	roleData := state.roles[roleKey]
	state.mu.Unlock()

	policies, _ := roleData["policies"].([]interface{})
	if len(policies) > 0 {
		firstPolicy, _ := policies[0].(string)
		if firstPolicy != testDriftedPolicy {
			t.Errorf("detect mode should NOT overwrite; expected DRIFTED-policy, got %v", firstPolicy)
		}
	}
}

func TestSyncRole_DriftCorrect_WithAnnotation(t *testing.T) {
	state := newMockVaultState()
	vaultRoleName := testNamespace + "-" + testRoleName

	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Spec.DriftMode = vaultv1alpha1.DriftModeCorrect
	role.Annotations = map[string]string{
		vaultv1alpha1.AnnotationAllowDestructive: vaultv1alpha1.AnnotationValueTrue,
	}

	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, role).
		WithStatusSubresource(conn, role).
		Build()

	cache := vault.NewClientCache()
	server := newMockVaultServer(mockVaultServerConfig{state: state})
	defer server.Close()

	vaultClient := newTestCachedVaultClient(t, server.URL)
	cache.Set(testConnName, vaultClient)

	handler := NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	ctx := logr.NewContext(context.Background(), logr.Discard())

	// First sync
	adapter := domain.NewVaultRoleAdapter(role)
	if err := handler.SyncRole(ctx, adapter); err != nil {
		t.Fatalf("initial SyncRole failed: %v", err)
	}

	// Re-fetch role to get hash
	var updatedRole vaultv1alpha1.VaultRole
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	// Simulate drift in Vault
	roleKey := "auth/kubernetes/role/" + vaultRoleName
	state.mu.Lock()
	state.roles[roleKey] = map[string]interface{}{
		"policies":                         []interface{}{testDriftedPolicy},
		"bound_service_account_names":      []interface{}{"app-sa"},
		"bound_service_account_namespaces": []interface{}{testNamespace},
	}
	state.mu.Unlock()

	// Re-sync with correct mode + destructive annotation
	updatedRole.Status.Phase = vaultv1alpha1.PhaseActive
	adapter2 := domain.NewVaultRoleAdapter(&updatedRole)

	err := handler.SyncRole(ctx, adapter2)
	if err != nil {
		t.Fatalf("SyncRole should correct drift with annotation: %v", err)
	}

	// Verify Vault WAS overwritten (correct mode with annotation)
	state.mu.Lock()
	roleData := state.roles[roleKey]
	state.mu.Unlock()

	policies, _ := roleData["policies"].([]interface{})
	if len(policies) > 0 {
		firstPolicy, _ := policies[0].(string)
		if firstPolicy == testDriftedPolicy {
			t.Error("correct mode with annotation should overwrite drifted data")
		}
	}
}

func TestSyncRole_DriftCorrect_BlockedWithoutAnnotation(t *testing.T) {
	state := newMockVaultState()
	vaultRoleName := testNamespace + "-" + testRoleName

	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Spec.DriftMode = vaultv1alpha1.DriftModeCorrect
	// No AnnotationAllowDestructive

	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, role).
		WithStatusSubresource(conn, role).
		Build()

	cache := vault.NewClientCache()
	server := newMockVaultServer(mockVaultServerConfig{state: state})
	defer server.Close()

	vaultClient := newTestCachedVaultClient(t, server.URL)
	cache.Set(testConnName, vaultClient)

	handler := NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	ctx := logr.NewContext(context.Background(), logr.Discard())

	// First sync
	adapter := domain.NewVaultRoleAdapter(role)
	if err := handler.SyncRole(ctx, adapter); err != nil {
		t.Fatalf("initial SyncRole failed: %v", err)
	}

	// Re-fetch role to get hash
	var updatedRole vaultv1alpha1.VaultRole
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	// Simulate drift
	roleKey := "auth/kubernetes/role/" + vaultRoleName
	state.mu.Lock()
	state.roles[roleKey] = map[string]interface{}{
		"policies":                         []interface{}{testDriftedPolicy},
		"bound_service_account_names":      []interface{}{"app-sa"},
		"bound_service_account_namespaces": []interface{}{testNamespace},
	}
	state.mu.Unlock()

	// Re-sync without annotation → should set PhaseConflict
	updatedRole.Status.Phase = vaultv1alpha1.PhaseActive
	adapter2 := domain.NewVaultRoleAdapter(&updatedRole)

	err := handler.SyncRole(ctx, adapter2)
	// Blocked drift correction returns nil (status updated, no retry needed)
	if err != nil {
		t.Fatalf("SyncRole should return nil when drift is blocked: %v", err)
	}

	// Verify Vault was NOT overwritten
	state.mu.Lock()
	roleData := state.roles[roleKey]
	state.mu.Unlock()

	policies, _ := roleData["policies"].([]interface{})
	if len(policies) > 0 {
		firstPolicy, _ := policies[0].(string)
		if firstPolicy != testDriftedPolicy {
			t.Error("blocked correction should NOT overwrite drifted data")
		}
	}
}

func TestSyncRole_SkipWhenHashUnchanged(t *testing.T) {
	state := newMockVaultState()

	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Spec.DriftMode = vaultv1alpha1.DriftModeIgnore

	handler, server, _ := setupSyncRoleTest(t, role, conn, mockVaultServerConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	// First sync
	if err := handler.SyncRole(ctx, adapter); err != nil {
		t.Fatalf("initial SyncRole failed: %v", err)
	}

	// The handler should have written the role. Now sync again with the same spec.
	// With ignore mode and same hash+Active, the role should still be written
	// (ignore mode doesn't skip writes, it skips drift detection).
	role.Status.Phase = vaultv1alpha1.PhaseActive
	adapter2 := domain.NewVaultRoleAdapter(role)

	err := handler.SyncRole(ctx, adapter2)
	if err != nil {
		t.Fatalf("second SyncRole failed: %v", err)
	}
}

func TestSyncRole_EventPublished(t *testing.T) {
	state := newMockVaultState()
	conn := newTestVaultConnection()
	role := newTestVaultRole()

	handler, server, bus := setupSyncRoleTest(t, role, conn, mockVaultServerConfig{state: state})
	defer server.Close()

	// Subscribe to RoleCreated events using a channel for race-free synchronization
	eventCh := make(chan events.RoleCreated, 1)
	events.Subscribe(bus, func(_ context.Context, e events.RoleCreated) error {
		eventCh <- e
		return nil
	})

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.SyncRole(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncRole failed: %v", err)
	}

	// Wait for async event delivery
	select {
	case e := <-eventCh:
		expectedRoleName := testNamespace + "-" + testRoleName
		if e.RoleName != expectedRoleName {
			t.Errorf("expected RoleName=%s, got %s", expectedRoleName, e.RoleName)
		}
		if e.AuthPath != "auth/kubernetes" {
			t.Errorf("expected AuthPath=auth/kubernetes, got %s", e.AuthPath)
		}
		if e.Resource.Name != testRoleName {
			t.Errorf("expected Resource.Name=%s, got %s", testRoleName, e.Resource.Name)
		}
		if e.Resource.Namespace != testNamespace {
			t.Errorf("expected Resource.Namespace=%s, got %s", testNamespace, e.Resource.Namespace)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for RoleCreated event")
	}
}

func TestSyncRole_NoEventBus(t *testing.T) {
	state := newMockVaultState()
	conn := newTestVaultConnection()
	role := newTestVaultRole()

	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, role).
		WithStatusSubresource(conn, role).
		Build()

	cache := vault.NewClientCache()
	server := newMockVaultServer(mockVaultServerConfig{state: state})
	defer server.Close()

	vaultClient := newTestCachedVaultClient(t, server.URL)
	cache.Set(testConnName, vaultClient)

	// Create handler with nil event bus
	handler := NewHandler(k8sClient, cache, nil, logr.Discard())

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	// Should not panic
	err := handler.SyncRole(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncRole with nil eventBus should not fail: %v", err)
	}
}

func TestSyncRole_ConflictPolicy_Adopt(t *testing.T) {
	state := newMockVaultState()
	// Pre-populate an existing role (unmanaged)
	state.roles["auth/kubernetes/role/"+testNamespace+"-"+testRoleName] = map[string]interface{}{
		"policies": []interface{}{"existing-policy"},
	}

	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Spec.ConflictPolicy = vaultv1alpha1.ConflictPolicyAdopt

	handler, server, _ := setupSyncRoleTest(t, role, conn, mockVaultServerConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.SyncRole(ctx, adapter)
	if err != nil {
		t.Fatalf("SyncRole with ConflictPolicy=Adopt should succeed: %v", err)
	}
}

// --- CleanupRole tests (Gap 7) ---

func TestCleanupRole_VaultClientUnavailable(t *testing.T) {
	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Status.Phase = vaultv1alpha1.PhaseActive

	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, role).
		WithStatusSubresource(conn, role).
		Build()

	// Empty cache — no Vault client available
	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(k8sClient, cache, bus, logr.Discard())

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.CleanupRole(ctx, adapter)
	// CleanupRole should succeed even when Vault is unavailable
	if err != nil {
		t.Errorf("CleanupRole should succeed even without Vault client, got: %v", err)
	}
}

func TestCleanupRole_RoleNotInVault(t *testing.T) {
	state := newMockVaultState()
	// State is empty — no roles in Vault
	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Status.Phase = vaultv1alpha1.PhaseActive

	handler, server, _ := setupSyncRoleTest(t, role, conn, mockVaultServerConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.CleanupRole(ctx, adapter)
	// Deleting a non-existent role is a no-op
	if err != nil {
		t.Errorf("CleanupRole should succeed for non-existent role, got: %v", err)
	}
}

func TestCleanupRole_RetainPolicy(t *testing.T) {
	state := newMockVaultState()
	rolePath := "auth/kubernetes/role/" + testNamespace + "-" + testRoleName
	state.roles[rolePath] = map[string]interface{}{
		"policies": []interface{}{"test-policy"},
	}

	conn := newTestVaultConnection()
	role := newTestVaultRole()
	role.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyRetain
	role.Status.Phase = vaultv1alpha1.PhaseActive

	handler, server, _ := setupSyncRoleTest(t, role, conn, mockVaultServerConfig{state: state})
	defer server.Close()

	ctx := logr.NewContext(context.Background(), logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	err := handler.CleanupRole(ctx, adapter)
	if err != nil {
		t.Fatalf("CleanupRole failed: %v", err)
	}

	// Role should still exist in Vault (Retain)
	state.mu.Lock()
	_, exists := state.roles[rolePath]
	state.mu.Unlock()

	if !exists {
		t.Error("expected role to be retained in Vault with DeletionPolicy=Retain")
	}
}

// keysOf returns the keys of a map for debugging.
func keysOf[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
