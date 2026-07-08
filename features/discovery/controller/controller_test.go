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
	"net/http"
	"net/http/httptest"
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
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/markers"
)

// newTestScheme creates a scheme with the required types registered.
func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = vaultv1alpha1.AddToScheme(scheme)
	return scheme
}

// newMockVaultServer creates an httptest server that handles the Vault API
// endpoints used by the discovery scanner.
//
// Parameters control what the server returns:
//   - policies: policy names in Vault (GET /v1/sys/policies/acl)
//   - roles: role names on the kubernetes auth mount (LIST /v1/auth/kubernetes/role)
//   - managedPolicies: vault names of managed policies — seeded as markers so
//     ListManaged(MarkerPolicy) keys them exactly (matched against policyName)
//   - managedRoles: vault names of managed roles on the kubernetes mount —
//     seeded so ListManaged(MarkerRole) keys them "kubernetes/{name}"
//
// Managed markers are custom_metadata only, at hierarchical metadata paths. Each
// managed name is seeded as a cluster-scoped marker (_cluster segment) so its
// derived ListManaged key is the bare vault name (roles gain the mount prefix).
// newMockVaultServer serves the read-only Vault surface discovery scans:
// policy list + per-policy reads (in-band ownership headers, ADR 0008) and a
// role list on auth/kubernetes. managedPolicies get a header naming THIS
// operator (auth-mount "kubernetes"); everything else is unmanaged.
func newMockVaultServer(policies, roles, managedPolicies []string) *httptest.Server {
	hcls := map[string]string{}
	for _, p := range policies {
		hcls[p] = "path \"secret/*\" {\n  capabilities = [\"read\"]\n}\n"
	}
	for _, p := range managedPolicies {
		hcls[p] = vault.OwnershipHeader(vault.Ownership{
			ManagedBy:   vault.KVManagedByValue,
			AuthMount:   "kubernetes",
			K8sResource: "test/test-resource",
			K8sKind:     "VaultPolicy",
		}) + "\n" + hcls[p]
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")

		switch {
		// ListPolicies: GET /v1/sys/policies/acl?list=true → {"data":{"keys":[...]}}
		case path == "/v1/sys/policies/acl":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": policies},
			})

		// ReadPolicy: GET /v1/sys/policies/acl/{name}
		case strings.HasPrefix(path, "/v1/sys/policies/acl/"):
			name := strings.TrimPrefix(path, "/v1/sys/policies/acl/")
			hcl, ok := hcls[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"name": name, "policy": hcl},
			})

		// ListKubernetesAuthRoles: LIST /v1/auth/kubernetes/role
		case path == "/v1/auth/kubernetes/role":
			keys := make([]interface{}, len(roles))
			for i, rl := range roles {
				keys[i] = rl
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": keys},
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// newVaultClientFromServer creates a vault.Client connected to the test server
// and stores it in the provided cache under the given connection name.
func newVaultClientFromServer(t *testing.T, server *httptest.Server, cache *vault.ClientCache, connName string) {
	t.Helper()
	vc, err := vault.NewClient(vault.ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	// The operator's identity (ADR 0008) — headers written by "this" operator
	// carry the same mount, so managed-set detection matches.
	vc.SetAuthMount("kubernetes")
	cache.Set(connName, vc)
}

// testConnName is the canonical connection name used by discovery controller tests.
// Extracted as a constant because it appears enough times (4+) that the goconst
// linter flags the raw strings.
const testConnName = "test-conn"

// newVaultConnection creates a VaultConnection object for testing.
func newVaultConnection(
	discovery *vaultv1alpha1.DiscoveryConfig,
	discoveryStatus *vaultv1alpha1.DiscoveryStatus,
) *vaultv1alpha1.VaultConnection {
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name: testConnName,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault.example.com:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Token: &vaultv1alpha1.TokenAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name: "vault-token",
						Key:  "token",
					},
				},
			},
			// Token auth has no login mount — role scanning targets the
			// explicitly declared role mount, like any real token-auth
			// connection that manages roles.
			Defaults:  &vaultv1alpha1.ConnectionDefaults{AuthPath: "kubernetes"},
			Discovery: discovery,
		},
	}
	if discoveryStatus != nil {
		conn.Status.DiscoveryStatus = discoveryStatus
	}
	return conn
}

func TestReconcile_DiscoveryDisabled_Nil(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(nil, nil)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-conn"},
	})

	if err != nil {
		t.Fatalf("Reconcile() error = %v, want nil", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("Reconcile() RequeueAfter = %v, want 0", result.RequeueAfter)
	}
}

func TestReconcile_DiscoveryDisabled_False(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{
		Enabled: false,
	}, nil)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-conn"},
	})

	if err != nil {
		t.Fatalf("Reconcile() error = %v, want nil", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("Reconcile() RequeueAfter = %v, want 0", result.RequeueAfter)
	}
}

func TestReconcile_FirstScan_Success(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{
		Enabled:  true,
		Interval: "1h",
	}, nil)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	server := newMockVaultServer(
		[]string{"default", "root", "app-policy"},
		[]string{"app-role"},
		nil, // no managed policies
	)
	defer server.Close()

	cache := vault.NewClientCache()
	newVaultClientFromServer(t, server, cache, "test-conn")

	recorder := record.NewFakeRecorder(10)
	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: cache,
		Log:         logr.Discard(),
		Recorder:    recorder,
	})

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-conn"},
	})

	if err != nil {
		t.Fatalf("Reconcile() error = %v, want nil", err)
	}
	if result.RequeueAfter != time.Hour {
		t.Errorf("Reconcile() RequeueAfter = %v, want %v", result.RequeueAfter, time.Hour)
	}

	// Verify status was updated
	var updated vaultv1alpha1.VaultConnection
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: "test-conn"}, &updated); err != nil {
		t.Fatalf("failed to get updated VaultConnection: %v", err)
	}
	if updated.Status.DiscoveryStatus == nil {
		t.Fatal("DiscoveryStatus should not be nil after scan")
	}
	if updated.Status.DiscoveryStatus.LastScanAt == nil {
		t.Error("LastScanAt should be set after scan")
	}
}

func TestReconcile_NotYetDue(t *testing.T) {
	scheme := newTestScheme()
	recentScan := metav1.NewTime(time.Now().Add(-10 * time.Minute))
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{
		Enabled:  true,
		Interval: "1h",
	}, &vaultv1alpha1.DiscoveryStatus{
		LastScanAt: &recentScan,
	})

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-conn"},
	})

	if err != nil {
		t.Fatalf("Reconcile() error = %v, want nil", err)
	}
	// Should requeue for the remaining time (~50 minutes)
	if result.RequeueAfter <= 0 {
		t.Error("Reconcile() should return RequeueAfter > 0 when scan is not yet due")
	}
	if result.RequeueAfter > time.Hour {
		t.Errorf("Reconcile() RequeueAfter = %v, should be less than scan interval", result.RequeueAfter)
	}
}

func TestReconcile_NoVaultClient(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{
		Enabled:  true,
		Interval: "1h",
	}, nil)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	// Empty cache — no vault client registered
	cache := vault.NewClientCache()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: cache,
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-conn"},
	})

	if err != nil {
		t.Fatalf("Reconcile() error = %v, want nil (should requeue, not error)", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("Reconcile() should requeue when vault client is not in cache")
	}
}

func TestReconcile_ConnectionNotFound(t *testing.T) {
	scheme := newTestScheme()

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent"},
	})

	if err != nil {
		t.Fatalf("Reconcile() error = %v, want nil for not-found", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("Reconcile() RequeueAfter = %v, want 0 for not-found", result.RequeueAfter)
	}
}

func TestReconcile_FindsUnmanagedResources(t *testing.T) {
	// Managed-set filtering only means anything with marker tracking on.
	markers.SetEnabled(true)
	t.Cleanup(func() { markers.SetEnabled(false) })

	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{
		Enabled:  true,
		Interval: "1h",
	}, nil)
	managedRoleCR := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "managed-role"},
		// Ownership is derived via the connection: this CR references the
		// scanned connection, whose defaults.authPath resolves the mount.
		Spec: vaultv1alpha1.VaultClusterRoleSpec{ConnectionRef: testConnName},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, managedRoleCR).
		WithStatusSubresource(conn).
		Build()

	// Vault has 4 policies (default, root are system), app-policy is unmanaged,
	// managed-policy carries our in-band ownership header. Roles: app-role is
	// unmanaged; managed-role is derived from the VaultClusterRole CR below
	// (roles have no in-band record — the CR set is the ownership source).
	server := newMockVaultServer(
		[]string{"default", "root", "app-policy", "managed-policy"},
		[]string{"app-role", "managed-role"},
		[]string{"managed-policy"},
	)
	defer server.Close()

	cache := vault.NewClientCache()
	newVaultClientFromServer(t, server, cache, "test-conn")

	recorder := record.NewFakeRecorder(10)
	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: cache,
		Log:         logr.Discard(),
		Recorder:    recorder,
	})

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-conn"},
	})

	if err != nil {
		t.Fatalf("Reconcile() error = %v, want nil", err)
	}
	if result.RequeueAfter != time.Hour {
		t.Errorf("Reconcile() RequeueAfter = %v, want %v", result.RequeueAfter, time.Hour)
	}

	// Verify status was updated with correct counts
	var updated vaultv1alpha1.VaultConnection
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: "test-conn"}, &updated); err != nil {
		t.Fatalf("failed to get updated VaultConnection: %v", err)
	}
	if updated.Status.DiscoveryStatus == nil {
		t.Fatal("DiscoveryStatus should not be nil")
	}
	if updated.Status.DiscoveryStatus.UnmanagedPolicies != 1 {
		t.Errorf("UnmanagedPolicies = %d, want 1 (app-policy)", updated.Status.DiscoveryStatus.UnmanagedPolicies)
	}
	if updated.Status.DiscoveryStatus.UnmanagedRoles != 1 {
		t.Errorf("UnmanagedRoles = %d, want 1 (app-role)", updated.Status.DiscoveryStatus.UnmanagedRoles)
	}
	if len(updated.Status.DiscoveryStatus.DiscoveredResources) != 2 {
		t.Errorf("DiscoveredResources count = %d, want 2", len(updated.Status.DiscoveryStatus.DiscoveredResources))
	}

	// Verify an event was emitted
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "DiscoveryScanComplete") {
			t.Errorf("expected DiscoveryScanComplete event, got %q", event)
		}
	default:
		t.Error("expected a DiscoveryScanComplete event to be emitted")
	}
}

func TestReconcile_MinScanIntervalClamping(t *testing.T) {
	// Override MinScanInterval for this test
	origMin := MinScanInterval
	MinScanInterval = 5 * time.Minute
	defer func() { MinScanInterval = origMin }()

	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{
		Enabled:  true,
		Interval: "1m", // less than MinScanInterval
	}, nil)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	server := newMockVaultServer(
		[]string{"default", "root"},
		nil,
		nil,
	)
	defer server.Close()

	cache := vault.NewClientCache()
	newVaultClientFromServer(t, server, cache, "test-conn")

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: cache,
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-conn"},
	})

	if err != nil {
		t.Fatalf("Reconcile() error = %v, want nil", err)
	}
	// Should be clamped to MinScanInterval (5m), not the configured 1m
	if result.RequeueAfter != 5*time.Minute {
		t.Errorf("Reconcile() RequeueAfter = %v, want %v (clamped to MinScanInterval)", result.RequeueAfter, 5*time.Minute)
	}
}

func TestAutoCreateCRs_Success(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{
		Enabled:         true,
		AutoCreateCRs:   true,
		TargetNamespace: "vault-resources",
	}, nil)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	now := metav1.Now()
	scanResult := &ScanResult{
		UnmanagedPolicies: []string{"app-policy"},
		UnmanagedRoles:    []string{"app-role"},
		DiscoveredResources: []vaultv1alpha1.DiscoveredResource{
			{
				Type:            "policy",
				Name:            "app-policy",
				DiscoveredAt:    now,
				SuggestedCRName: "app-policy",
				AdoptionStatus:  "discovered",
			},
			{
				Type:            "role",
				Name:            "app-role",
				DiscoveredAt:    now,
				SuggestedCRName: "app-role",
				AdoptionStatus:  "discovered",
			},
		},
	}

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	err := r.autoCreateCRs(context.Background(), conn, scanResult)
	if err != nil {
		t.Fatalf("autoCreateCRs() error = %v, want nil", err)
	}

	// Verify VaultPolicy was created
	var policy vaultv1alpha1.VaultPolicy
	if err := k8sClient.Get(context.Background(), types.NamespacedName{
		Name:      "app-policy",
		Namespace: "vault-resources",
	}, &policy); err != nil {
		t.Fatalf("failed to get created VaultPolicy: %v", err)
	}
	if policy.Annotations[vaultv1alpha1.AnnotationAdopt] != vaultv1alpha1.AnnotationValueTrue {
		t.Error("VaultPolicy should have adopt annotation set to 'true'")
	}
	// §4 regression: discovery-pending must be set so the operator doesn't
	// overwrite the adopted Vault policy with the placeholder rule below.
	if policy.Annotations[vaultv1alpha1.AnnotationDiscoveryPending] != vaultv1alpha1.AnnotationValueTrue {
		t.Error("VaultPolicy should carry discovery-pending=true to block placeholder writes")
	}
	if policy.Annotations[vaultv1alpha1.AnnotationDiscoveredFrom] != testConnName {
		t.Errorf("VaultPolicy.discovered-from = %q, want %q",
			policy.Annotations[vaultv1alpha1.AnnotationDiscoveredFrom], testConnName)
	}
	if policy.Spec.ConnectionRef != testConnName {
		t.Errorf("VaultPolicy.Spec.ConnectionRef = %q, want %q", policy.Spec.ConnectionRef, testConnName)
	}

	// Verify VaultRole was created
	var role vaultv1alpha1.VaultRole
	if err := k8sClient.Get(context.Background(), types.NamespacedName{
		Name:      "app-role",
		Namespace: "vault-resources",
	}, &role); err != nil {
		t.Fatalf("failed to get created VaultRole: %v", err)
	}
	if role.Annotations[vaultv1alpha1.AnnotationAdopt] != vaultv1alpha1.AnnotationValueTrue {
		t.Error("VaultRole should have adopt annotation set to 'true'")
	}
	// §4 regression: without discovery-pending, the first reconcile would
	// write ServiceAccounts=[placeholder] over the adopted Vault role,
	// unbinding every real workload. The annotation is load-bearing.
	if role.Annotations[vaultv1alpha1.AnnotationDiscoveryPending] != vaultv1alpha1.AnnotationValueTrue {
		t.Error("VaultRole MUST carry discovery-pending=true — missing annotation causes silent auth loss (IMPROVEMENTS §4)")
	}
	if role.Annotations[vaultv1alpha1.AnnotationDiscoveredFrom] != testConnName {
		t.Errorf("VaultRole.discovered-from = %q, want %q",
			role.Annotations[vaultv1alpha1.AnnotationDiscoveredFrom], testConnName)
	}
	if role.Spec.ConnectionRef != testConnName {
		t.Errorf("VaultRole.Spec.ConnectionRef = %q, want %q", role.Spec.ConnectionRef, testConnName)
	}
	// §4 — MinItems=1 on ServiceAccounts + Policies means the old empty-slice
	// spec would be rejected by the API server (kubebuilder schema validation).
	// Fake-client tests mask this, so assert the placeholder values explicitly.
	if got, want := role.Spec.ServiceAccounts, []string{discoveryPlaceholder}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("VaultRole.Spec.ServiceAccounts = %v, want %v", got, want)
	}
	if len(role.Spec.Policies) != 1 || role.Spec.Policies[0].Name != discoveryPlaceholder {
		t.Errorf("VaultRole.Spec.Policies = %v, want one placeholder ref", role.Spec.Policies)
	}
}

func TestAutoCreateCRs_MissingTargetNamespace(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{
		Enabled:         true,
		AutoCreateCRs:   true,
		TargetNamespace: "", // missing
	}, nil)

	r := NewReconciler(ReconcilerConfig{
		Client:      fake.NewClientBuilder().WithScheme(scheme).Build(),
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	scanResult := &ScanResult{
		DiscoveredResources: []vaultv1alpha1.DiscoveredResource{
			{
				Type:            "policy",
				Name:            "some-policy",
				DiscoveredAt:    metav1.Now(),
				SuggestedCRName: "some-policy",
			},
		},
	}

	err := r.autoCreateCRs(context.Background(), conn, scanResult)
	if err == nil {
		t.Fatal("autoCreateCRs() error = nil, want error about missing targetNamespace")
	}
	if !strings.Contains(err.Error(), "targetNamespace") {
		t.Errorf("autoCreateCRs() error = %v, want error mentioning targetNamespace", err)
	}
}

func TestAutoCreateCRs_AlreadyExists(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{
		Enabled:         true,
		AutoCreateCRs:   true,
		TargetNamespace: "vault-resources",
	}, nil)

	// Pre-create the VaultPolicy that autoCreateCRs will attempt to create
	existingPolicy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-policy",
			Namespace: "vault-resources",
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "test-conn",
			Rules:         []vaultv1alpha1.PolicyRule{},
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, existingPolicy).
		WithStatusSubresource(conn).
		Build()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	now := metav1.Now()
	scanResult := &ScanResult{
		UnmanagedPolicies: []string{"app-policy"},
		DiscoveredResources: []vaultv1alpha1.DiscoveredResource{
			{
				Type:            "policy",
				Name:            "app-policy",
				DiscoveredAt:    now,
				SuggestedCRName: "app-policy",
				AdoptionStatus:  "discovered",
			},
		},
	}

	// autoCreateCRs should not return an error when the resource already exists;
	// it logs and continues.
	err := r.autoCreateCRs(context.Background(), conn, scanResult)
	if err != nil {
		t.Fatalf("autoCreateCRs() error = %v, want nil (should continue on AlreadyExists)", err)
	}

	// Verify the existing policy is still there and unchanged
	var policy vaultv1alpha1.VaultPolicy
	if err := k8sClient.Get(context.Background(), types.NamespacedName{
		Name:      "app-policy",
		Namespace: "vault-resources",
	}, &policy); err != nil {
		t.Fatalf("existing VaultPolicy should still exist: %v", err)
	}
}

func TestUpdateDiscoveryStatus_Success(t *testing.T) {
	scheme := newTestScheme()
	conn := newVaultConnection(&vaultv1alpha1.DiscoveryConfig{
		Enabled: true,
	}, nil)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	now := metav1.Now()
	scanResult := &ScanResult{
		UnmanagedPolicies: []string{"policy-a", "policy-b"},
		UnmanagedRoles:    []string{"role-a"},
		DiscoveredResources: []vaultv1alpha1.DiscoveredResource{
			{Type: "policy", Name: "policy-a", DiscoveredAt: now, SuggestedCRName: "policy-a"},
			{Type: "policy", Name: "policy-b", DiscoveredAt: now, SuggestedCRName: "policy-b"},
			{Type: "role", Name: "role-a", DiscoveredAt: now, SuggestedCRName: "role-a"},
		},
	}

	err := r.updateDiscoveryStatus(context.Background(), "test-conn", now, scanResult)
	if err != nil {
		t.Fatalf("updateDiscoveryStatus() error = %v, want nil", err)
	}

	// Verify the status
	var updated vaultv1alpha1.VaultConnection
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: "test-conn"}, &updated); err != nil {
		t.Fatalf("failed to get VaultConnection: %v", err)
	}

	ds := updated.Status.DiscoveryStatus
	if ds == nil {
		t.Fatal("DiscoveryStatus should not be nil")
	}
	if ds.LastScanAt == nil {
		t.Error("LastScanAt should be set")
	} else if ds.LastScanAt.Unix() != now.Unix() {
		t.Errorf("LastScanAt = %v, want %v", ds.LastScanAt.Time, now.Time)
	}
	if ds.UnmanagedPolicies != 2 {
		t.Errorf("UnmanagedPolicies = %d, want 2", ds.UnmanagedPolicies)
	}
	if ds.UnmanagedRoles != 1 {
		t.Errorf("UnmanagedRoles = %d, want 1", ds.UnmanagedRoles)
	}
	if len(ds.DiscoveredResources) != 3 {
		t.Errorf("DiscoveredResources count = %d, want 3", len(ds.DiscoveredResources))
	}
}

func TestUpdateDiscoveryStatus_ConnectionDeleted(t *testing.T) {
	scheme := newTestScheme()
	// Do not create the connection — simulate it being deleted
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	r := NewReconciler(ReconcilerConfig{
		Client:      k8sClient,
		Scheme:      scheme,
		ClientCache: vault.NewClientCache(),
		Log:         logr.Discard(),
		Recorder:    record.NewFakeRecorder(10),
	})

	scanResult := &ScanResult{
		UnmanagedPolicies:   []string{},
		UnmanagedRoles:      []string{},
		DiscoveredResources: []vaultv1alpha1.DiscoveredResource{},
	}

	err := r.updateDiscoveryStatus(context.Background(), "deleted-conn", metav1.Now(), scanResult)
	if err != nil {
		t.Fatalf("updateDiscoveryStatus() error = %v, want nil for deleted connection", err)
	}
}
