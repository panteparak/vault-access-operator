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

package orphan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// orphanVaultMock serves the read-only Vault surface the orphan scanner uses:
// policy list + reads (in-band ownership headers) and role list on one mount.
type orphanVaultMock struct {
	policies map[string]string // name → HCL (headers included)
	roles    []string          // role names on auth/kubernetes
	failList bool
}

func (m *orphanVaultMock) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/sys/policies/acl" && r.URL.Query().Get("list") == "true":
		if m.failList {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"denied"}})
			return
		}
		keys := make([]string, 0, len(m.policies))
		for k := range m.policies {
			keys = append(keys, k)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"keys": keys},
		})
	case strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/"):
		name := strings.TrimPrefix(r.URL.Path, "/v1/sys/policies/acl/")
		hcl, ok := m.policies[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"name": name, "policy": hcl},
		})
	case r.URL.Path == "/v1/auth/kubernetes/role" && r.URL.Query().Get("list") == "true":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"keys": m.roles},
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newOrphanVaultClient(t *testing.T, m *orphanVaultMock, authMount string) *vault.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(srv.Close)
	c, err := vault.NewClient(vault.ClientConfig{Address: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.SetAuthMount(authMount)
	return c
}

func newOrphanK8sClient(objs ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func ownedHCL(authMount, k8sResource string) string {
	return vault.OwnershipHeader(vault.Ownership{
		ManagedBy:   vault.KVManagedByValue,
		AuthMount:   authMount,
		K8sResource: k8sResource,
		K8sKind:     "VaultPolicy",
	}) + "\npath \"secret/*\" {\n  capabilities = [\"read\"]\n}\n"
}

// TestController_DetectOrphanedPolicies exercises the in-band ownership scan
// (ADR 0008): only OUR policies (matching auth-mount identity) whose owning
// CR is gone are flagged.
func TestController_DetectOrphanedPolicies(t *testing.T) {
	mock := &orphanVaultMock{policies: map[string]string{
		// Ours, CR exists → not an orphan.
		"default-live": ownedHCL("kubernetes", "default/live"),
		// Ours, CR gone → orphan.
		"default-gone": ownedHCL("kubernetes", "default/gone"),
		// Another operator's (different mount) → never flagged.
		"other-cluster": ownedHCL("k8s-other", "default/gone"),
		// No header → unmanaged, never flagged.
		"handwritten": "path \"x\" {\n  capabilities = [\"read\"]\n}\n",
	}}
	vc := newOrphanVaultClient(t, mock, "kubernetes")
	ctrl := &Controller{
		k8sClient: newOrphanK8sClient(&vaultv1alpha1.VaultPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "live", Namespace: "default"},
		}),
		log: logr.Discard(),
	}

	orphans := ctrl.DetectOrphanedPolicies(context.Background(), vc, "conn")
	if len(orphans) != 1 {
		t.Fatalf("orphans = %+v, want exactly 1", orphans)
	}
	if orphans[0].VaultName != "default-gone" || orphans[0].K8sResource != "default/gone" {
		t.Errorf("orphan = %+v, want default-gone owned by default/gone", orphans[0])
	}
}

// TestController_DetectOrphanedPolicies_ListError verifies a Vault list
// failure degrades to "no orphans" rather than an error or false positives.
func TestController_DetectOrphanedPolicies_ListError(t *testing.T) {
	vc := newOrphanVaultClient(t, &orphanVaultMock{failList: true}, "kubernetes")
	ctrl := &Controller{k8sClient: newOrphanK8sClient(), log: logr.Discard()}
	if orphans := ctrl.DetectOrphanedPolicies(context.Background(), vc, "conn"); orphans != nil {
		t.Errorf("orphans = %+v, want nil on list error", orphans)
	}
}

// TestController_DetectOrphanedRoles: under the one-cluster-per-mount
// invariant, any role on OUR mount with no deriving CR is an orphan
// candidate; roles derived from live CRs are not.
func TestController_DetectOrphanedRoles(t *testing.T) {
	mock := &orphanVaultMock{roles: []string{"default-live", "stale-role"}}
	vc := newOrphanVaultClient(t, mock, "kubernetes")
	ctrl := &Controller{
		k8sClient: newOrphanK8sClient(&vaultv1alpha1.VaultRole{
			ObjectMeta: metav1.ObjectMeta{Name: "live", Namespace: "default"},
			Spec:       vaultv1alpha1.VaultRoleSpec{AuthPath: "kubernetes"},
		}),
		log: logr.Discard(),
	}

	orphans := ctrl.DetectOrphanedRoles(context.Background(), vc, "conn")
	if len(orphans) != 1 {
		t.Fatalf("orphans = %+v, want exactly 1", orphans)
	}
	if orphans[0].VaultName != "stale-role" {
		t.Errorf("orphan = %+v, want stale-role", orphans[0])
	}
	// No in-band record exists for roles, so the owner is unknowable.
	if orphans[0].K8sResource != "" {
		t.Errorf("role orphan K8sResource = %q, want empty (no ownership record)", orphans[0].K8sResource)
	}
}

// TestController_DetectOrphanedRoles_NoAuthMount: a static-token connection
// has no mount to scan — the role pass is skipped entirely.
func TestController_DetectOrphanedRoles_NoAuthMount(t *testing.T) {
	vc := newOrphanVaultClient(t, &orphanVaultMock{roles: []string{"anything"}}, "")
	ctrl := &Controller{k8sClient: newOrphanK8sClient(), log: logr.Discard()}
	if orphans := ctrl.DetectOrphanedRoles(context.Background(), vc, "conn"); orphans != nil {
		t.Errorf("orphans = %+v, want nil for mountless connection", orphans)
	}
}

func TestNewController(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	tests := []struct {
		name             string
		interval         time.Duration
		expectedInterval time.Duration
	}{
		{
			name:             "uses provided interval",
			interval:         5 * time.Minute,
			expectedInterval: 5 * time.Minute,
		},
		{
			name:             "uses default interval when zero",
			interval:         0,
			expectedInterval: DefaultScanInterval,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ControllerConfig{
				K8sClient:   k8sClient,
				ClientCache: nil,
				Interval:    tt.interval,
				Log:         logr.Discard(),
			}

			ctrl := NewController(cfg)

			if ctrl.interval != tt.expectedInterval {
				t.Errorf("interval = %v, want %v", ctrl.interval, tt.expectedInterval)
			}
			if ctrl.k8sClient == nil {
				t.Error("k8sClient should not be nil")
			}
			if ctrl.stopCh == nil {
				t.Error("stopCh should not be nil")
			}
			if ctrl.stoppedCh == nil {
				t.Error("stoppedCh should not be nil")
			}
		})
	}
}

func TestController_NeedsLeaderElection(t *testing.T) {
	ctrl := &Controller{}
	if !ctrl.NeedsLeaderElection() {
		t.Error("NeedsLeaderElection should return true")
	}
}

func TestController_k8sResourceExists(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	existingPolicy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-policy",
			Namespace: "default",
		},
	}

	existingClusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "existing-cluster-policy",
		},
	}

	existingRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-role",
			Namespace: "default",
		},
	}

	existingClusterRole := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "existing-cluster-role",
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingPolicy, existingClusterPolicy, existingRole, existingClusterRole).
		Build()

	ctrl := &Controller{
		k8sClient: k8sClient,
		log:       logr.Discard(),
	}

	tests := []struct {
		name         string
		k8sResource  string
		resourceType string
		expected     bool
	}{
		// VaultPolicy tests (namespaced)
		{
			name:         "existing VaultPolicy returns true",
			k8sResource:  "default/existing-policy",
			resourceType: ResourceTypePolicy,
			expected:     true,
		},
		{
			name:         "non-existent VaultPolicy returns false",
			k8sResource:  "default/non-existent",
			resourceType: ResourceTypePolicy,
			expected:     false,
		},
		// VaultClusterPolicy tests (cluster-scoped)
		{
			name:         "existing VaultClusterPolicy returns true",
			k8sResource:  "existing-cluster-policy",
			resourceType: ResourceTypePolicy,
			expected:     true,
		},
		{
			name:         "non-existent VaultClusterPolicy returns false",
			k8sResource:  "non-existent-cluster-policy",
			resourceType: ResourceTypePolicy,
			expected:     false,
		},
		// VaultRole tests (namespaced)
		{
			name:         "existing VaultRole returns true",
			k8sResource:  "default/existing-role",
			resourceType: ResourceTypeRole,
			expected:     true,
		},
		{
			name:         "non-existent VaultRole returns false",
			k8sResource:  "default/non-existent-role",
			resourceType: ResourceTypeRole,
			expected:     false,
		},
		// VaultClusterRole tests (cluster-scoped)
		{
			name:         "existing VaultClusterRole returns true",
			k8sResource:  "existing-cluster-role",
			resourceType: ResourceTypeRole,
			expected:     true,
		},
		{
			name:         "non-existent VaultClusterRole returns false",
			k8sResource:  "non-existent-cluster-role",
			resourceType: ResourceTypeRole,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ctrl.k8sResourceExists(context.Background(), tt.k8sResource, tt.resourceType)
			if result != tt.expected {
				t.Errorf("k8sResourceExists(%q, %q) = %v, want %v",
					tt.k8sResource, tt.resourceType, result, tt.expected)
			}
		})
	}
}

func TestController_Start_ContextCancellation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	ctrl := NewController(ControllerConfig{
		K8sClient:   k8sClient,
		ClientCache: nil,
		Interval:    100 * time.Millisecond,
		Log:         logr.Discard(),
	})

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Start the controller in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- ctrl.Start(ctx)
	}()

	// Give it a moment to start
	time.Sleep(200 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for the controller to stop
	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("controller did not stop within timeout")
	}
}

func TestController_Stop(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	ctrl := NewController(ControllerConfig{
		K8sClient:   k8sClient,
		ClientCache: nil,
		Interval:    100 * time.Millisecond,
		Log:         logr.Discard(),
	})

	// Start the controller in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- ctrl.Start(context.Background())
	}()

	// Give it a moment to start
	time.Sleep(200 * time.Millisecond)

	// Stop the controller
	stopCh := make(chan struct{})
	go func() {
		ctrl.Stop()
		close(stopCh)
	}()

	// Wait for Stop() to complete
	select {
	case <-stopCh:
		// Good, Stop() returned
	case <-time.After(2 * time.Second):
		t.Error("Stop() did not return within timeout")
	}

	// Wait for Start() to return
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected nil error from Stop(), got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start() did not return within timeout after Stop()")
	}
}

func TestOrphanInfo_Fields(t *testing.T) {
	info := OrphanInfo{
		VaultName:      "test-policy",
		ResourceType:   ResourceTypePolicy,
		K8sResource:    "default/test-policy",
		ConnectionName: "vault-connection",
	}

	if info.VaultName != "test-policy" {
		t.Errorf("VaultName = %q, want 'test-policy'", info.VaultName)
	}
	if info.ResourceType != ResourceTypePolicy {
		t.Errorf("ResourceType = %q, want 'policy'", info.ResourceType)
	}
	if info.K8sResource != "default/test-policy" {
		t.Errorf("K8sResource = %q, want 'default/test-policy'", info.K8sResource)
	}
	if info.ConnectionName != "vault-connection" {
		t.Errorf("ConnectionName = %q, want 'vault-connection'", info.ConnectionName)
	}
}

// TestController_StopWithoutStart pins the followup fix where Stop()
// would deadlock forever when Start was never called. Mirrors the same
// fix in pkg/cleanup.
func TestController_StopWithoutStart(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	c := NewController(ControllerConfig{
		K8sClient: fake.NewClientBuilder().WithScheme(scheme).Build(),
		Log:       logr.Discard(),
	})

	done := make(chan struct{})
	go func() {
		c.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Pass.
	case <-time.After(time.Second):
		t.Fatal("Stop deadlocked when Start was never called")
	}
}
