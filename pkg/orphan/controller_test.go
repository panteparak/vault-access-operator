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

// mockVaultClient implements a subset of vault.Client for testing
type mockVaultClient struct {
	managedPolicies map[string]vault.ManagedResource
	managedRoles    map[string]vault.ManagedResource
	listPoliciesErr error
	listRolesErr    error
}

func (m *mockVaultClient) ListManagedPolicies(_ context.Context) (map[string]vault.ManagedResource, error) {
	if m.listPoliciesErr != nil {
		return nil, m.listPoliciesErr
	}
	if m.managedPolicies == nil {
		return map[string]vault.ManagedResource{}, nil
	}
	return m.managedPolicies, nil
}

func (m *mockVaultClient) ListManagedRoles(_ context.Context) (map[string]vault.ManagedResource, error) {
	if m.listRolesErr != nil {
		return nil, m.listRolesErr
	}
	if m.managedRoles == nil {
		return map[string]vault.ManagedResource{}, nil
	}
	return m.managedRoles, nil
}

// testableController extends Controller to allow injecting mock vault clients
type testableController struct {
	*Controller
	mockClients map[string]*mockVaultClient
}

func newTestableController(
	k8sClient client.Client,
	mockClients map[string]*mockVaultClient,
	connections []string,
) *testableController {
	// Note: We don't use a real ClientCache here since we inject mocks directly
	_ = connections // connections would be used by real ClientCache.List()

	ctrl := &Controller{
		k8sClient:   k8sClient,
		clientCache: nil, // Will use mock methods
		interval:    time.Second,
		log:         logr.Discard(),
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
	}

	return &testableController{
		Controller:  ctrl,
		mockClients: mockClients,
	}
}

// detectOrphansForConnectionWithMock is a test helper that uses mock clients
func (c *testableController) detectOrphansForConnectionWithMock(
	ctx context.Context, connName string,
) ([]OrphanInfo, []OrphanInfo) {
	mockClient := c.mockClients[connName]
	if mockClient == nil {
		return nil, nil
	}

	orphanedPolicies := c.detectOrphanedPoliciesWithMock(ctx, mockClient, connName)
	orphanedRoles := c.detectOrphanedRolesWithMock(ctx, mockClient, connName)

	return orphanedPolicies, orphanedRoles
}

func (c *testableController) detectOrphanedPoliciesWithMock(
	ctx context.Context, mockClient *mockVaultClient, connName string,
) []OrphanInfo {
	managed, err := mockClient.ListManagedPolicies(ctx)
	if err != nil {
		return nil
	}

	var orphans []OrphanInfo
	for vaultName, metadata := range managed {
		if !c.k8sResourceExists(ctx, metadata.K8sResource, ResourceTypePolicy) {
			orphans = append(orphans, OrphanInfo{
				VaultName:      vaultName,
				ResourceType:   ResourceTypePolicy,
				K8sResource:    metadata.K8sResource,
				ConnectionName: connName,
			})
		}
	}
	return orphans
}

func (c *testableController) detectOrphanedRolesWithMock(
	ctx context.Context, mockClient *mockVaultClient, connName string,
) []OrphanInfo {
	managed, err := mockClient.ListManagedRoles(ctx)
	if err != nil {
		return nil
	}

	var orphans []OrphanInfo
	for vaultName, metadata := range managed {
		if !c.k8sResourceExists(ctx, metadata.K8sResource, ResourceTypeRole) {
			orphans = append(orphans, OrphanInfo{
				VaultName:      vaultName,
				ResourceType:   ResourceTypeRole,
				K8sResource:    metadata.K8sResource,
				ConnectionName: connName,
			})
		}
	}
	return orphans
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

//nolint:dupl // Similar test structure for policies and roles is intentional
func TestController_detectOrphanedPolicies(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	// Create some existing K8s resources
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

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingPolicy, existingClusterPolicy).
		Build()

	tests := []struct {
		name            string
		managedPolicies map[string]vault.ManagedResource
		expectedOrphans int
		expectedNames   []string
	}{
		{
			name:            "no managed policies",
			managedPolicies: map[string]vault.ManagedResource{},
			expectedOrphans: 0,
		},
		{
			name: "all policies have K8s resources",
			managedPolicies: map[string]vault.ManagedResource{
				"default-existing-policy": {
					K8sResource: "default/existing-policy",
					ManagedAt:   time.Now(),
				},
				"existing-cluster-policy": {
					K8sResource: "existing-cluster-policy",
					ManagedAt:   time.Now(),
				},
			},
			expectedOrphans: 0,
		},
		{
			name: "one orphaned policy",
			managedPolicies: map[string]vault.ManagedResource{
				"default-existing-policy": {
					K8sResource: "default/existing-policy",
					ManagedAt:   time.Now(),
				},
				"orphaned-policy": {
					K8sResource: "default/deleted-policy",
					ManagedAt:   time.Now(),
				},
			},
			expectedOrphans: 1,
			expectedNames:   []string{"orphaned-policy"},
		},
		{
			name: "multiple orphaned policies",
			managedPolicies: map[string]vault.ManagedResource{
				"orphan1": {
					K8sResource: "default/deleted1",
					ManagedAt:   time.Now(),
				},
				"orphan2": {
					K8sResource: "deleted-cluster-policy",
					ManagedAt:   time.Now(),
				},
			},
			expectedOrphans: 2,
			expectedNames:   []string{"orphan1", "orphan2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClients := map[string]*mockVaultClient{
				"test-connection": {
					managedPolicies: tt.managedPolicies,
				},
			}

			ctrl := newTestableController(k8sClient, mockClients, []string{"test-connection"})

			orphanedPolicies, _ := ctrl.detectOrphansForConnectionWithMock(
				context.Background(),
				"test-connection",
			)

			if len(orphanedPolicies) != tt.expectedOrphans {
				t.Errorf("got %d orphaned policies, want %d", len(orphanedPolicies), tt.expectedOrphans)
			}

			// Verify expected orphan names
			orphanNames := make(map[string]bool)
			for _, o := range orphanedPolicies {
				orphanNames[o.VaultName] = true
				if o.ResourceType != ResourceTypePolicy {
					t.Errorf("orphan %q has ResourceType %q, want 'policy'", o.VaultName, o.ResourceType)
				}
				if o.ConnectionName != "test-connection" {
					t.Errorf("orphan %q has ConnectionName %q, want 'test-connection'", o.VaultName, o.ConnectionName)
				}
			}

			for _, expectedName := range tt.expectedNames {
				if !orphanNames[expectedName] {
					t.Errorf("expected orphan %q not found", expectedName)
				}
			}
		})
	}
}

//nolint:dupl // Similar test structure for policies and roles is intentional
func TestController_detectOrphanedRoles(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	// Create some existing K8s resources
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
		WithObjects(existingRole, existingClusterRole).
		Build()

	tests := []struct {
		name            string
		managedRoles    map[string]vault.ManagedResource
		expectedOrphans int
		expectedNames   []string
	}{
		{
			name:            "no managed roles",
			managedRoles:    map[string]vault.ManagedResource{},
			expectedOrphans: 0,
		},
		{
			name: "all roles have K8s resources",
			managedRoles: map[string]vault.ManagedResource{
				"default-existing-role": {
					K8sResource: "default/existing-role",
					ManagedAt:   time.Now(),
				},
				"existing-cluster-role": {
					K8sResource: "existing-cluster-role",
					ManagedAt:   time.Now(),
				},
			},
			expectedOrphans: 0,
		},
		{
			name: "one orphaned role",
			managedRoles: map[string]vault.ManagedResource{
				"default-existing-role": {
					K8sResource: "default/existing-role",
					ManagedAt:   time.Now(),
				},
				"orphaned-role": {
					K8sResource: "default/deleted-role",
					ManagedAt:   time.Now(),
				},
			},
			expectedOrphans: 1,
			expectedNames:   []string{"orphaned-role"},
		},
		{
			name: "multiple orphaned roles",
			managedRoles: map[string]vault.ManagedResource{
				"orphan1": {
					K8sResource: "default/deleted1",
					ManagedAt:   time.Now(),
				},
				"orphan2": {
					K8sResource: "deleted-cluster-role",
					ManagedAt:   time.Now(),
				},
			},
			expectedOrphans: 2,
			expectedNames:   []string{"orphan1", "orphan2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClients := map[string]*mockVaultClient{
				"test-connection": {
					managedRoles: tt.managedRoles,
				},
			}

			ctrl := newTestableController(k8sClient, mockClients, []string{"test-connection"})

			_, orphanedRoles := ctrl.detectOrphansForConnectionWithMock(
				context.Background(),
				"test-connection",
			)

			if len(orphanedRoles) != tt.expectedOrphans {
				t.Errorf("got %d orphaned roles, want %d", len(orphanedRoles), tt.expectedOrphans)
			}

			// Verify expected orphan names
			orphanNames := make(map[string]bool)
			for _, o := range orphanedRoles {
				orphanNames[o.VaultName] = true
				if o.ResourceType != ResourceTypeRole {
					t.Errorf("orphan %q has ResourceType %q, want 'role'", o.VaultName, o.ResourceType)
				}
				if o.ConnectionName != "test-connection" {
					t.Errorf("orphan %q has ConnectionName %q, want 'test-connection'", o.VaultName, o.ConnectionName)
				}
			}

			for _, expectedName := range tt.expectedNames {
				if !orphanNames[expectedName] {
					t.Errorf("expected orphan %q not found", expectedName)
				}
			}
		})
	}
}

func TestController_detectOrphans_ListError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Test policy list error
	mockClients := map[string]*mockVaultClient{
		"test-connection": {
			listPoliciesErr: context.DeadlineExceeded,
			managedRoles: map[string]vault.ManagedResource{
				"orphan": {
					K8sResource: "default/deleted",
					ManagedAt:   time.Now(),
				},
			},
		},
	}

	ctrl := newTestableController(k8sClient, mockClients, []string{"test-connection"})

	orphanedPolicies, orphanedRoles := ctrl.detectOrphansForConnectionWithMock(
		context.Background(),
		"test-connection",
	)

	// Policy detection should fail gracefully
	if len(orphanedPolicies) != 0 {
		t.Errorf("expected no orphaned policies due to error, got %d", len(orphanedPolicies))
	}

	// Role detection should still work
	if len(orphanedRoles) != 1 {
		t.Errorf("expected 1 orphaned role, got %d", len(orphanedRoles))
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
	time.Sleep(50 * time.Millisecond)

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
	time.Sleep(50 * time.Millisecond)

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
