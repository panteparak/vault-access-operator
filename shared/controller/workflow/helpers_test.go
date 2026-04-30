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

package workflow

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// ---------------------------------------------------------------------------
// testResource wraps a *VaultPolicy to satisfy SyncableResource.
// Uses SyncStatusAccessor to eliminate boilerplate status delegation.
// ---------------------------------------------------------------------------

type testResource struct {
	*vaultv1alpha1.VaultPolicy
	vaultv1alpha1.SyncStatusAccessor
}

func newTestResource(p *vaultv1alpha1.VaultPolicy) *testResource {
	return &testResource{
		VaultPolicy:        p,
		SyncStatusAccessor: vaultv1alpha1.NewSyncStatusAccessor(&p.Status.SyncStatus),
	}
}

func (r *testResource) GetObject() client.Object         { return r.VaultPolicy }
func (r *testResource) GetConnectionRef() string         { return r.Spec.ConnectionRef }
func (r *testResource) GetK8sResourceIdentifier() string { return r.Namespace + "/" + r.Name }
func (r *testResource) IsNamespaced() bool               { return true }
func (r *testResource) GetDeletionPolicy() vaultv1alpha1.DeletionPolicy {
	return r.Spec.DeletionPolicy
}
func (r *testResource) GetConflictPolicy() vaultv1alpha1.ConflictPolicy {
	return r.Spec.ConflictPolicy
}
func (r *testResource) GetDriftMode() vaultv1alpha1.DriftMode { return r.Spec.DriftMode }

// ---------------------------------------------------------------------------
// mockOps implements ResourceOps with call recording and configurable errors.
// ---------------------------------------------------------------------------

type mockOps struct {
	// calls records method names in invocation order
	calls []string

	// Configurable error returns
	validateErr      error
	checkConflictErr error
	prepareErr       error
	writeErr         error
	readbackErr      error
	markManagedErr   error
	deleteErr        error
	removeManagedErr error

	// Configurable results
	specHash      string
	driftDetected bool
	driftSummary  string
}

func (m *mockOps) ResourceKind() string      { return "VaultPolicy" }
func (m *mockOps) VaultResourceName() string { return "default-test-policy" }
func (m *mockOps) AuthPath() string          { return "" }

func (m *mockOps) Validate() error {
	m.calls = append(m.calls, "Validate")
	return m.validateErr
}

func (m *mockOps) CheckConflict(_ context.Context, _ VaultOpsClient) error {
	m.calls = append(m.calls, "CheckConflict")
	return m.checkConflictErr
}

func (m *mockOps) PrepareContent(_ context.Context, _ VaultOpsClient) (string, error) {
	m.calls = append(m.calls, "PrepareContent")
	return m.specHash, m.prepareErr
}

func (m *mockOps) DetectDrift(_ context.Context, _ VaultOpsClient) (bool, string) {
	m.calls = append(m.calls, "DetectDrift")
	return m.driftDetected, m.driftSummary
}

func (m *mockOps) WriteToVault(_ context.Context, _ VaultOpsClient) error {
	m.calls = append(m.calls, "WriteToVault")
	return m.writeErr
}

func (m *mockOps) ReadbackVerify(_ context.Context, _ VaultOpsClient) error {
	m.calls = append(m.calls, "ReadbackVerify")
	return m.readbackErr
}

func (m *mockOps) MarkManaged(_ context.Context, _ VaultOpsClient) error {
	m.calls = append(m.calls, "MarkManaged")
	return m.markManagedErr
}

func (m *mockOps) DeleteFromVault(_ context.Context, _ VaultOpsClient) error {
	m.calls = append(m.calls, "DeleteFromVault")
	return m.deleteErr
}

func (m *mockOps) RemoveManaged(_ context.Context, _ VaultOpsClient) error {
	m.calls = append(m.calls, "RemoveManaged")
	return m.removeManagedErr
}

func (m *mockOps) ApplyActiveStatus(_ string, _ *metav1.Time) {
	m.calls = append(m.calls, "ApplyActiveStatus")
}

func (m *mockOps) ApplyBindings() {
	m.calls = append(m.calls, "ApplyBindings")
}

func (m *mockOps) PublishSyncEvent(_ context.Context, _ *events.EventBus) {
	m.calls = append(m.calls, "PublishSyncEvent")
}

func (m *mockOps) PublishDeleteEvent(_ context.Context, _ *events.EventBus) {
	m.calls = append(m.calls, "PublishDeleteEvent")
}

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

// newTestVaultClient creates a Vault client for testing.
// The client points to localhost:8200 but never makes real HTTP connections.
func newTestVaultClient(t *testing.T) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: "http://localhost:8200"})
	if err != nil {
		t.Fatalf("failed to create test vault client: %v", err)
	}
	return c
}

// newFakeK8sClient creates a fake Kubernetes client with the operator's scheme
// and the given objects pre-loaded. VaultPolicy has status subresource support.
func newFakeK8sClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := vaultv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add v1alpha1 to scheme: %v", err)
	}
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultPolicy{}).
		WithObjects(objs...).
		Build()
}

// containsCall checks whether a method name appears in the call log.
func containsCall(calls []string, name string) bool {
	for _, c := range calls {
		if c == name {
			return true
		}
	}
	return false
}

// findCondition finds a condition by type in a conditions slice.
func findCondition(conds []vaultv1alpha1.Condition, condType string) *vaultv1alpha1.Condition {
	for i := range conds {
		if conds[i].Type == condType {
			return &conds[i]
		}
	}
	return nil
}
