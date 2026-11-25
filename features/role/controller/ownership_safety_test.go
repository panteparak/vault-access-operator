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
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

const safetyRoleKey = "auth/kubernetes/role/vao.cluster-a.test-ns.test-role"

// AC1 (#18): an ownership-read error on delete is returned (so the caller
// queues a retry) and the role is not deleted.
func TestRoleOps_DeleteFromVault_OwnershipReadErrorFailsClosed(t *testing.T) {
	state := newMockVaultState()
	state.roles[safetyRoleKey] = map[string]interface{}{"policies": []interface{}{"p"}}
	server := newMockVaultServer(mockVaultServerConfig{state: state, readRoleErr: true})
	t.Cleanup(server.Close)
	vc := newTestCachedVaultClient(t, server.URL)

	ops := NewRoleOps(domain.NewVaultRoleAdapter(newTestVaultRole()), &Handler{}, &roleTarget{mount: "kubernetes"})
	if err := ops.DeleteFromVault(context.Background(), vc, "vao.cluster-a.test-ns.test-role"); err == nil {
		t.Fatal("ownership read error must be returned, got nil")
	}
	if _, ok := state.roles[safetyRoleKey]; !ok {
		t.Error("role deleted on a read error")
	}
}

// AC4 (#18): role drift ignores alias_metadata, so a same-content write by
// another owner used to pass readback. With checks on, readback fails
// unless the record read back is the one just written.
func TestRoleOps_ReadbackVerify_OwnershipRecord(t *testing.T) {
	run := func(t *testing.T, markersOn bool, aliasMount string) error {
		t.Helper()
		if markersOn {
			enableMarkersForTest(t)
		}
		state := newMockVaultState()
		server := newMockVaultServer(mockVaultServerConfig{state: state})
		t.Cleanup(server.Close)
		vc := newTestCachedVaultClient(t, server.URL)
		vc.SetAuthMount("cluster-a")

		adapter := domain.NewVaultRoleAdapter(newTestVaultRole())
		ops := NewRoleOps(adapter, &Handler{}, &roleTarget{mount: "kubernetes"})
		ops.vaultName = "vao.cluster-a.test-ns.test-role"
		ops.roleData = map[string]interface{}{"policies": []string{"p"}}
		own := ops.ownership(vc)
		own.AuthMount = aliasMount
		state.roles[safetyRoleKey] = map[string]interface{}{"policies": []interface{}{"p"}}
		if aliasMount != "" { // "" = Vault dropped alias_metadata
			live := map[string]interface{}{}
			for k, v := range vault.OwnershipAliasMetadata(own) {
				live[k] = v
			}
			state.roles[safetyRoleKey][vault.RoleAliasMetadataKey] = live
		}
		return ops.ReadbackVerify(context.Background(), vc)
	}

	t.Run("own record: ok", func(t *testing.T) {
		if err := run(t, true, "cluster-a"); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
	t.Run("foreign record, identical content: conflict", func(t *testing.T) {
		if err := run(t, true, "cluster-b"); !infraerrors.IsConflictError(err) {
			t.Errorf("want ConflictError, got %v", err)
		}
	})
	// Vault < 1.21 drops alias_metadata: no record to compare, so readback
	// passes rather than putting every role into Conflict.
	t.Run("record-less read back (Vault < 1.21): ok", func(t *testing.T) {
		if err := run(t, true, ""); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
	t.Run("checks off: content only, as v0.12.0", func(t *testing.T) {
		if err := run(t, false, "cluster-b"); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
}

// Owner decision on 867eb67 (A + E): a record-less readback still passes,
// but on a Vault that stores alias_metadata it emits a non-blocking
// OwnershipRecordMissing Warning. Vault 1.21.0-1.21.2 accept alias_metadata
// on write and drop it; 1.21.3 is the first release that stores it
// (review finding 4, measured), so 1.21.2 must stay silent.
func TestRoleOps_ReadbackVerify_OwnershipRecordMissingWarning(t *testing.T) {
	run := func(t *testing.T, vaultVersion, aliasMount string) ([]string, error) {
		t.Helper()
		enableMarkersForTest(t)
		state := newMockVaultState()
		server := newMockVaultServer(mockVaultServerConfig{state: state})
		t.Cleanup(server.Close)
		vc := newTestCachedVaultClient(t, server.URL)
		vc.SetAuthMount("cluster-a")

		conn := newTestVaultConnection()
		conn.Status.VaultVersion = vaultVersion
		recorder := record.NewFakeRecorder(10)
		h := &Handler{
			client:   fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(conn).Build(),
			recorder: recorder,
		}
		ops := NewRoleOps(domain.NewVaultRoleAdapter(newTestVaultRole()), h, &roleTarget{mount: "kubernetes"})
		ops.vaultName = "vao.cluster-a.test-ns.test-role"
		ops.roleData = map[string]interface{}{"policies": []string{"p"}}
		state.roles[safetyRoleKey] = map[string]interface{}{"policies": []interface{}{"p"}}
		if aliasMount != "" {
			own := ops.ownership(vc)
			own.AuthMount = aliasMount
			live := map[string]interface{}{}
			for k, v := range vault.OwnershipAliasMetadata(own) {
				live[k] = v
			}
			state.roles[safetyRoleKey][vault.RoleAliasMetadataKey] = live
		}
		err := ops.ReadbackVerify(context.Background(), vc)
		close(recorder.Events)
		emitted := make([]string, 0, len(recorder.Events))
		for e := range recorder.Events {
			emitted = append(emitted, e)
		}
		return emitted, err
	}

	for _, tc := range []struct {
		name, version string
		wantEvent     bool
	}{
		{"Vault 1.21.3, no record: warning", "1.21.3", true},
		{"Vault 1.21.4, no record: warning", "1.21.4", true},
		{"Vault v1.22.0+ent, no record: warning", "v1.22.0+ent", true},
		{"Vault 1.22, no patch: warning", "1.22", true},
		{"Vault 1.21.2 (drops the record), no record: silent", "1.21.2", false},
		{"Vault 1.21.1 (drops the record), no record: silent", "1.21.1", false},
		{"Vault 1.21, no patch: silent", "1.21", false},
		{"Vault 1.17.2, no record: silent", "1.17.2", false},
		{"unparseable version: silent", "unknown", false},
		{"unknown version: silent", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events, err := run(t, tc.version, "")
			if err != nil {
				t.Fatalf("readback must not fail, got %v", err)
			}
			got := len(events) == 1 && strings.Contains(events[0], "Warning "+eventReasonOwnershipRecordMissing)
			if got != tc.wantEvent || (!tc.wantEvent && len(events) != 0) {
				t.Errorf("events = %v, want warning = %v", events, tc.wantEvent)
			}
		})
	}
	t.Run("foreign record on 1.21.3: still conflicts", func(t *testing.T) {
		if _, err := run(t, "1.21.3", "cluster-b"); !infraerrors.IsConflictError(err) {
			t.Errorf("want ConflictError, got %v", err)
		}
	})
}

// interruptedRename syncs a role, switches the naming identity so the next
// sync renames it, and runs that sync with its status commit lost: the
// write to the new name lands, status still records the old one. The mock
// Vault drops alias_metadata like Vault < 1.21.3, so the role is
// record-less.
func interruptedRename(t *testing.T) (
	h *Handler, fetch func() *vaultv1alpha1.VaultRole, state *mockVaultState, newName string,
) {
	t.Helper()
	enableMarkersForTest(t)
	state = newMockVaultState()
	server := newMockVaultServer(mockVaultServerConfig{state: state, dropAliasMetadata: true})
	t.Cleanup(server.Close)

	newName = naming.VaultName("pe", testNamespace, testRoleName)
	conn := newTestVaultConnection()
	role := newTestVaultRole()
	refPolicy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "app-read", Namespace: testNamespace},
		Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: testConnName},
		Status: vaultv1alpha1.VaultPolicyStatus{
			VaultName: naming.VaultName(naming.Placeholder, testNamespace, "app-read"),
		},
	}
	// Lose the status commit that records the new name, once: the write
	// to Vault has landed by then.
	loseRenameCommit := false
	k8sClient := fake.NewClientBuilder().WithScheme(newTestScheme()).
		WithObjects(conn, role, refPolicy).WithStatusSubresource(conn, role, refPolicy).
		WithInterceptorFuncs(interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client,
			sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if r, ok := obj.(*vaultv1alpha1.VaultRole); ok && loseRenameCommit && r.Status.VaultRoleName == newName {
				loseRenameCommit = false
				return errors.New("simulated: operator restarted before the status commit")
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		}}).Build()
	cache := vault.NewClientCache()
	cache.Set(conn.Name, newTestCachedVaultClient(t, server.URL))
	h = NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	ctx := logr.NewContext(context.Background(), logr.Discard())
	fetch = func() *vaultv1alpha1.VaultRole {
		var r vaultv1alpha1.VaultRole
		if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: testNamespace, Name: testRoleName}, &r); err != nil {
			t.Fatal(err)
		}
		return &r
	}

	if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); err != nil {
		t.Fatalf("sync 1: %v", err)
	}
	naming.SetCluster("pe") // naming config change: the next sync renames
	t.Cleanup(func() { naming.SetCluster("") })
	loseRenameCommit = true
	if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); err == nil {
		t.Fatal("sync 2: want the lost status commit to fail the sync")
	}
	if _, ok := state.roles["auth/kubernetes/role/"+newName]; !ok {
		t.Fatalf("sync 2 did not write the new name; roles: %v", keysOf(state.roles))
	}
	return h, fetch, state, newName
}

// Review finding 1 (#18): on a Vault that drops alias_metadata (< 1.21.3),
// a rename whose Vault write lands but whose status commit is lost
// (operator restart, 409) left our record-less role at the new name. The
// AC3 rule (recorded name == bound name) then made every retry a
// ConflictError, and deleting the CR cleaned only the old name. The rename
// target is persisted before the write, so the retry recognises it.
func TestSyncRole_InterruptedRenameResumes(t *testing.T) {
	h, fetch, state, newName := interruptedRename(t)
	ctx := logr.NewContext(context.Background(), logr.Discard())

	if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); err != nil {
		t.Fatalf("sync 3 (retry): %v", err)
	}
	got := fetch()
	if got.Status.Phase != vaultv1alpha1.PhaseActive || got.Status.VaultRoleName != newName {
		t.Fatalf("sync 3: phase=%s vaultRoleName=%s, want Active at %s",
			got.Status.Phase, got.Status.VaultRoleName, newName)
	}
	if pending := got.Status.PendingVaultRoleName; pending != "" {
		t.Errorf("pendingVaultRoleName = %q after commit, want empty", pending)
	}

	if err := h.CleanupRole(ctx, domain.NewVaultRoleAdapter(fetch())); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(state.roles) != 0 {
		t.Errorf("roles left after cleanup: %v", keysOf(state.roles))
	}
}

// The CR is deleted before any retry: cleanup deletes the pending name as
// well as the recorded one, so the role written by the interrupted rename
// does not leak.
func TestCleanupRole_DeletesPendingName(t *testing.T) {
	h, fetch, state, newName := interruptedRename(t)
	ctx := logr.NewContext(context.Background(), logr.Discard())

	if got := fetch().Status.PendingVaultRoleName; got != newName {
		t.Fatalf("pendingVaultRoleName = %q, want %q", got, newName)
	}
	if err := h.CleanupRole(ctx, domain.NewVaultRoleAdapter(fetch())); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(state.roles) != 0 {
		t.Errorf("roles left after cleanup: %v", keysOf(state.roles))
	}
}
