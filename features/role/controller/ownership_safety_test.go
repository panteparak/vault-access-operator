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
	"fmt"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	// #18 AC7: checks always run, markers on or off.
	t.Run("markers off: still checked", func(t *testing.T) {
		if err := run(t, false, "cluster-b"); !infraerrors.IsConflictError(err) {
			t.Errorf("want ConflictError, got %v", err)
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
	h, fetch, state, newName, faults := renameHarness(t)
	ctx := logr.NewContext(context.Background(), logr.Discard())
	faults.loseRenameCommit = true
	if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); err == nil {
		t.Fatal("sync 2: want the lost status commit to fail the sync")
	}
	if _, ok := state.roles["auth/kubernetes/role/"+newName]; !ok {
		t.Fatalf("sync 2 did not write the new name; roles: %v", keysOf(state.roles))
	}
	return h, fetch, state, newName
}

// renameHarness syncs a role under identity "_" on a mock Vault that drops
// alias_metadata (< 1.21.3, so roles are record-less), then switches the
// naming identity to "pe" so the next sync renames it to newName. Setting
// faults.loseRenameCommit fails the next status update that records
// newName, once; faults.failErrorUpdates fails that many Phase=Error status
// updates (the sync's error path); faults.conflictRestores answers that
// many restores of a refused write's pending name (pending empty, not
// Phase=Error) with a conflict.
func renameHarness(t *testing.T) (
	h *Handler, fetch func() *vaultv1alpha1.VaultRole, state *mockVaultState, newName string,
	faults *renameFaults,
) {
	t.Helper()
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
	faults = &renameFaults{}
	k8sClient := fake.NewClientBuilder().WithScheme(newTestScheme()).
		WithObjects(conn, role, refPolicy).WithStatusSubresource(conn, role, refPolicy).
		WithInterceptorFuncs(interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client,
			sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if r, ok := obj.(*vaultv1alpha1.VaultRole); ok {
				if faults.loseRenameCommit && r.Status.VaultRoleName == newName {
					faults.loseRenameCommit = false
					return errors.New("simulated: operator restarted before the status commit")
				}
				if faults.failErrorUpdates > 0 && r.Status.Phase == vaultv1alpha1.PhaseError {
					faults.failErrorUpdates--
					return errors.New("simulated: error-path status update failed")
				}
				if faults.conflictRestores > 0 && r.Status.PendingVaultRoleName == "" &&
					r.Status.Phase != vaultv1alpha1.PhaseError {
					faults.conflictRestores--
					return apierrors.NewConflict(schema.GroupResource{Resource: "vaultroles"}, r.Name,
						errors.New("simulated: object modified"))
				}
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
	return h, fetch, state, newName, faults
}

// renameFaults are renameHarness's status-update fault switches.
type renameFaults struct {
	loseRenameCommit bool
	failErrorUpdates int
	conflictRestores int
}

// setRoleWrite sets the mock's outcome for writes to one role name ("" clears it).
func setRoleWrite(state *mockVaultState, name, mode string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.roleWrites == nil {
		state.roleWrites = map[string]string{}
	}
	state.roleWrites[name] = mode
}

// Review round 2, finding A (#18): a rename whose Vault write is rejected
// (403: it did not land) must not leave the new name pending. Otherwise a
// record-less role someone else then creates at that name (Vault < 1.21.3
// stores no record) counts as ours: the retry overwrites it and deleting
// the CR deletes it.
func TestSyncRole_RejectedRenameWriteDropsPendingName(t *testing.T) {
	h, fetch, state, newName, _ := renameHarness(t)
	ctx := logr.NewContext(context.Background(), logr.Discard())
	key := "auth/kubernetes/role/" + newName

	setRoleWrite(state, newName, "reject")
	if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); err == nil {
		t.Fatal("sync 2: want the rejected write to fail the sync")
	}
	if got := fetch().Status.PendingVaultRoleName; got != "" {
		t.Errorf("pendingVaultRoleName = %q after a rejected write, want empty", got)
	}

	setRoleWrite(state, newName, "")
	foreign := map[string]interface{}{"bound_service_account_names": []interface{}{"intruder"}}
	state.mu.Lock()
	state.roles[key] = foreign
	state.mu.Unlock()
	if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); !infraerrors.IsConflictError(err) {
		t.Errorf("sync 3: want ConflictError for the record-less role at %s, got %v", newName, err)
	}
	if err := h.CleanupRole(ctx, domain.NewVaultRoleAdapter(fetch())); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if got := state.roles[key]; fmt.Sprint(got["bound_service_account_names"]) != "[intruder]" {
		t.Errorf("role at %s was taken over or deleted: %v", newName, got)
	}
}

// Review round 3, finding A2 (#18): the restore of a refused write's
// pending name was persisted only by the error path's single status
// update. When that update failed once, pending stayed at the refused
// name; later refused writes set nothing so restored nothing, and a
// record-less role someone else then created there was taken over.
// The restore persists itself, retrying a conflict.
func TestSyncRole_RejectedWriteRestoreSurvivesFailedErrorUpdate(t *testing.T) {
	t.Run("error update fails", func(t *testing.T) { restoreSurvives(t, renameFaults{failErrorUpdates: 1}) })
	t.Run("restore conflicts once", func(t *testing.T) {
		restoreSurvives(t, renameFaults{failErrorUpdates: 1, conflictRestores: 1})
	})
}

func restoreSurvives(t *testing.T, f renameFaults) {
	h, fetch, state, newName, faults := renameHarness(t)
	ctx := logr.NewContext(context.Background(), logr.Discard())
	key := "auth/kubernetes/role/" + newName

	setRoleWrite(state, newName, "reject")
	*faults = f
	_ = h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch()))
	_ = h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch()))
	if got := fetch().Status.PendingVaultRoleName; got != "" {
		t.Errorf("pendingVaultRoleName = %q after refused writes, want empty", got)
	}

	setRoleWrite(state, newName, "")
	state.mu.Lock()
	state.roles[key] = map[string]interface{}{"bound_service_account_names": []interface{}{"intruder"}}
	state.mu.Unlock()
	if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); !infraerrors.IsConflictError(err) {
		t.Errorf("sync 4: want ConflictError for the record-less role at %s, got %v", newName, err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if got := state.roles[key]; fmt.Sprint(got["bound_service_account_names"]) != "[intruder]" {
		t.Errorf("role at %s was taken over: %v", newName, got)
	}
}

// A write that fails ambiguously (5xx: it may have landed) keeps the
// pending name, so the retry and cleanup still find the role.
func TestSyncRole_AmbiguousRenameWriteKeepsPendingName(t *testing.T) {
	h, fetch, state, newName, _ := renameHarness(t)
	ctx := logr.NewContext(context.Background(), logr.Discard())

	setRoleWrite(state, newName, "lost")
	if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); err == nil {
		t.Fatal("sync 2: want the lost response to fail the sync")
	}
	if got := fetch().Status.PendingVaultRoleName; got != newName {
		t.Errorf("pendingVaultRoleName = %q after an ambiguous write, want %q", got, newName)
	}
}

// Review round 3, finding A1 (#18): with the SDK's own retries, a role
// write's first attempt could land and answer 500, and a retry then get
// 429 or 412 (both retried by the SDK). Read as "refused", that dropped the
// pending name, so on Vault < 1.21.3 the retry self-conflicted and deleting
// the CR leaked the role. The write is now one attempt, so the 500 is what
// the sync sees and the pending name stays.
func TestSyncRole_LandedWriteThenRetryRefusalKeepsPendingName(t *testing.T) {
	for _, mode := range []string{"lost-then-429", "lost-then-412"} {
		t.Run(mode, func(t *testing.T) {
			h, fetch, state, newName, _ := renameHarness(t)
			ctx := logr.NewContext(context.Background(), logr.Discard())

			setRoleWrite(state, newName, mode)
			if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); err == nil {
				t.Fatal("sync 2: want the failed write to fail the sync")
			}
			state.mu.Lock()
			_, landed := state.roles["auth/kubernetes/role/"+newName]
			attempts := state.roleWriteCalls[newName]
			state.mu.Unlock()
			if !landed {
				t.Fatalf("sync 2: the first attempt did not land")
			}
			if got := fetch().Status.PendingVaultRoleName; got != newName {
				t.Errorf("pendingVaultRoleName = %q after a write that landed (attempts %d), want %q",
					got, attempts, newName)
			}
			if err := h.CleanupRole(ctx, domain.NewVaultRoleAdapter(fetch())); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			if len(state.roles) != 0 {
				t.Errorf("roles left after cleanup: %v", keysOf(state.roles))
			}
		})
	}
}

// Review round 2, finding B (#18): a rename write lands but its response is
// lost, then the naming input flips back before the retry. The retry writes
// the recorded name and must delete the role the pending name points at
// (through the ownership gate), or it leaks: cleanup then sees no pending.
func TestSyncRole_FlipBackDeletesPendingName(t *testing.T) {
	h, fetch, state, newName, _ := renameHarness(t)
	ctx := logr.NewContext(context.Background(), logr.Discard())
	oldName := fetch().Status.VaultRoleName

	setRoleWrite(state, newName, "lost")
	if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); err == nil {
		t.Fatal("sync 2: want the lost response to fail the sync")
	}
	setRoleWrite(state, newName, "")
	naming.SetCluster("") // the naming input flips back

	if err := h.SyncRole(ctx, domain.NewVaultRoleAdapter(fetch())); err != nil {
		t.Fatalf("sync 3: %v", err)
	}
	got := fetch()
	if got.Status.Phase != vaultv1alpha1.PhaseActive || got.Status.VaultRoleName != oldName ||
		got.Status.PendingVaultRoleName != "" {
		t.Errorf("sync 3: phase=%s name=%s pending=%q, want Active at %s, no pending",
			got.Status.Phase, got.Status.VaultRoleName, got.Status.PendingVaultRoleName, oldName)
	}
	if _, ok := state.roles["auth/kubernetes/role/"+newName]; ok {
		t.Errorf("role %s written in sync 2 survives sync 3", newName)
	}
	if err := h.CleanupRole(ctx, domain.NewVaultRoleAdapter(fetch())); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(state.roles) != 0 {
		t.Errorf("roles left after cleanup: %v", keysOf(state.roles))
	}
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
