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
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/record"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
	"github.com/panteparak/vault-access-operator/shared/markers"
)

// roleAliasVaultState seeds the shared mock Vault with a role that carries
// the given alias_metadata ownership record.
func roleAliasVaultState(roleKey string, own map[string]interface{}) *mockVaultState {
	state := newMockVaultState()
	state.roles[roleKey] = map[string]interface{}{
		"policies":                 []interface{}{"p"},
		vault.RoleAliasMetadataKey: own,
	}
	return state
}

// TestRoleCheckConflict_AliasMetadata pins the ADR 0010 role ownership
// semantics: a live role whose alias_metadata names this operator+CR is
// ours; one naming a different owner is a hard conflict regardless of
// adoption settings; a record-less role falls back to status memory.
func TestRoleCheckConflict_AliasMetadata(t *testing.T) {
	markers.SetEnabled(true)
	t.Cleanup(func() { markers.SetEnabled(false) })

	role := newTestVaultRole()
	adapter := domain.NewVaultRoleAdapter(role)
	roleKey := "auth/kubernetes/role/vao._.test-ns.test-role"

	run := func(t *testing.T, own map[string]interface{}) error {
		t.Helper()
		state := roleAliasVaultState(roleKey, own)
		server := newMockVaultServer(mockVaultServerConfig{state: state})
		t.Cleanup(server.Close)
		vc := newTestCachedVaultClient(t, server.URL)
		h := &Handler{log: logr.Discard(), recorder: record.NewFakeRecorder(10)}
		return h.checkConflict(logr.NewContext(context.Background(), logr.Discard()),
			vc, adapter, "auth/kubernetes", "vao._.test-ns.test-role")
	}

	t.Run("owned by self: no conflict even without status memory", func(t *testing.T) {
		err := run(t, map[string]interface{}{
			vault.KVManagedByKey:   vault.KVManagedByValue,
			vault.KVK8sResourceKey: adapter.GetK8sResourceIdentifier(),
		})
		if err != nil {
			t.Errorf("self-owned role should not conflict, got %v", err)
		}
	})

	t.Run("foreign owner: hard conflict", func(t *testing.T) {
		err := run(t, map[string]interface{}{
			vault.KVManagedByKey:        vault.KVManagedByValue,
			vault.OwnershipAuthMountKey: "other-cluster-mount",
			vault.KVK8sResourceKey:      "other-ns/other-role",
		})
		if !infraerrors.IsConflictError(err) {
			t.Errorf("foreign-owned role must be a ConflictError, got %v", err)
		}
	})

	recordLess := func(t *testing.T, recordedName string) error {
		t.Helper()
		role2 := newTestVaultRole()
		role2.Status.LastAppliedHash = "prior-sync"
		role2.Status.VaultRoleName = recordedName
		a2 := domain.NewVaultRoleAdapter(role2)
		state := roleAliasVaultState(roleKey, nil)
		delete(state.roles[roleKey], vault.RoleAliasMetadataKey)
		server := newMockVaultServer(mockVaultServerConfig{state: state})
		t.Cleanup(server.Close)
		vc := newTestCachedVaultClient(t, server.URL)
		h := &Handler{log: logr.Discard(), recorder: record.NewFakeRecorder(10)}
		return h.checkConflict(logr.NewContext(context.Background(), logr.Discard()),
			vc, a2, "auth/kubernetes", "vao._.test-ns.test-role")
	}

	t.Run("record-less role with status memory: ours", func(t *testing.T) {
		if err := recordLess(t, "vao._.test-ns.test-role"); err != nil {
			t.Errorf("record-less role with prior sync should not conflict, got %v", err)
		}
	})

	// AC3 (#18): status memory counts only at the recorded name; during a
	// rename a record-less role at the new name is someone else's.
	t.Run("record-less role at the new name during a rename: conflict", func(t *testing.T) {
		err := recordLess(t, "vao.old-identity.test-ns.test-role")
		if !infraerrors.IsConflictError(err) {
			t.Errorf("record-less role at the rename target must conflict, got %v", err)
		}
	})
}

// TestWarnIdentityMismatch pins #18 AC10: a role named under one identity
// that references a policy named under another gets a Warning per such
// policy; matching, unresolved and pre-ADR 0010 names stay silent.
func TestWarnIdentityMismatch(t *testing.T) {
	ref := func(name string) vaultv1alpha1.PolicyReference {
		return vaultv1alpha1.PolicyReference{Kind: "VaultPolicy", Name: name}
	}
	resolution := []resolvedPolicyRef{
		{Ref: ref("same"), VaultName: "vao.proj.ns.same", Resolved: true},
		{Ref: ref("other"), VaultName: "vao.cluster-a.ns.other", Resolved: true},
		{Ref: ref("pending"), VaultName: "", Resolved: false},
		{Ref: ref("legacy"), VaultName: "legacy-name", Resolved: true},
	}
	recorder := record.NewFakeRecorder(10)
	h := &Handler{recorder: recorder}
	h.warnIdentityMismatch(domain.NewVaultRoleAdapter(newTestVaultRole()), "proj", resolution)
	close(recorder.Events)
	got := make([]string, 0, len(recorder.Events))
	for e := range recorder.Events {
		got = append(got, e)
	}
	if len(got) != 1 || !strings.Contains(got[0], "Warning "+eventReasonPolicyIdentityMismatch) ||
		!strings.Contains(got[0], `"other"`) || !strings.Contains(got[0], `"cluster-a"`) {
		t.Fatalf("events = %v, want one PolicyIdentityMismatch for policy other (identity cluster-a)", got)
	}
}
