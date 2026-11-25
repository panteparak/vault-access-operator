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

	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
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
// but on a Vault that stores alias_metadata (status.vaultVersion >= 1.21)
// it emits a non-blocking OwnershipRecordMissing Warning.
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
		events := make([]string, 0, len(recorder.Events))
		for e := range recorder.Events {
			events = append(events, e)
		}
		return events, err
	}

	for _, tc := range []struct {
		name, version string
		wantEvent     bool
	}{
		{"Vault 1.21.2, no record: warning", "1.21.2", true},
		{"Vault v1.22.0+ent, no record: warning", "v1.22.0+ent", true},
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
	t.Run("foreign record on 1.21: still conflicts", func(t *testing.T) {
		if _, err := run(t, "1.21.2", "cluster-b"); !infraerrors.IsConflictError(err) {
			t.Errorf("want ConflictError, got %v", err)
		}
	})
}
