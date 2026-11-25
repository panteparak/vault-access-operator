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
	"reflect"
	"testing"

	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

// TestGolden_V012_RoleUnchangedWithoutIdentity pins #18 AC11 for roles:
// with no spec.identity, the Vault name, the alias_metadata record and the
// content hash are byte-identical to v0.12.0's (literals produced by
// v0.12.0, d4fc34e, from the same inputs).
func TestGolden_V012_RoleUnchangedWithoutIdentity(t *testing.T) {
	for _, tc := range []struct {
		mount, cluster, wantName, wantHash string
		wantAlias                          map[string]string
	}{
		{"kubernetes", "", "vao.kubernetes.test-ns.test-role",
			"9957d770a0b931b15bf71f340abc374b05d5ebdc9f7fba1828fef51dc097b46e",
			map[string]string{"auth-mount": "kubernetes", "k8s-kind": "VaultRole",
				"k8s-resource": "test-ns/test-role", "managed-by": "vault-access-operator"}},
		{"", "pe", "vao.pe.test-ns.test-role",
			"58303a9541a0755374cb3818a89d7b279b69296e9c3ee189e4f94f98507f7f58",
			map[string]string{"cluster": "pe", "k8s-kind": "VaultRole",
				"k8s-resource": "test-ns/test-role", "managed-by": "vault-access-operator"}},
	} {
		t.Run("mount="+tc.mount+",cluster="+tc.cluster, func(t *testing.T) {
			naming.SetCluster(tc.cluster)
			t.Cleanup(func() { naming.SetCluster("") })
			vc := newTestCachedVaultClient(t, "http://127.0.0.1:1")
			vc.SetAuthMount(tc.mount)
			h := &Handler{}
			adapter := domain.NewVaultRoleAdapter(newTestVaultRole())
			ops := NewRoleOps(adapter, h, &roleTarget{mount: "kubernetes"})
			if got := ops.BindVaultName(vc); got != tc.wantName {
				t.Errorf("name = %q, want %q", got, tc.wantName)
			}
			// The same steps PrepareContent runs after policy resolution.
			roleData, err := h.buildRoleData(adapter, vault.AuthBackendKubernetes,
				[]string{"vao._.test-ns.app-read"}, adapter.GetServiceAccountBindings(), nil)
			if err != nil {
				t.Fatal(err)
			}
			alias := vault.OwnershipAliasMetadata(ops.ownership(vc))
			if !reflect.DeepEqual(alias, tc.wantAlias) {
				t.Errorf("alias_metadata = %#v, want v0.12.0 %#v", alias, tc.wantAlias)
			}
			roleData[vault.RoleAliasMetadataKey] = alias
			if hash, _ := h.calculateSpecHash(roleData); hash != tc.wantHash {
				t.Errorf("hash = %q, want v0.12.0 %q", hash, tc.wantHash)
			}
		})
	}
}
