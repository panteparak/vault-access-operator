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
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

// TestGolden_V012_RoleUnchangedWithoutIdentity pins #18 AC11 for roles:
// with no spec.identity, the Vault name, the alias_metadata record and the
// content hash PrepareContent returns are byte-identical to v0.12.0's
// (literals produced by running this same test body on v0.12.0, d4fc34e).
func TestGolden_V012_RoleUnchangedWithoutIdentity(t *testing.T) {
	record := func(extra map[string]string) map[string]string {
		m := map[string]string{"k8s-kind": "VaultRole", "k8s-resource": "test-ns/test-role",
			"managed-by": "vault-access-operator"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for _, tc := range []struct {
		mount, cluster, wantName, wantHash string
		wantAlias                          map[string]string
	}{
		{"kubernetes", "", "vao.kubernetes.test-ns.test-role",
			"9957d770a0b931b15bf71f340abc374b05d5ebdc9f7fba1828fef51dc097b46e",
			record(map[string]string{"auth-mount": "kubernetes"})},
		{"", "pe", "vao.pe.test-ns.test-role",
			"58303a9541a0755374cb3818a89d7b279b69296e9c3ee189e4f94f98507f7f58",
			record(map[string]string{"cluster": "pe"})},
		{"kubernetes", "pe", "vao.pe.test-ns.test-role",
			"eb7f9b321d670640dcedb775887d91085053e6e34a54413f91bb33419c5c823e",
			record(map[string]string{"auth-mount": "kubernetes", "cluster": "pe"})},
	} {
		t.Run("mount="+tc.mount+",cluster="+tc.cluster, func(t *testing.T) {
			naming.SetCluster(tc.cluster)
			t.Cleanup(func() { naming.SetCluster("") })
			server := newMockVaultServer(mockVaultServerConfig{state: newMockVaultState()})
			t.Cleanup(server.Close)
			vc := newTestCachedVaultClient(t, server.URL)
			vc.SetAuthMount(tc.mount)

			role := newTestVaultRole()
			refPolicy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "app-read", Namespace: testNamespace},
				Status:     vaultv1alpha1.VaultPolicyStatus{VaultName: "vao._.test-ns.app-read"},
			}
			k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(role, refPolicy).Build()
			adapter := domain.NewVaultRoleAdapter(role)
			ops := NewRoleOps(adapter, &Handler{client: k8s}, &roleTarget{mount: "kubernetes"})

			if got := ops.BindVaultName(vc); got != tc.wantName {
				t.Errorf("name = %q, want %q", got, tc.wantName)
			}
			hash, err := ops.PrepareContent(context.Background(), vc)
			if err != nil {
				t.Fatal(err)
			}
			if alias := ops.roleData[vault.RoleAliasMetadataKey]; !reflect.DeepEqual(alias, tc.wantAlias) {
				t.Errorf("alias_metadata = %#v, want v0.12.0 %#v", alias, tc.wantAlias)
			}
			if hash != tc.wantHash {
				t.Errorf("hash = %q, want v0.12.0 %q", hash, tc.wantHash)
			}
		})
	}
}
