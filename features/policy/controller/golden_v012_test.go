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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

// TestGolden_V012_PolicyUnchangedWithoutIdentity pins #18 AC11: with no
// spec.identity, the Vault name, the policy document (ownership header +
// body) and the content hash are byte-identical to what v0.12.0 wrote, so an
// upgrade rewrites nothing. The literals were produced by v0.12.0 (d4fc34e)
// from the same inputs.
func TestGolden_V012_PolicyUnchangedWithoutIdentity(t *testing.T) {
	const body = "path \"secret/data/team-a/*\" {\n  capabilities = [\"read\", \"list\"]\n}\n"
	for _, tc := range []struct {
		mount, cluster, wantName, wantHash, wantHCL string
	}{
		{"kubernetes", "", "vao.kubernetes.team-a.app",
			"b98af791d2b1da84c4662f31b30e04233f6a0ede5c494185941f1ab9e5cc342d",
			"# managed-by: vault-access-operator\n# auth-mount: kubernetes\n# k8s-resource: team-a/app\n" +
				"# k8s-kind: VaultPolicy\n\n" + body},
		{"", "pe", "vao.pe.team-a.app",
			"de121cda5a6d1101ffa273a85d243059603a8c8bf488cbd9970391ad67e965a4",
			"# managed-by: vault-access-operator\n# cluster: pe\n# k8s-resource: team-a/app\n" +
				"# k8s-kind: VaultPolicy\n\n" + body},
		{"", "", "vao._.team-a.app",
			"94f58effb5573cead613035b5c4a6c5b4cc7c5aa24715c18cef6f10d183ad11f",
			"# managed-by: vault-access-operator\n# k8s-resource: team-a/app\n# k8s-kind: VaultPolicy\n\n" + body},
	} {
		t.Run("mount="+tc.mount+",cluster="+tc.cluster, func(t *testing.T) {
			naming.SetCluster(tc.cluster)
			t.Cleanup(func() { naming.SetCluster("") })
			p := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"},
				Spec: vaultv1alpha1.VaultPolicySpec{ConnectionRef: "c", Rules: []vaultv1alpha1.PolicyRule{
					{Path: "secret/data/{{namespace}}/*", Capabilities: []vaultv1alpha1.Capability{"read", "list"}},
				}},
			}
			mc := newMockVaultClient()
			mc.authMount = tc.mount
			ops := NewPolicyOps(domain.NewVaultPolicyAdapter(p), &Handler{})
			if got := ops.BindVaultName(mc); got != tc.wantName {
				t.Errorf("name = %q, want %q", got, tc.wantName)
			}
			hash, err := ops.PrepareContent(context.Background(), mc)
			if err != nil {
				t.Fatal(err)
			}
			if ops.hcl != tc.wantHCL {
				t.Errorf("document differs from v0.12.0:\ngot  %q\nwant %q", ops.hcl, tc.wantHCL)
			}
			if hash != tc.wantHash {
				t.Errorf("hash = %q, want v0.12.0 %q", hash, tc.wantHash)
			}
		})
	}
}

// TestPolicyOps_SpecIdentity pins #18 AC6 precedence (spec.identity.name
// wins over --cluster-name and the login mount) and the records it leaves:
// the header gains an identity line, status.binding names the identity and
// the connection.
func TestPolicyOps_SpecIdentity(t *testing.T) {
	naming.SetCluster("pe")
	t.Cleanup(func() { naming.SetCluster("") })
	p := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"},
		Spec: vaultv1alpha1.VaultPolicySpec{ConnectionRef: "proj-conn", Rules: []vaultv1alpha1.PolicyRule{
			{Path: "secret/data/x", Capabilities: []vaultv1alpha1.Capability{"read"}},
		}},
	}
	mc := newMockVaultClient()
	mc.authMount, mc.specIdentity = "kubernetes", "proj"
	adapter := domain.NewVaultPolicyAdapter(p)
	ops := NewPolicyOps(adapter, &Handler{})
	if got := ops.BindVaultName(mc); got != "vao.proj.team-a.app" {
		t.Errorf("name = %q, want vao.proj.team-a.app", got)
	}
	if _, err := ops.PrepareContent(context.Background(), mc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ops.hcl, "# cluster: pe\n# identity: proj\n") {
		t.Errorf("header lacks the identity line:\n%s", ops.hcl)
	}
	ops.ApplyBindings()
	if b := p.Status.Binding; b.Connection != "proj-conn" {
		t.Errorf("binding connection = %q, want proj-conn", b.Connection)
	}
}
