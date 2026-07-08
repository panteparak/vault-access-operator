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

package naming

import (
	"strings"
	"testing"
)

func TestIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		clusterName string
		authMount   string
		want        string
	}{
		{name: "flag wins over mount", clusterName: "pe", authMount: "ep-digital-pe", want: "pe"},
		{name: "mount fallback when flag empty", clusterName: "", authMount: "ep-digital-pe", want: "ep-digital-pe"},
		{name: "both empty yields placeholder", clusterName: "", authMount: "", want: Placeholder},
		{name: "nested mount slashes sanitized", clusterName: "", authMount: "teams/pe", want: "teams-pe"},
		{name: "dotted mount sanitized", clusterName: "", authMount: "a.b", want: "a-b"},
		{name: "bare underscore mount cannot impersonate placeholder", clusterName: "", authMount: "_", want: "-"},
		{name: "kubernetes default mount", clusterName: "", authMount: "kubernetes", want: "kubernetes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Identity(tt.clusterName, tt.authMount); got != tt.want {
				t.Errorf("Identity(%q, %q) = %q, want %q", tt.clusterName, tt.authMount, got, tt.want)
			}
		})
	}
}

func TestVaultName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		identity  string
		namespace string
		crName    string
		want      string
	}{
		{
			name: "namespaced with cluster identity", identity: "pe",
			namespace: "default", crName: "app-secrets", want: "vao.pe.default.app-secrets",
		},
		{
			name: "cluster-scoped with cluster identity", identity: "pe",
			namespace: "", crName: "admin", want: "vao.pe._.admin",
		},
		{
			name: "namespaced without identity", identity: Placeholder,
			namespace: "default", crName: "app-secrets", want: "vao._.default.app-secrets",
		},
		{
			name: "cluster-scoped without identity", identity: Placeholder,
			namespace: "", crName: "admin", want: "vao._._.admin",
		},
		{
			name: "dotted CR name stays last segment", identity: "pe",
			namespace: "default", crName: "my.dotted.name", want: "vao.pe.default.my.dotted.name",
		},
		{
			name: "mount-derived identity", identity: "ep-digital-pe",
			namespace: "vault-access-operator", crName: "app-role",
			want: "vao.ep-digital-pe.vault-access-operator.app-role",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := VaultName(tt.identity, tt.namespace, tt.crName); got != tt.want {
				t.Errorf("VaultName(%q, %q, %q) = %q, want %q", tt.identity, tt.namespace, tt.crName, got, tt.want)
			}
		})
	}
}

// TestVaultName_ClusterScopedNeverCollidesWithNamespaced pins the injectivity
// hole that killed the variable-arity design: a cluster-scoped CR with a
// dotted name must not impersonate a namespaced (ns, name) pair.
func TestVaultName_ClusterScopedNeverCollidesWithNamespaced(t *testing.T) {
	t.Parallel()
	clusterScoped := VaultName("pe", "", "default.admin")
	namespaced := VaultName("pe", "default", "admin")
	if clusterScoped == namespaced {
		t.Errorf("cluster-scoped %q collides with namespaced %q", clusterScoped, namespaced)
	}
}

func TestSetClusterAndCluster(t *testing.T) {
	// Mutates package state — not parallel.
	SetCluster("pe")
	defer SetCluster("")
	if got := Cluster(); got != "pe" {
		t.Errorf("Cluster() = %q, want %q", got, "pe")
	}
}

// FuzzVaultName asserts the injectivity contract (F12): the fixed 4-segment
// shape must be losslessly parseable — splitting on the first 3 dots recovers
// exactly (identity, namespace, name) — for every input the operator can
// produce. identity/namespace are constrained to their real charsets by
// mapping arbitrary fuzz input through the same rules production uses.
func FuzzVaultName(f *testing.F) {
	f.Add("pe", "default", "app-secrets")
	f.Add("", "", "admin")
	f.Add("_", "default", "my.dotted.name")
	f.Add("ep-digital/pe", "kube-system", "a")
	f.Add("a.b", "ns", "x_y")
	f.Fuzz(func(t *testing.T, mount, namespace, name string) {
		if name == "" {
			t.Skip("CR names are never empty")
		}
		// Namespaces are RFC 1123 labels (no dots); emulate by running the
		// fuzz input through the same charset mapping the mount sanitizer
		// uses, discarding reserved results.
		namespace = sanitizeMount(namespace)
		if namespace == "-" || namespace == Placeholder {
			namespace = ""
		}
		identity := Identity("", mount)

		got := VaultName(identity, namespace, name)

		parts := strings.SplitN(got, ".", 4)
		if len(parts) != 4 {
			t.Fatalf("VaultName(%q, %q, %q) = %q: want 4 dot segments", identity, namespace, name, got)
		}
		wantNS := namespace
		if wantNS == "" {
			wantNS = Placeholder
		}
		if parts[0] != Marker || parts[1] != identity || parts[2] != wantNS || parts[3] != name {
			t.Fatalf("round-trip mismatch: %q parsed to %v, want [%s %s %s %s]",
				got, parts, Marker, identity, wantNS, name)
		}
		if strings.Contains(identity, ".") {
			t.Fatalf("identity %q contains a dot — segment charset violated", identity)
		}
	})
}
