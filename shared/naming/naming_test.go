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
	"regexp"
	"strings"
	"testing"
)

// TestIdentity pins the naming precedence (ADR 0011, #18 AC6):
// spec.identity.name > --cluster-name > login mount > "_".
func TestIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		spec        string
		clusterName string
		authMount   string
		want        string
		wantSource  string
	}{
		{name: "spec wins over flag and mount", spec: "proj", clusterName: "pe", authMount: "ep-digital-pe",
			want: "proj", wantSource: SourceSpec},
		{name: "spec wins over mount", spec: "proj", authMount: "ep-digital-pe", want: "proj", wantSource: SourceSpec},
		{name: "flag wins over mount", clusterName: "pe", authMount: "ep-digital-pe", want: "pe",
			wantSource: SourceClusterName},
		{name: "mount fallback when flag empty", authMount: "ep-digital-pe", want: "ep-digital-pe",
			wantSource: SourceAuthMount},
		{name: "all empty yields placeholder", want: Placeholder, wantSource: SourceNone},
		{name: "nested mount slashes sanitized", authMount: "teams/pe", want: "teams-pe", wantSource: SourceAuthMount},
		{name: "dotted mount sanitized", authMount: "a.b", want: "a-b", wantSource: SourceAuthMount},
		{name: "bare underscore mount cannot impersonate placeholder", authMount: "_", want: "-",
			wantSource: SourceAuthMount},
		{name: "kubernetes default mount", authMount: "kubernetes", want: "kubernetes", wantSource: SourceAuthMount},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, source := Identity(tt.spec, tt.clusterName, tt.authMount)
			if got != tt.want || source != tt.wantSource {
				t.Errorf("Identity(%q, %q, %q) = (%q, %q), want (%q, %q)",
					tt.spec, tt.clusterName, tt.authMount, got, source, tt.want, tt.wantSource)
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
		namespace = SanitizeMount(namespace)
		if namespace == "-" || namespace == Placeholder {
			namespace = ""
		}
		identity, _ := Identity("", "", mount)

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

// specIdentityRE is the CRD pattern on VaultConnection spec.identity.name;
// clusterNameRE is the --cluster-name pattern (cmd/main.go).
var (
	specIdentityRE = regexp.MustCompile(`^[a-z0-9-]+$`)
	clusterNameRE  = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
)

// FuzzVaultName_Unique pins #18 AC6: across every identity source (spec,
// cluster name, login mount, none), two different (identity, namespace,
// name) triples never produce the same Vault name, and no source can yield
// a dotted or placeholder-impersonating segment. Spec identities and
// cluster names are filtered through their real validation patterns.
func FuzzVaultName_Unique(f *testing.F) {
	f.Add("proj", "", "", "default", "app", "", "pe", "", "default", "app")
	f.Add("", "pe", "", "ns", "a.b", "", "", "pe", "ns", "a.b")
	f.Add("", "", "a.b", "x", "y", "a-b", "", "", "x", "y")
	f.Add("", "", "", "", "default.admin", "", "", "", "default", "admin")
	f.Fuzz(func(t *testing.T, specA, clusterA, mountA, nsA, nameA, specB, clusterB, mountB, nsB, nameB string) {
		idA, okA := fuzzIdentity(specA, clusterA, mountA)
		idB, okB := fuzzIdentity(specB, clusterB, mountB)
		if !okA || !okB || nameA == "" || nameB == "" {
			t.Skip("input rejected by validation")
		}
		nsA, nsB = fuzzNamespace(nsA), fuzzNamespace(nsB)
		for _, id := range []string{idA, idB} {
			if strings.Contains(id, ".") || id == "" {
				t.Fatalf("identity segment %q is empty or dotted", id)
			}
		}
		same := idA == idB && nsA == nsB && nameA == nameB
		if (VaultName(idA, nsA, nameA) == VaultName(idB, nsB, nameB)) != same {
			t.Fatalf("uniqueness violated: (%q,%q,%q) vs (%q,%q,%q) -> %q / %q",
				idA, nsA, nameA, idB, nsB, nameB, VaultName(idA, nsA, nameA), VaultName(idB, nsB, nameB))
		}
	})
}

// fuzzIdentity resolves an identity the way production does, after the
// same validation production applies (CRD pattern + "_" refusal for spec,
// --cluster-name pattern for the flag). ok=false means validation rejects it.
func fuzzIdentity(spec, cluster, mount string) (string, bool) {
	if spec != "" && (!specIdentityRE.MatchString(spec) || len(spec) > 40) {
		return "", false
	}
	if cluster != "" && !clusterNameRE.MatchString(cluster) {
		return "", false
	}
	id, source := Identity(spec, cluster, mount)
	if source != SourceNone && id == Placeholder {
		panic("a real identity source produced the placeholder")
	}
	return id, true
}

// fuzzNamespace maps fuzz input onto a dot-free namespace ("" = cluster-scoped).
func fuzzNamespace(ns string) string {
	ns = SanitizeMount(ns)
	if ns == "-" || ns == Placeholder {
		return ""
	}
	return ns
}

func TestIdentityOf(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		in, want string
		ok       bool
	}{
		{"vao.proj.ns.app", "proj", true},
		{"vao._._.cluster-policy", "_", true},
		{"vao.pe.ns.name.with.dots", "pe", true},
		{"legacy-policy-name", "", false},
		{"vao..ns.app", "", false},
		{"other.pe.ns.app", "", false},
	} {
		got, ok := IdentityOf(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("IdentityOf(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
