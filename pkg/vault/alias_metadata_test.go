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

package vault

import "testing"

// TestOwnershipAliasMetadata_RoundTrip pins the role ownership record
// (ADR 0010): what OwnershipAliasMetadata writes, ParseAliasMetadata reads
// back identically after the JSON round-trip Vault performs (string map in,
// map[string]interface{} out).
func TestOwnershipAliasMetadata_RoundTrip(t *testing.T) {
	t.Parallel()
	in := Ownership{
		ManagedBy:   KVManagedByValue,
		AuthMount:   "ep-digital-pe",
		Cluster:     "pe",
		K8sResource: "default/app-role",
		K8sKind:     "VaultRole",
	}

	rendered := OwnershipAliasMetadata(in)

	// Simulate Vault's echo: string map comes back as map[string]interface{}.
	echoed := make(map[string]interface{}, len(rendered))
	for k, v := range rendered {
		echoed[k] = v
	}
	out, ok := ParseAliasMetadata(map[string]interface{}{RoleAliasMetadataKey: echoed})
	if !ok {
		t.Fatal("ParseAliasMetadata: ok = false, want true")
	}
	if out != in {
		t.Errorf("round-trip mismatch: got %+v, want %+v", out, in)
	}
	if !out.SameOwner("ep-digital-pe", "default/app-role") {
		t.Error("SameOwner should match the original identity")
	}
	if out.SameOwner("other-mount", "default/app-role") {
		t.Error("SameOwner must reject a different auth mount")
	}
}

// TestParseAliasMetadata_NoRecord: a hand-created role (no alias_metadata,
// or metadata without the sentinel) carries no ownership record.
func TestParseAliasMetadata_NoRecord(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data map[string]interface{}
	}{
		{"no alias_metadata", map[string]interface{}{"token_ttl": 3600}},
		{"alias_metadata without sentinel", map[string]interface{}{
			RoleAliasMetadataKey: map[string]interface{}{"team": "payments"},
		}},
		{"nil data", nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, ok := ParseAliasMetadata(tt.data); ok {
				t.Error("ok = true, want false for non-operator role data")
			}
		})
	}
}
