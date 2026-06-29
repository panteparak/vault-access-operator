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

import "testing"

func TestPrefixed(t *testing.T) {
	cases := []struct {
		name          string
		cluster, base string
		want          string
	}{
		{"empty cluster is a no-op", "", "default-admin", "default-admin"},
		{"namespaced name gets prefixed", "east", "default-admin", "east-default-admin"},
		{"cluster-scoped name gets prefixed", "east", "admin", "east-admin"},
	}
	for _, c := range cases {
		if got := Prefixed(c.cluster, c.base); got != c.want {
			t.Errorf("%s: Prefixed(%q, %q) = %q, want %q", c.name, c.cluster, c.base, got, c.want)
		}
	}
}

func TestVaultUsesConfiguredCluster(t *testing.T) {
	t.Cleanup(func() { SetCluster("") })

	SetCluster("")
	if got := Vault("ns-name"); got != "ns-name" {
		t.Errorf("Vault with empty cluster = %q, want %q", got, "ns-name")
	}

	SetCluster("west")
	if got := Vault("ns-name"); got != "west-ns-name" {
		t.Errorf("Vault with cluster=west = %q, want %q", got, "west-ns-name")
	}
}
