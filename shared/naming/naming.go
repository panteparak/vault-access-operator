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

// Package naming centralizes derivation of Vault resource names so a single
// operator-wide cluster prefix can be applied consistently.
//
// Vault Community Edition has no namespaces, so the ACL policy store
// (sys/policies/acl/) and the managed-marker KV mount are global across every
// operator that shares a Vault server. To let multiple clusters coexist on one
// Vault, the operator can prefix every derived Vault resource name with a
// per-cluster identifier (set via --cluster-name / CLUSTER_NAME). An empty
// prefix disables this, preserving single-cluster behavior.
package naming

import "sync/atomic"

// ponytail: cluster is an operator-wide identity, set once at startup from
// --cluster-name and read-only thereafter. A package var avoids threading it
// through every adapter constructor and handler (adapters are value structs
// built inline in many call sites and tests). atomic.Value keeps it race-clean.
// Upgrade path: if per-connection prefixes are ever needed, thread an explicit
// value through the adapters instead of this global.
var cluster atomic.Value // holds string

// SetCluster records the operator's cluster prefix. Call once at startup,
// before the manager starts. An empty name disables prefixing.
func SetCluster(name string) { cluster.Store(name) }

// Cluster returns the configured cluster prefix ("" when unset).
func Cluster() string {
	name, _ := cluster.Load().(string)
	return name
}

// Prefixed returns "{clusterName}-{base}", or base unchanged when clusterName
// is empty. It is pure (no global state) so the prefix logic is unit-testable.
func Prefixed(clusterName, base string) string {
	if clusterName == "" {
		return base
	}
	return clusterName + "-" + base
}

// Vault returns base prefixed with the operator's configured cluster prefix.
// Every Vault resource-name derivation routes through this single seam.
func Vault(base string) string { return Prefixed(Cluster(), base) }
