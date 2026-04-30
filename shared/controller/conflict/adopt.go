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

// Package conflict contains cross-feature helpers for conflict detection
// and adoption (IMPROVEMENTS §13). Each CRD family (policy, role) previously
// duplicated the same shouldAdopt logic byte-for-byte. Centralizing here
// keeps the annotation/policy precedence rule in one place so a future
// change (e.g., a third trigger like a ClusterAdopt CRD) applies uniformly.
package conflict

import (
	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// AdoptCandidate is the minimal adapter surface shouldAdopt needs. Both
// PolicyAdapter and RoleAdapter satisfy it. Interface defined in this
// package (not in features/*) so the helper can stay dependency-free.
type AdoptCandidate interface {
	GetAnnotations() map[string]string
	GetConflictPolicy() vaultv1alpha1.ConflictPolicy
}

// ShouldAdopt returns true when either:
//   - the resource carries `vault.platform.io/adopt=true` (annotation wins),
//     OR
//   - the resource's ConflictPolicy is `Adopt`.
//
// The annotation-wins rule is load-bearing: users can temporarily override a
// `ConflictPolicy: Fail` spec by annotating the CR without editing its
// canonical spec, useful for one-off adoption of resources created outside
// the GitOps loop.
func ShouldAdopt(adapter AdoptCandidate) bool {
	// Check annotation first (takes precedence)
	if adapter.GetAnnotations()[vaultv1alpha1.AnnotationAdopt] == vaultv1alpha1.AnnotationValueTrue {
		return true
	}
	// Fall back to ConflictPolicy
	return adapter.GetConflictPolicy() == vaultv1alpha1.ConflictPolicyAdopt
}
