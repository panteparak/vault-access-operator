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

// Package workflow provides shared sync and cleanup orchestration for Vault resources.
// It encapsulates the common reconciliation flow used by both policy and role handlers,
// parameterized by resource-specific operations via the ResourceOps interface.
package workflow

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// VaultResourceIdentity captures the immutable identity and scope of a
// Vault resource during reconciliation. Consumers that only need to read
// the resource's identity (connection ref, scope, spec policies) should
// depend on this narrower interface.
type VaultResourceIdentity interface {
	client.Object

	// GetObject returns the underlying K8s API object for status updates.
	GetObject() client.Object

	// GetConnectionRef returns the VaultConnection name.
	GetConnectionRef() string

	// GetK8sResourceIdentifier returns the ownership identifier (e.g., "namespace/name").
	GetK8sResourceIdentifier() string

	// IsNamespaced returns true for namespaced resources, false for cluster-scoped.
	IsNamespaced() bool

	// Spec policies influencing workflow behavior.
	GetDeletionPolicy() vaultv1alpha1.DeletionPolicy
	GetConflictPolicy() vaultv1alpha1.ConflictPolicy
	GetDriftMode() vaultv1alpha1.DriftMode
}

// SyncableResource is the common interface shared by PolicyAdapter and
// RoleAdapter. It composes the narrow identity view with the full set of
// status-writing sub-interfaces implemented by SyncStatusAccessor.
type SyncableResource interface {
	VaultResourceIdentity
	vaultv1alpha1.SyncStatusReadWriter
}
