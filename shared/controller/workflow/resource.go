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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// SyncableResource is the common interface shared by PolicyAdapter and RoleAdapter.
// It provides the status fields that the shared workflow needs to read and write.
// Both adapters satisfy this interface via SyncStatusAccessor embedding (for common
// status methods) plus a handful of resource-specific identity/spec methods.
type SyncableResource interface {
	client.Object

	// GetObject returns the underlying K8s API object for status updates.
	GetObject() client.Object

	// GetConnectionRef returns the VaultConnection name.
	GetConnectionRef() string

	// GetK8sResourceIdentifier returns the ownership identifier (e.g., "namespace/name").
	GetK8sResourceIdentifier() string

	// IsNamespaced returns true for namespaced resources, false for cluster-scoped.
	IsNamespaced() bool

	// Spec fields needed by workflow
	GetDeletionPolicy() vaultv1alpha1.DeletionPolicy
	GetConflictPolicy() vaultv1alpha1.ConflictPolicy
	GetDriftMode() vaultv1alpha1.DriftMode

	// Common sync status methods (implemented via SyncStatusAccessor embedding
	// in concrete adapter types)

	// Phase
	GetPhase() vaultv1alpha1.Phase
	SetPhase(phase vaultv1alpha1.Phase)

	// Hash
	GetLastAppliedHash() string
	SetLastAppliedHash(hash string)

	// General sync tracking
	SetManaged(managed bool)
	SetLastSyncedAt(t *metav1.Time)
	SetLastAttemptAt(t *metav1.Time)
	SetRetryCount(count int)
	GetRetryCount() int
	SetNextRetryAt(t *metav1.Time)
	SetMessage(msg string)

	// Conditions
	GetConditions() []vaultv1alpha1.Condition
	SetConditions(conditions []vaultv1alpha1.Condition)

	// Drift
	GetDriftDetected() bool
	SetDriftDetected(driftDetected bool)
	SetLastDriftCheckAt(t *metav1.Time)
	GetEffectiveDriftMode() vaultv1alpha1.DriftMode
	SetEffectiveDriftMode(mode vaultv1alpha1.DriftMode)
	GetDriftSummary() string
	SetDriftSummary(summary string)
	SetDriftCorrectedAt(t *metav1.Time)

	// Deletion
	GetDeletionStartedAt() *metav1.Time
	SetDeletionStartedAt(t *metav1.Time)

	// Binding
	GetBinding() vaultv1alpha1.VaultResourceBinding
	SetBinding(binding vaultv1alpha1.VaultResourceBinding)
}
