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

// +kubebuilder:object:generate=false

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// SyncPhaseReadWriter reads and writes phase + sync-tracking fields.
// Matches the Phase, Hash, General-tracking, Conditions sections of
// SyncStatusAccessor.
//
// +kubebuilder:object:generate=false
type SyncPhaseReadWriter interface {
	GetPhase() Phase
	SetPhase(phase Phase)

	GetLastAppliedHash() string
	SetLastAppliedHash(hash string)

	SetManaged(managed bool)
	SetLastSyncedAt(t *metav1.Time)
	SetLastAttemptAt(t *metav1.Time)
	SetRetryCount(count int)
	GetRetryCount() int
	SetNextRetryAt(t *metav1.Time)
	SetMessage(msg string)

	GetConditions() []Condition
	SetConditions(conditions []Condition)
}

// DriftStatusReadWriter reads and writes drift-state fields.
//
// +kubebuilder:object:generate=false
type DriftStatusReadWriter interface {
	GetDriftDetected() bool
	SetDriftDetected(driftDetected bool)
	SetLastDriftCheckAt(t *metav1.Time)
	GetEffectiveDriftMode() DriftMode
	SetEffectiveDriftMode(mode DriftMode)
	GetDriftSummary() string
	SetDriftSummary(summary string)
	SetDriftCorrectedAt(t *metav1.Time)
}

// DeletionStatusReadWriter reads and writes deletion-lifecycle fields.
//
// +kubebuilder:object:generate=false
type DeletionStatusReadWriter interface {
	GetDeletionStartedAt() *metav1.Time
	SetDeletionStartedAt(t *metav1.Time)
}

// BindingReadWriter reads and writes the Vault resource binding.
//
// +kubebuilder:object:generate=false
type BindingReadWriter interface {
	GetBinding() VaultResourceBinding
	SetBinding(binding VaultResourceBinding)
}

// SyncStatusReadWriter is the composition of all SyncStatus-backed fields,
// implemented via SyncStatusAccessor embedding in concrete adapter types.
// Consumers that need only a subset (e.g. syncerror only writes phase and
// retry fields) should depend on the narrower sub-interfaces above.
//
// +kubebuilder:object:generate=false
type SyncStatusReadWriter interface {
	SyncPhaseReadWriter
	DriftStatusReadWriter
	DeletionStatusReadWriter
	BindingReadWriter
}

// Compile-time check: SyncStatusAccessor must satisfy the composed interface.
// This keeps the interface and implementation in lockstep as fields are
// added or renamed.
var _ SyncStatusReadWriter = (*SyncStatusAccessor)(nil)
