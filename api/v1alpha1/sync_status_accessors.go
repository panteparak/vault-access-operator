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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SyncStatusAccessor provides getter/setter methods for all SyncStatus fields.
// Embed this in adapter structs to eliminate repetitive delegation boilerplate.
// The adapter only needs to implement the 3-5 methods that actually differ
// between namespaced and cluster-scoped resource types.
type SyncStatusAccessor struct {
	s *SyncStatus
}

// NewSyncStatusAccessor creates a new SyncStatusAccessor wrapping the given SyncStatus pointer.
func NewSyncStatusAccessor(s *SyncStatus) SyncStatusAccessor {
	return SyncStatusAccessor{s: s}
}

// --- Phase ---

func (a *SyncStatusAccessor) GetPhase() Phase      { return a.s.Phase }
func (a *SyncStatusAccessor) SetPhase(phase Phase) { a.s.Phase = phase }

// --- Hash ---

func (a *SyncStatusAccessor) GetLastAppliedHash() string     { return a.s.LastAppliedHash }
func (a *SyncStatusAccessor) SetLastAppliedHash(hash string) { a.s.LastAppliedHash = hash }

// --- General sync tracking ---

func (a *SyncStatusAccessor) SetManaged(managed bool)         { a.s.Managed = managed }
func (a *SyncStatusAccessor) SetLastSyncedAt(t *metav1.Time)  { a.s.LastSyncedAt = t }
func (a *SyncStatusAccessor) SetLastAttemptAt(t *metav1.Time) { a.s.LastAttemptAt = t }
func (a *SyncStatusAccessor) SetRetryCount(count int)         { a.s.RetryCount = count }
func (a *SyncStatusAccessor) GetRetryCount() int              { return a.s.RetryCount }
func (a *SyncStatusAccessor) SetNextRetryAt(t *metav1.Time)   { a.s.NextRetryAt = t }
func (a *SyncStatusAccessor) SetMessage(msg string)           { a.s.Message = msg }

// --- Conditions ---

func (a *SyncStatusAccessor) GetConditions() []Condition { return a.s.Conditions }
func (a *SyncStatusAccessor) SetConditions(conditions []Condition) {
	a.s.Conditions = conditions
}

// --- Drift ---

func (a *SyncStatusAccessor) GetDriftDetected() bool              { return a.s.DriftDetected }
func (a *SyncStatusAccessor) SetDriftDetected(driftDetected bool) { a.s.DriftDetected = driftDetected }
func (a *SyncStatusAccessor) SetLastDriftCheckAt(t *metav1.Time)  { a.s.LastDriftCheckAt = t }
func (a *SyncStatusAccessor) GetEffectiveDriftMode() DriftMode    { return a.s.EffectiveDriftMode }
func (a *SyncStatusAccessor) SetEffectiveDriftMode(mode DriftMode) {
	a.s.EffectiveDriftMode = mode
}
func (a *SyncStatusAccessor) GetDriftSummary() string            { return a.s.DriftSummary }
func (a *SyncStatusAccessor) SetDriftSummary(summary string)     { a.s.DriftSummary = summary }
func (a *SyncStatusAccessor) GetDriftCorrectedAt() *metav1.Time  { return a.s.DriftCorrectedAt }
func (a *SyncStatusAccessor) SetDriftCorrectedAt(t *metav1.Time) { a.s.DriftCorrectedAt = t }

// --- Deletion ---

func (a *SyncStatusAccessor) GetDeletionStartedAt() *metav1.Time { return a.s.DeletionStartedAt }
func (a *SyncStatusAccessor) SetDeletionStartedAt(t *metav1.Time) {
	a.s.DeletionStartedAt = t
}

// --- Binding ---

func (a *SyncStatusAccessor) GetBinding() VaultResourceBinding { return a.s.Binding }
func (a *SyncStatusAccessor) SetBinding(binding VaultResourceBinding) {
	a.s.Binding = binding
}
