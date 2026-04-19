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

// Package domain provides domain types and adapters for the policy feature.
package domain

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// PolicyAdapter provides a unified interface for both VaultPolicy and VaultClusterPolicy.
// This allows shared logic in the handler while respecting type-specific differences.
type PolicyAdapter interface {
	client.Object

	// GetObject returns the underlying Kubernetes API object (e.g. *VaultPolicy).
	// Use this when passing to client.Status().Update() since the adapter wrapper
	// type is not registered in the runtime scheme.
	GetObject() client.Object

	// GetConnectionRef returns the name of the VaultConnection to use
	GetConnectionRef() string

	// GetRules returns the policy rules
	GetRules() []vaultv1alpha1.PolicyRule

	// GetDeletionPolicy returns the deletion policy
	GetDeletionPolicy() vaultv1alpha1.DeletionPolicy

	// GetConflictPolicy returns the conflict handling policy
	GetConflictPolicy() vaultv1alpha1.ConflictPolicy

	// GetVaultPolicyName returns the policy name in Vault
	// For namespaced: {namespace}-{name}, for cluster: {name}
	GetVaultPolicyName() string

	// GetK8sResourceIdentifier returns the identifier for tracking ownership
	// For namespaced: {namespace}/{name}, for cluster: {name}
	GetK8sResourceIdentifier() string

	// IsNamespaced returns true for VaultPolicy, false for VaultClusterPolicy
	IsNamespaced() bool

	// IsEnforceNamespaceBoundary returns whether namespace boundary is enforced
	IsEnforceNamespaceBoundary() bool

	// Policy-specific status fields
	GetVaultName() string
	SetVaultName(name string)
	SetRulesCount(count int)

	// UsedByRoles is the reverse policy→role index (IMPROVEMENTS §B).
	// Populated by the policy reconciler from a list of all VaultRole
	// and VaultClusterRole resources that reference this policy.
	GetUsedByRoles() []string
	SetUsedByRoles(refs []string)

	// Drift mode from spec
	GetDriftMode() vaultv1alpha1.DriftMode

	// Common sync status methods (implemented via SyncStatusAccessor embedding)
	GetPhase() vaultv1alpha1.Phase
	SetPhase(phase vaultv1alpha1.Phase)
	GetLastAppliedHash() string
	SetLastAppliedHash(hash string)
	SetManaged(managed bool)
	SetLastSyncedAt(t *metav1.Time)
	SetLastAttemptAt(t *metav1.Time)
	SetRetryCount(count int)
	GetRetryCount() int
	SetNextRetryAt(t *metav1.Time)
	SetMessage(msg string)
	GetConditions() []vaultv1alpha1.Condition
	SetConditions(conditions []vaultv1alpha1.Condition)
	GetDriftDetected() bool
	SetDriftDetected(driftDetected bool)
	SetLastDriftCheckAt(t *metav1.Time)
	GetEffectiveDriftMode() vaultv1alpha1.DriftMode
	SetEffectiveDriftMode(mode vaultv1alpha1.DriftMode)
	GetDriftSummary() string
	SetDriftSummary(summary string)
	SetDriftCorrectedAt(t *metav1.Time)
	GetDeletionStartedAt() *metav1.Time
	SetDeletionStartedAt(t *metav1.Time)
	GetBinding() vaultv1alpha1.VaultResourceBinding
	SetBinding(binding vaultv1alpha1.VaultResourceBinding)
}

// VaultPolicyAdapter adapts VaultPolicy to the PolicyAdapter interface.
type VaultPolicyAdapter struct {
	*vaultv1alpha1.VaultPolicy
	vaultv1alpha1.SyncStatusAccessor
}

func NewVaultPolicyAdapter(p *vaultv1alpha1.VaultPolicy) *VaultPolicyAdapter {
	return &VaultPolicyAdapter{
		VaultPolicy:        p,
		SyncStatusAccessor: vaultv1alpha1.NewSyncStatusAccessor(&p.Status.SyncStatus),
	}
}

func (a *VaultPolicyAdapter) GetObject() client.Object             { return a.VaultPolicy }
func (a *VaultPolicyAdapter) GetConnectionRef() string             { return a.Spec.ConnectionRef }
func (a *VaultPolicyAdapter) GetRules() []vaultv1alpha1.PolicyRule { return a.Spec.Rules }
func (a *VaultPolicyAdapter) GetDeletionPolicy() vaultv1alpha1.DeletionPolicy {
	return a.Spec.DeletionPolicy
}
func (a *VaultPolicyAdapter) GetConflictPolicy() vaultv1alpha1.ConflictPolicy {
	return a.Spec.ConflictPolicy
}
func (a *VaultPolicyAdapter) GetVaultPolicyName() string       { return a.Namespace + "-" + a.Name }
func (a *VaultPolicyAdapter) GetK8sResourceIdentifier() string { return a.Namespace + "/" + a.Name }
func (a *VaultPolicyAdapter) IsNamespaced() bool               { return true }
func (a *VaultPolicyAdapter) IsEnforceNamespaceBoundary() bool {
	return a.Spec.IsEnforceNamespaceBoundary()
}
func (a *VaultPolicyAdapter) GetVaultName() string                  { return a.Status.VaultName }
func (a *VaultPolicyAdapter) SetVaultName(name string)              { a.Status.VaultName = name }
func (a *VaultPolicyAdapter) SetRulesCount(count int)               { a.Status.RulesCount = count }
func (a *VaultPolicyAdapter) GetUsedByRoles() []string              { return a.Status.UsedByRoles }
func (a *VaultPolicyAdapter) SetUsedByRoles(refs []string)          { a.Status.UsedByRoles = refs }
func (a *VaultPolicyAdapter) GetDriftMode() vaultv1alpha1.DriftMode { return a.Spec.DriftMode }

// VaultClusterPolicyAdapter adapts VaultClusterPolicy to the PolicyAdapter interface.
type VaultClusterPolicyAdapter struct {
	*vaultv1alpha1.VaultClusterPolicy
	vaultv1alpha1.SyncStatusAccessor
}

func NewVaultClusterPolicyAdapter(p *vaultv1alpha1.VaultClusterPolicy) *VaultClusterPolicyAdapter {
	return &VaultClusterPolicyAdapter{
		VaultClusterPolicy: p,
		SyncStatusAccessor: vaultv1alpha1.NewSyncStatusAccessor(&p.Status.SyncStatus),
	}
}

func (a *VaultClusterPolicyAdapter) GetObject() client.Object             { return a.VaultClusterPolicy }
func (a *VaultClusterPolicyAdapter) GetConnectionRef() string             { return a.Spec.ConnectionRef }
func (a *VaultClusterPolicyAdapter) GetRules() []vaultv1alpha1.PolicyRule { return a.Spec.Rules }
func (a *VaultClusterPolicyAdapter) GetDeletionPolicy() vaultv1alpha1.DeletionPolicy {
	return a.Spec.DeletionPolicy
}
func (a *VaultClusterPolicyAdapter) GetConflictPolicy() vaultv1alpha1.ConflictPolicy {
	return a.Spec.ConflictPolicy
}
func (a *VaultClusterPolicyAdapter) GetVaultPolicyName() string       { return a.Name }
func (a *VaultClusterPolicyAdapter) GetK8sResourceIdentifier() string { return a.Name }
func (a *VaultClusterPolicyAdapter) IsNamespaced() bool               { return false }

// Cluster-scoped policies don't enforce namespace boundary
func (a *VaultClusterPolicyAdapter) IsEnforceNamespaceBoundary() bool { return false }

func (a *VaultClusterPolicyAdapter) GetVaultName() string                  { return a.Status.VaultName }
func (a *VaultClusterPolicyAdapter) SetVaultName(name string)              { a.Status.VaultName = name }
func (a *VaultClusterPolicyAdapter) SetRulesCount(count int)               { a.Status.RulesCount = count }
func (a *VaultClusterPolicyAdapter) GetUsedByRoles() []string              { return a.Status.UsedByRoles }
func (a *VaultClusterPolicyAdapter) SetUsedByRoles(refs []string)          { a.Status.UsedByRoles = refs }
func (a *VaultClusterPolicyAdapter) GetDriftMode() vaultv1alpha1.DriftMode { return a.Spec.DriftMode }
