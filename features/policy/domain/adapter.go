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

	// Status accessors and mutators
	GetPhase() vaultv1alpha1.Phase
	SetPhase(phase vaultv1alpha1.Phase)
	GetLastAppliedHash() string
	SetLastAppliedHash(hash string)
	GetVaultName() string
	SetVaultName(name string)
	SetManaged(managed bool)
	SetRulesCount(count int)
	SetLastSyncedAt(t *metav1.Time)
	SetLastAttemptAt(t *metav1.Time)
	SetRetryCount(count int)
	GetRetryCount() int
	SetNextRetryAt(t *metav1.Time)
	SetMessage(msg string)
	GetConditions() []vaultv1alpha1.Condition
	SetConditions(conditions []vaultv1alpha1.Condition)
}

// VaultPolicyAdapter adapts VaultPolicy to the PolicyAdapter interface.
type VaultPolicyAdapter struct {
	*vaultv1alpha1.VaultPolicy
}

func NewVaultPolicyAdapter(p *vaultv1alpha1.VaultPolicy) *VaultPolicyAdapter {
	return &VaultPolicyAdapter{VaultPolicy: p}
}

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

// Status accessors
func (a *VaultPolicyAdapter) GetPhase() vaultv1alpha1.Phase            { return a.Status.Phase }
func (a *VaultPolicyAdapter) SetPhase(phase vaultv1alpha1.Phase)       { a.Status.Phase = phase }
func (a *VaultPolicyAdapter) GetLastAppliedHash() string               { return a.Status.LastAppliedHash }
func (a *VaultPolicyAdapter) SetLastAppliedHash(hash string)           { a.Status.LastAppliedHash = hash }
func (a *VaultPolicyAdapter) GetVaultName() string                     { return a.Status.VaultName }
func (a *VaultPolicyAdapter) SetVaultName(name string)                 { a.Status.VaultName = name }
func (a *VaultPolicyAdapter) SetManaged(managed bool)                  { a.Status.Managed = managed }
func (a *VaultPolicyAdapter) SetRulesCount(count int)                  { a.Status.RulesCount = count }
func (a *VaultPolicyAdapter) SetLastSyncedAt(t *metav1.Time)           { a.Status.LastSyncedAt = t }
func (a *VaultPolicyAdapter) SetLastAttemptAt(t *metav1.Time)          { a.Status.LastAttemptAt = t }
func (a *VaultPolicyAdapter) SetRetryCount(count int)                  { a.Status.RetryCount = count }
func (a *VaultPolicyAdapter) GetRetryCount() int                       { return a.Status.RetryCount }
func (a *VaultPolicyAdapter) SetNextRetryAt(t *metav1.Time)            { a.Status.NextRetryAt = t }
func (a *VaultPolicyAdapter) SetMessage(msg string)                    { a.Status.Message = msg }
func (a *VaultPolicyAdapter) GetConditions() []vaultv1alpha1.Condition { return a.Status.Conditions }
func (a *VaultPolicyAdapter) SetConditions(conditions []vaultv1alpha1.Condition) {
	a.Status.Conditions = conditions
}

// VaultClusterPolicyAdapter adapts VaultClusterPolicy to the PolicyAdapter interface.
type VaultClusterPolicyAdapter struct {
	*vaultv1alpha1.VaultClusterPolicy
}

func NewVaultClusterPolicyAdapter(p *vaultv1alpha1.VaultClusterPolicy) *VaultClusterPolicyAdapter {
	return &VaultClusterPolicyAdapter{VaultClusterPolicy: p}
}

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

// Status accessors
func (a *VaultClusterPolicyAdapter) GetPhase() vaultv1alpha1.Phase      { return a.Status.Phase }
func (a *VaultClusterPolicyAdapter) SetPhase(phase vaultv1alpha1.Phase) { a.Status.Phase = phase }
func (a *VaultClusterPolicyAdapter) GetLastAppliedHash() string         { return a.Status.LastAppliedHash }
func (a *VaultClusterPolicyAdapter) SetLastAppliedHash(hash string)     { a.Status.LastAppliedHash = hash }
func (a *VaultClusterPolicyAdapter) GetVaultName() string               { return a.Status.VaultName }
func (a *VaultClusterPolicyAdapter) SetVaultName(name string)           { a.Status.VaultName = name }
func (a *VaultClusterPolicyAdapter) SetManaged(managed bool)            { a.Status.Managed = managed }
func (a *VaultClusterPolicyAdapter) SetRulesCount(count int)            { a.Status.RulesCount = count }
func (a *VaultClusterPolicyAdapter) SetLastSyncedAt(t *metav1.Time)     { a.Status.LastSyncedAt = t }
func (a *VaultClusterPolicyAdapter) SetLastAttemptAt(t *metav1.Time)    { a.Status.LastAttemptAt = t }
func (a *VaultClusterPolicyAdapter) SetRetryCount(count int)            { a.Status.RetryCount = count }
func (a *VaultClusterPolicyAdapter) GetRetryCount() int                 { return a.Status.RetryCount }
func (a *VaultClusterPolicyAdapter) SetNextRetryAt(t *metav1.Time)      { a.Status.NextRetryAt = t }
func (a *VaultClusterPolicyAdapter) SetMessage(msg string)              { a.Status.Message = msg }
func (a *VaultClusterPolicyAdapter) GetConditions() []vaultv1alpha1.Condition {
	return a.Status.Conditions
}
func (a *VaultClusterPolicyAdapter) SetConditions(conditions []vaultv1alpha1.Condition) {
	a.Status.Conditions = conditions
}
