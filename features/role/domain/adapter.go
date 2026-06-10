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

// Package domain provides domain types and adapters for the role feature.
package domain

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// RoleAdapter provides a unified interface for both VaultRole and VaultClusterRole.
// This allows shared logic in the handler while respecting type-specific differences.
//
// Common sync-status methods are provided via vaultv1alpha1.SyncStatusReadWriter
// (implemented by SyncStatusAccessor embedding in the concrete adapter types).
type RoleAdapter interface {
	client.Object
	vaultv1alpha1.SyncStatusReadWriter

	// GetObject returns the underlying Kubernetes API object (e.g. *VaultRole).
	// Use this when passing to client.Status().Update() since the adapter wrapper
	// type is not registered in the runtime scheme.
	GetObject() client.Object

	// GetConnectionRef returns the name of the VaultConnection to use.
	GetConnectionRef() string

	// GetAuthPath returns the mount path of the auth method in Vault.
	GetAuthPath() string

	// GetAuthType returns the explicit auth backend family override (empty when
	// the family should be inferred from the auth path name).
	GetAuthType() vaultv1alpha1.AuthBackendType

	// GetConflictPolicy returns the conflict handling policy.
	GetConflictPolicy() vaultv1alpha1.ConflictPolicy

	// GetServiceAccountBindings returns formatted "namespace/name" strings for Vault.
	// For VaultRole: uses the role's namespace with each service account name.
	// For VaultClusterRole: uses each ServiceAccountRef's namespace and name.
	GetServiceAccountBindings() []string

	// GetPolicies returns the policy references for this role.
	GetPolicies() []vaultv1alpha1.PolicyReference

	// GetTokenTTL returns the default TTL for tokens issued by this role.
	GetTokenTTL() string

	// GetTokenMaxTTL returns the maximum TTL for tokens issued by this role.
	GetTokenMaxTTL() string

	// GetJWT returns the optional JWT role overrides (nil if not set).
	GetJWT() *vaultv1alpha1.VaultRoleJWTSpec

	// GetDeletionPolicy returns the deletion policy.
	GetDeletionPolicy() vaultv1alpha1.DeletionPolicy

	// GetVaultRoleName returns the role name in Vault.
	// For namespaced: {namespace}-{name}, for cluster: {name}.
	GetVaultRoleName() string

	// GetK8sResourceIdentifier returns the identifier for tracking ownership.
	// For namespaced: {namespace}/{name}, for cluster: {name}.
	GetK8sResourceIdentifier() string

	// IsNamespaced returns true for VaultRole, false for VaultClusterRole.
	IsNamespaced() bool

	// Role-specific status fields.
	SetVaultRoleName(name string)
	SetBoundServiceAccounts(accounts []string)
	SetResolvedPolicies(policies []string)
	GetPolicyBindings() []vaultv1alpha1.PolicyBinding
	SetPolicyBindings(bindings []vaultv1alpha1.PolicyBinding)

	// GetDriftMode returns the resource's configured drift mode (from spec).
	GetDriftMode() vaultv1alpha1.DriftMode
}

// VaultRoleAdapter adapts VaultRole to the RoleAdapter interface.
type VaultRoleAdapter struct {
	*vaultv1alpha1.VaultRole
	vaultv1alpha1.SyncStatusAccessor
}

// NewVaultRoleAdapter creates a new VaultRoleAdapter.
func NewVaultRoleAdapter(r *vaultv1alpha1.VaultRole) *VaultRoleAdapter {
	return &VaultRoleAdapter{
		VaultRole:          r,
		SyncStatusAccessor: vaultv1alpha1.NewSyncStatusAccessor(&r.Status.SyncStatus),
	}
}

func (a *VaultRoleAdapter) GetObject() client.Object { return a.VaultRole }
func (a *VaultRoleAdapter) GetConnectionRef() string { return a.Spec.ConnectionRef }
func (a *VaultRoleAdapter) GetAuthPath() string      { return a.Spec.AuthPath }
func (a *VaultRoleAdapter) GetAuthType() vaultv1alpha1.AuthBackendType {
	return a.Spec.AuthType
}
func (a *VaultRoleAdapter) GetConflictPolicy() vaultv1alpha1.ConflictPolicy {
	return a.Spec.ConflictPolicy
}

func (a *VaultRoleAdapter) GetServiceAccountBindings() []string {
	bindings := make([]string, len(a.Spec.ServiceAccounts))
	for i, sa := range a.Spec.ServiceAccounts {
		bindings[i] = a.Namespace + "/" + sa
	}
	return bindings
}

func (a *VaultRoleAdapter) GetPolicies() []vaultv1alpha1.PolicyReference { return a.Spec.Policies }
func (a *VaultRoleAdapter) GetTokenTTL() string                          { return a.Spec.TokenTTL }
func (a *VaultRoleAdapter) GetTokenMaxTTL() string                       { return a.Spec.TokenMaxTTL }
func (a *VaultRoleAdapter) GetJWT() *vaultv1alpha1.VaultRoleJWTSpec      { return a.Spec.JWT }
func (a *VaultRoleAdapter) GetDeletionPolicy() vaultv1alpha1.DeletionPolicy {
	return a.Spec.DeletionPolicy
}
func (a *VaultRoleAdapter) GetVaultRoleName() string         { return a.Namespace + "-" + a.Name }
func (a *VaultRoleAdapter) GetK8sResourceIdentifier() string { return a.Namespace + "/" + a.Name }
func (a *VaultRoleAdapter) IsNamespaced() bool               { return true }

// Role-specific status fields
func (a *VaultRoleAdapter) SetVaultRoleName(name string) { a.Status.VaultRoleName = name }
func (a *VaultRoleAdapter) SetBoundServiceAccounts(accounts []string) {
	a.Status.BoundServiceAccounts = accounts
}
func (a *VaultRoleAdapter) SetResolvedPolicies(policies []string) {
	a.Status.ResolvedPolicies = policies
}
func (a *VaultRoleAdapter) GetPolicyBindings() []vaultv1alpha1.PolicyBinding {
	return a.Status.PolicyBindings
}
func (a *VaultRoleAdapter) SetPolicyBindings(bindings []vaultv1alpha1.PolicyBinding) {
	a.Status.PolicyBindings = bindings
}
func (a *VaultRoleAdapter) GetDriftMode() vaultv1alpha1.DriftMode { return a.Spec.DriftMode }

// VaultClusterRoleAdapter adapts VaultClusterRole to the RoleAdapter interface.
type VaultClusterRoleAdapter struct {
	*vaultv1alpha1.VaultClusterRole
	vaultv1alpha1.SyncStatusAccessor
}

// NewVaultClusterRoleAdapter creates a new VaultClusterRoleAdapter.
func NewVaultClusterRoleAdapter(r *vaultv1alpha1.VaultClusterRole) *VaultClusterRoleAdapter {
	return &VaultClusterRoleAdapter{
		VaultClusterRole:   r,
		SyncStatusAccessor: vaultv1alpha1.NewSyncStatusAccessor(&r.Status.SyncStatus),
	}
}

func (a *VaultClusterRoleAdapter) GetObject() client.Object { return a.VaultClusterRole }
func (a *VaultClusterRoleAdapter) GetConnectionRef() string { return a.Spec.ConnectionRef }
func (a *VaultClusterRoleAdapter) GetAuthPath() string      { return a.Spec.AuthPath }
func (a *VaultClusterRoleAdapter) GetAuthType() vaultv1alpha1.AuthBackendType {
	return a.Spec.AuthType
}
func (a *VaultClusterRoleAdapter) GetConflictPolicy() vaultv1alpha1.ConflictPolicy {
	return a.Spec.ConflictPolicy
}

func (a *VaultClusterRoleAdapter) GetServiceAccountBindings() []string {
	bindings := make([]string, len(a.Spec.ServiceAccounts))
	for i, sa := range a.Spec.ServiceAccounts {
		bindings[i] = sa.Namespace + "/" + sa.Name
	}
	return bindings
}

func (a *VaultClusterRoleAdapter) GetPolicies() []vaultv1alpha1.PolicyReference {
	return a.Spec.Policies
}
func (a *VaultClusterRoleAdapter) GetTokenTTL() string    { return a.Spec.TokenTTL }
func (a *VaultClusterRoleAdapter) GetTokenMaxTTL() string { return a.Spec.TokenMaxTTL }
func (a *VaultClusterRoleAdapter) GetJWT() *vaultv1alpha1.VaultRoleJWTSpec {
	return a.Spec.JWT
}
func (a *VaultClusterRoleAdapter) GetDeletionPolicy() vaultv1alpha1.DeletionPolicy {
	return a.Spec.DeletionPolicy
}
func (a *VaultClusterRoleAdapter) GetVaultRoleName() string         { return a.Name }
func (a *VaultClusterRoleAdapter) GetK8sResourceIdentifier() string { return a.Name }
func (a *VaultClusterRoleAdapter) IsNamespaced() bool               { return false }

// Role-specific status fields
func (a *VaultClusterRoleAdapter) SetVaultRoleName(name string) { a.Status.VaultRoleName = name }
func (a *VaultClusterRoleAdapter) SetBoundServiceAccounts(accounts []string) {
	a.Status.BoundServiceAccounts = accounts
}
func (a *VaultClusterRoleAdapter) SetResolvedPolicies(policies []string) {
	a.Status.ResolvedPolicies = policies
}
func (a *VaultClusterRoleAdapter) GetPolicyBindings() []vaultv1alpha1.PolicyBinding {
	return a.Status.PolicyBindings
}
func (a *VaultClusterRoleAdapter) SetPolicyBindings(bindings []vaultv1alpha1.PolicyBinding) {
	a.Status.PolicyBindings = bindings
}
func (a *VaultClusterRoleAdapter) GetDriftMode() vaultv1alpha1.DriftMode { return a.Spec.DriftMode }
