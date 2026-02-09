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

package v1alpha1 //nolint:dupl // VaultRole and VaultClusterRole are intentionally parallel (namespaced vs cluster-scoped)

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultRoleSpec defines the desired state of VaultRole.
type VaultRoleSpec struct {
	// ConnectionRef is the name of the VaultConnection to use
	// +kubebuilder:validation:Required
	ConnectionRef string `json:"connectionRef"`

	// AuthPath is the mount path of the Kubernetes auth method in Vault
	// +optional
	AuthPath string `json:"authPath,omitempty"`

	// ConflictPolicy defines how to handle conflicts with existing roles
	// +kubebuilder:default=Fail
	// +optional
	ConflictPolicy ConflictPolicy `json:"conflictPolicy,omitempty"`

	// ServiceAccounts defines which service accounts can use this role (names only, in same namespace)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	ServiceAccounts []string `json:"serviceAccounts"`

	// Policies defines which policies to attach to this role
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Policies []PolicyReference `json:"policies"`

	// TokenTTL is the default TTL for tokens issued by this role
	// +optional
	TokenTTL string `json:"tokenTTL,omitempty"`

	// TokenMaxTTL is the maximum TTL for tokens issued by this role
	// +optional
	TokenMaxTTL string `json:"tokenMaxTTL,omitempty"`

	// DeletionPolicy defines what happens when the resource is deleted
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// DriftMode overrides the VaultConnection's default drift mode for this role.
	// Values: ignore (skip detection), detect (report only), correct (auto-fix).
	// If not specified, uses the VaultConnection's default (which defaults to "detect").
	// +optional
	DriftMode DriftMode `json:"driftMode,omitempty"`
}

// VaultRoleStatus defines the observed state of VaultRole.
type VaultRoleStatus struct {
	ReconcileStatus `json:",inline"`
	SyncStatus      `json:",inline"`

	// VaultRoleName is the name of the role in Vault (namespace-name format)
	// +optional
	VaultRoleName string `json:"vaultRoleName,omitempty"`

	// BoundServiceAccounts lists the service accounts bound to this role
	// +optional
	BoundServiceAccounts []string `json:"boundServiceAccounts,omitempty"`

	// ResolvedPolicies lists the resolved Vault policy names
	// +optional
	ResolvedPolicies []string `json:"resolvedPolicies,omitempty"`

	// LastAppliedHash is the hash of the last applied spec
	// Used to distinguish between spec changes and external Vault drift
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// Binding contains the explicit reference to the Vault role.
	// Acts like a foreign key to the Vault Kubernetes auth role.
	// +optional
	Binding VaultResourceBinding `json:"binding,omitempty"`

	// PolicyBindings tracks the relationship between this role and its referenced policies.
	// Each entry shows the K8s reference and the corresponding Vault policy path.
	// +optional
	PolicyBindings []PolicyBinding `json:"policyBindings,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vr
// +kubebuilder:printcolumn:name="Vault Role",type=string,JSONPath=`.status.vaultRoleName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Policies",type=string,JSONPath=`.status.resolvedPolicies`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VaultRole is the Schema for the vaultroles API.
type VaultRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultRoleSpec   `json:"spec,omitempty"`
	Status VaultRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultRoleList contains a list of VaultRole.
type VaultRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultRole `json:"items"`
}

// SetLastReconcileID implements ReconcileTrackable.
func (r *VaultRole) SetLastReconcileID(id string) { r.Status.LastReconcileID = id }

func init() {
	SchemeBuilder.Register(&VaultRole{}, &VaultRoleList{})
}
