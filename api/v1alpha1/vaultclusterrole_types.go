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

package v1alpha1 //nolint:dupl // VaultClusterRole and VaultRole are intentionally parallel (cluster-scoped vs namespaced)

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultClusterRoleSpec defines the desired state of VaultClusterRole.
type VaultClusterRoleSpec struct {
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

	// ServiceAccounts defines which service accounts can use this role
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	ServiceAccounts []ServiceAccountRef `json:"serviceAccounts"`

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
}

// VaultClusterRoleStatus defines the observed state of VaultClusterRole.
type VaultClusterRoleStatus struct {
	ReconcileStatus `json:",inline"`
	SyncStatus      `json:",inline"`

	// VaultRoleName is the name of the role in Vault
	// +optional
	VaultRoleName string `json:"vaultRoleName,omitempty"`

	// BoundServiceAccounts lists the service accounts bound to this role
	// +optional
	BoundServiceAccounts []string `json:"boundServiceAccounts,omitempty"`

	// ResolvedPolicies lists the resolved Vault policy names
	// +optional
	ResolvedPolicies []string `json:"resolvedPolicies,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=vcr
// +kubebuilder:printcolumn:name="Vault Role",type=string,JSONPath=`.status.vaultRoleName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Policies",type=string,JSONPath=`.status.resolvedPolicies`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VaultClusterRole is the Schema for the vaultclusterroles API.
type VaultClusterRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultClusterRoleSpec   `json:"spec,omitempty"`
	Status VaultClusterRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultClusterRoleList contains a list of VaultClusterRole.
type VaultClusterRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultClusterRole `json:"items"`
}

// SetLastReconcileID implements ReconcileTrackable.
func (r *VaultClusterRole) SetLastReconcileID(id string) { r.Status.LastReconcileID = id }

func init() {
	SchemeBuilder.Register(&VaultClusterRole{}, &VaultClusterRoleList{})
}
