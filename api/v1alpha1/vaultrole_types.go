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
}

// VaultRoleStatus defines the observed state of VaultRole.
type VaultRoleStatus struct {
	// Phase represents the current phase of the role
	// +optional
	Phase Phase `json:"phase,omitempty"`

	// VaultRoleName is the name of the role in Vault (namespace-name format)
	// +optional
	VaultRoleName string `json:"vaultRoleName,omitempty"`

	// Managed indicates whether this role is managed by the operator
	// +optional
	Managed bool `json:"managed,omitempty"`

	// BoundServiceAccounts lists the service accounts bound to this role
	// +optional
	BoundServiceAccounts []string `json:"boundServiceAccounts,omitempty"`

	// ResolvedPolicies lists the resolved Vault policy names
	// +optional
	ResolvedPolicies []string `json:"resolvedPolicies,omitempty"`

	// LastSyncedAt is the time of the last successful sync
	// +optional
	LastSyncedAt *metav1.Time `json:"lastSyncedAt,omitempty"`

	// LastAttemptAt is the time of the last sync attempt
	// +optional
	LastAttemptAt *metav1.Time `json:"lastAttemptAt,omitempty"`

	// RetryCount is the number of retry attempts
	// +optional
	RetryCount int `json:"retryCount,omitempty"`

	// NextRetryAt is the time of the next retry attempt
	// +optional
	NextRetryAt *metav1.Time `json:"nextRetryAt,omitempty"`

	// Message provides additional information about the current state
	// +optional
	Message string `json:"message,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`
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

func init() {
	SchemeBuilder.Register(&VaultRole{}, &VaultRoleList{})
}
