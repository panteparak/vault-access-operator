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

// VaultPolicySpec defines the desired state of VaultPolicy.
type VaultPolicySpec struct {
	// ConnectionRef is the name of the VaultConnection to use
	// +kubebuilder:validation:Required
	ConnectionRef string `json:"connectionRef"`

	// ConflictPolicy defines how to handle conflicts with existing policies
	// +kubebuilder:default=Fail
	// +optional
	ConflictPolicy ConflictPolicy `json:"conflictPolicy,omitempty"`

	// Rules defines the policy rules
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Rules []PolicyRule `json:"rules"`

	// DeletionPolicy defines what happens when the resource is deleted
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// EnforceNamespaceBoundary ensures all paths contain {{namespace}} variable
	// +kubebuilder:default=false
	// +optional
	EnforceNamespaceBoundary *bool `json:"enforceNamespaceBoundary,omitempty"`
}

// VaultPolicyStatus defines the observed state of VaultPolicy.
type VaultPolicyStatus struct {
	ReconcileStatus `json:",inline"`
	SyncStatus      `json:",inline"`

	// VaultName is the name of the policy in Vault (namespace-name format)
	// +optional
	VaultName string `json:"vaultName,omitempty"`

	// RulesCount is the number of rules in the policy
	// +optional
	RulesCount int `json:"rulesCount,omitempty"`

	// LastAppliedHash is the hash of the last applied spec
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`
}

// IsEnforceNamespaceBoundary returns whether namespace boundary enforcement is enabled
func (s *VaultPolicySpec) IsEnforceNamespaceBoundary() bool {
	if s.EnforceNamespaceBoundary == nil {
		return false // default is false
	}
	return *s.EnforceNamespaceBoundary
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vp
// +kubebuilder:printcolumn:name="Vault Name",type=string,JSONPath=`.status.vaultName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Rules",type=integer,JSONPath=`.status.rulesCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VaultPolicy is the Schema for the vaultpolicies API.
type VaultPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultPolicySpec   `json:"spec,omitempty"`
	Status VaultPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultPolicyList contains a list of VaultPolicy.
type VaultPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultPolicy `json:"items"`
}

// SetLastReconcileID implements ReconcileTrackable.
func (p *VaultPolicy) SetLastReconcileID(id string) { p.Status.LastReconcileID = id }

func init() {
	SchemeBuilder.Register(&VaultPolicy{}, &VaultPolicyList{})
}
