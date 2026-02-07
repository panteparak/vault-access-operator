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

// VaultClusterPolicySpec defines the desired state of VaultClusterPolicy.
type VaultClusterPolicySpec struct {
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

	// DriftMode overrides the VaultConnection's default drift mode for this policy.
	// Values: ignore (skip detection), detect (report only), correct (auto-fix).
	// If not specified, uses the VaultConnection's default (which defaults to "detect").
	// +optional
	DriftMode DriftMode `json:"driftMode,omitempty"`
}

// VaultClusterPolicyStatus defines the observed state of VaultClusterPolicy.
type VaultClusterPolicyStatus struct {
	ReconcileStatus `json:",inline"`
	SyncStatus      `json:",inline"`

	// VaultName is the name of the policy in Vault
	// +optional
	VaultName string `json:"vaultName,omitempty"`

	// RulesCount is the number of rules in the policy
	// +optional
	RulesCount int `json:"rulesCount,omitempty"`

	// LastAppliedHash is the hash of the last applied spec
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// Binding contains the explicit reference to the Vault resource.
	// Acts like a foreign key to the Vault policy.
	// +optional
	Binding VaultResourceBinding `json:"binding,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=vcp
// +kubebuilder:printcolumn:name="Vault Name",type=string,JSONPath=`.status.vaultName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Rules",type=integer,JSONPath=`.status.rulesCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VaultClusterPolicy is the Schema for the vaultclusterpolicies API.
type VaultClusterPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultClusterPolicySpec   `json:"spec,omitempty"`
	Status VaultClusterPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultClusterPolicyList contains a list of VaultClusterPolicy.
type VaultClusterPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultClusterPolicy `json:"items"`
}

// SetLastReconcileID implements ReconcileTrackable.
func (p *VaultClusterPolicy) SetLastReconcileID(id string) { p.Status.LastReconcileID = id }

func init() {
	SchemeBuilder.Register(&VaultClusterPolicy{}, &VaultClusterPolicyList{})
}
