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

// VaultKVSecretSpec defines the desired state of VaultKVSecret.
//
// A VaultKVSecret pre-creates ("seeds") a KV v2 secret path so consumers such
// as External Secrets Operator (ESO) don't fail when the source path is missing
// on a fresh deployment. The operator only ever CREATES the path when absent —
// it never overwrites or reads the values stored there, so real data written
// later by ESO or a human is never clobbered.
type VaultKVSecretSpec struct {
	// ConnectionRef is the name of the VaultConnection to use.
	// +kubebuilder:validation:Required
	ConnectionRef string `json:"connectionRef"`

	// Path is the full KV v2 data path to seed, e.g.
	// "secret/data/apps/myapp/config". It MUST contain a "/data/" segment
	// (the KV v2 data API) and is immutable after creation — changing it would
	// orphan the previously-seeded secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="path is immutable"
	// +kubebuilder:validation:XValidation:rule="self.matches('^[^/]+/data/.+')",message="path must be a KV v2 data path containing a '/data/' segment, e.g. secret/data/apps/myapp"
	Path string `json:"path"`

	// Data is the initial key/value content written when the path is absent.
	// Values are typically empty-string placeholders so ESO references that
	// target a specific property (remoteRef.property) resolve. Defaults to an
	// empty map ({}), which is sufficient for whole-secret (dataFrom) reads.
	//
	// The operator only writes Data when the path does not already exist; it
	// NEVER overwrites an existing secret, so a non-empty real secret written
	// later is preserved.
	// +optional
	Data map[string]string `json:"data,omitempty"`

	// DeletionPolicy defines what happens to the seeded secret when this
	// resource is deleted. "Delete" (default) removes the seeded secret only if
	// it is still operator-owned and unmodified since seeding (delete-if-untouched);
	// a secret that has been written to since seeding is always retained.
	// "Retain" never deletes the seeded secret.
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// VaultKVSecretStatus defines the observed state of VaultKVSecret.
type VaultKVSecretStatus struct {
	ReconcileStatus `json:",inline"`
	SyncStatus      `json:",inline"`

	// VaultPath is the resolved KV v2 data path that was seeded.
	// +optional
	VaultPath string `json:"vaultPath,omitempty"`

	// Seeded indicates the operator created this path (true) versus the path
	// already existing when first reconciled (false). Only an operator-seeded
	// path is eligible for delete-if-untouched cleanup.
	// +optional
	Seeded bool `json:"seeded,omitempty"`

	// SeededVersion is the KV v2 version the operator created. It is the
	// baseline for the delete-if-untouched check: on deletion, if the current
	// version differs, the secret has been written to since seeding and is
	// retained. Zero when the path pre-existed (not seeded by the operator).
	// +optional
	SeededVersion int `json:"seededVersion,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vks
// +kubebuilder:printcolumn:name="Path",type=string,JSONPath=`.status.vaultPath`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Seeded",type=boolean,JSONPath=`.status.seeded`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VaultKVSecret is the Schema for the vaultkvsecrets API.
type VaultKVSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultKVSecretSpec   `json:"spec,omitempty"`
	Status VaultKVSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultKVSecretList contains a list of VaultKVSecret.
type VaultKVSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultKVSecret `json:"items"`
}

// SetLastReconcileID implements base.ReconcileTrackable.
func (k *VaultKVSecret) SetLastReconcileID(id string) { k.Status.LastReconcileID = id }

func init() {
	SchemeBuilder.Register(&VaultKVSecret{}, &VaultKVSecretList{})
}
