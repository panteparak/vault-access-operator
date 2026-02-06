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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Phase represents the current phase of a resource
// +kubebuilder:validation:Enum=Pending;Syncing;Active;Conflict;Error;Deleting
type Phase string

const (
	PhasePending  Phase = "Pending"
	PhaseSyncing  Phase = "Syncing"
	PhaseActive   Phase = "Active"
	PhaseConflict Phase = "Conflict"
	PhaseError    Phase = "Error"
	PhaseDeleting Phase = "Deleting"
)

// ConflictPolicy defines how to handle conflicts with existing Vault resources
// +kubebuilder:validation:Enum=Fail;Adopt
type ConflictPolicy string

const (
	ConflictPolicyFail  ConflictPolicy = "Fail"
	ConflictPolicyAdopt ConflictPolicy = "Adopt"
)

// DeletionPolicy defines what happens when the K8s resource is deleted
// +kubebuilder:validation:Enum=Delete;Retain
type DeletionPolicy string

const (
	DeletionPolicyDelete DeletionPolicy = "Delete"
	DeletionPolicyRetain DeletionPolicy = "Retain"
)

// Capability represents a Vault policy capability
// +kubebuilder:validation:Enum=create;read;update;delete;list;sudo;deny
type Capability string

const (
	CapabilityCreate Capability = "create"
	CapabilityRead   Capability = "read"
	CapabilityUpdate Capability = "update"
	CapabilityDelete Capability = "delete"
	CapabilityList   Capability = "list"
	CapabilitySudo   Capability = "sudo"
	CapabilityDeny   Capability = "deny"
)

// SecretKeySelector selects a key of a Secret
type SecretKeySelector struct {
	// Name of the secret
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the secret. If not specified, uses the namespace of the referencing resource.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Key in the secret to select
	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// LocalSecretKeySelector selects a key of a Secret in the same namespace
type LocalSecretKeySelector struct {
	// Name of the secret
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Key in the secret to select
	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// PolicyRule defines a single policy rule for Vault
type PolicyRule struct {
	// Path in Vault to apply the rule to
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9/_*{}+-]+$`
	Path string `json:"path"`

	// Capabilities to grant on this path
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Capabilities []Capability `json:"capabilities"`

	// Description of this rule
	// +optional
	Description string `json:"description,omitempty"`

	// Parameters for fine-grained control
	// +optional
	Parameters *PolicyParameters `json:"parameters,omitempty"`
}

// PolicyParameters defines parameter constraints for a policy rule
type PolicyParameters struct {
	// Allowed parameter values
	// +optional
	Allowed []string `json:"allowed,omitempty"`

	// Denied parameter values
	// +optional
	Denied []string `json:"denied,omitempty"`

	// Required parameters
	// +optional
	Required []string `json:"required,omitempty"`
}

// PolicyReference defines a reference to a VaultPolicy or VaultClusterPolicy
type PolicyReference struct {
	// Kind of the policy (VaultPolicy or VaultClusterPolicy)
	// +kubebuilder:validation:Enum=VaultPolicy;VaultClusterPolicy
	// +kubebuilder:validation:Required
	Kind string `json:"kind"`

	// Name of the policy
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the policy (only for VaultPolicy, defaults to the namespace of the referencing resource)
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// ServiceAccountRef references a Kubernetes service account
type ServiceAccountRef struct {
	// Name of the service account
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the service account
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`
}

// Condition represents a condition of a resource
type Condition struct {
	// Type of condition
	// +kubebuilder:validation:Required
	Type string `json:"type"`

	// Status of the condition (True, False, Unknown)
	// +kubebuilder:validation:Required
	Status metav1.ConditionStatus `json:"status"`

	// LastTransitionTime is the last time the condition transitioned
	// +kubebuilder:validation:Required
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// Reason for the condition's last transition
	// +kubebuilder:validation:Required
	Reason string `json:"reason"`

	// Message is a human-readable explanation
	// +optional
	Message string `json:"message,omitempty"`

	// ObservedGeneration represents the generation observed by the controller
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ConditionType constants
const (
	ConditionTypeReady            = "Ready"
	ConditionTypeSynced           = "Synced"
	ConditionTypeConnectionReady  = "ConnectionReady"
	ConditionTypePoliciesResolved = "PoliciesResolved"
)

// ConditionReason constants
const (
	ReasonSucceeded          = "Succeeded"
	ReasonFailed             = "Failed"
	ReasonInProgress         = "InProgress"
	ReasonConflict           = "Conflict"
	ReasonValidationFailed   = "ValidationFailed"
	ReasonConnectionNotReady = "ConnectionNotReady"
	ReasonPolicyNotFound     = "PolicyNotFound"
)

// ToSecretReference converts LocalSecretKeySelector to a corev1.SecretKeySelector
func (s *LocalSecretKeySelector) ToSecretReference() *corev1.SecretKeySelector {
	if s == nil {
		return nil
	}
	return &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{
			Name: s.Name,
		},
		Key: s.Key,
	}
}

// ReconcileStatus contains reconciliation tracking fields.
// Embed this in CRD status structs using json:",inline" for automatic reconcileID tracking.
type ReconcileStatus struct {
	// LastReconcileID is the correlation ID of the most recent reconciliation cycle.
	// Use this to filter operator logs: kubectl logs ... | jq 'select(.reconcileID == "<id>")'
	// +optional
	LastReconcileID string `json:"lastReconcileID,omitempty"`
}

// SyncStatus contains common reconciliation tracking fields for synced Vault resources.
// Embed with json:",inline" in CRD status structs alongside ReconcileStatus.
type SyncStatus struct {
	// Phase represents the current phase of the resource
	// +optional
	Phase Phase `json:"phase,omitempty"`

	// Managed indicates whether this resource is managed by the operator
	// +optional
	Managed bool `json:"managed,omitempty"`

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

// Finalizer name for the operator
const (
	FinalizerName = "vault.platform.io/finalizer"
)
