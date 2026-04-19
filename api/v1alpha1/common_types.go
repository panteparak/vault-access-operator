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

// DriftMode defines how drift detection and correction is handled
// +kubebuilder:validation:Enum=ignore;detect;correct
type DriftMode string

const (
	// DriftModeIgnore skips drift detection (performance optimization)
	DriftModeIgnore DriftMode = "ignore"
	// DriftModeDetect detects and reports drift but does NOT auto-correct
	DriftModeDetect DriftMode = "detect"
	// DriftModeCorrect detects AND auto-corrects drift
	DriftModeCorrect DriftMode = "correct"
)

// DefaultDriftMode is the default drift mode when not specified
const DefaultDriftMode = DriftModeDetect

// RenewalStrategy defines how Vault tokens are refreshed when approaching expiration
// +kubebuilder:validation:Enum=renew;reauth
type RenewalStrategy string

const (
	// RenewalStrategyRenew proactively renews Vault tokens before expiration.
	// Falls back to re-authentication if renewal fails. This is the default
	// and recommended strategy for most use cases.
	RenewalStrategyRenew RenewalStrategy = "renew"

	// RenewalStrategyReauth always re-authenticates with fresh credentials
	// instead of renewing existing tokens. More secure but higher Vault API load.
	// Use this for security-critical workloads that require fresh tokens.
	RenewalStrategyReauth RenewalStrategy = "reauth"
)

// DefaultRenewalStrategy is the default renewal strategy when not specified
const DefaultRenewalStrategy = RenewalStrategyRenew

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
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9/_*.{}+-]+$`
	Path string `json:"path"`

	// Capabilities to grant on this path
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Capabilities []Capability `json:"capabilities"`

	// Description of this rule
	// +optional
	// +kubebuilder:validation:MaxLength=256
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

// VaultRoleJWTSpec contains optional overrides for JWT auth roles.
// When a VaultRole (or VaultClusterRole) targets an auth/jwt mount via AuthPath,
// the operator derives sensible defaults from ServiceAccounts and the referenced
// VaultConnection. Fields in this struct let users override those defaults.
type VaultRoleJWTSpec struct {
	// UserClaim is the JWT claim to read as the identity. Defaults to "sub".
	// +optional
	UserClaim string `json:"userClaim,omitempty"`

	// BoundAudiences restricts which audiences the token must contain.
	// Defaults to the VaultConnection's spec.auth.jwt.audiences when the
	// connection uses JWT auth, otherwise to
	// ["https://kubernetes.default.svc.cluster.local"].
	// +optional
	BoundAudiences []string `json:"boundAudiences,omitempty"`

	// BoundSubject restricts the token's sub claim to an exact match.
	// Defaults to "system:serviceaccount:<namespace>:<serviceAccounts[0]>".
	// Mutually exclusive with BoundClaims.
	// +optional
	BoundSubject string `json:"boundSubject,omitempty"`

	// BoundClaims is an advanced match — arbitrary claim to value(s).
	// When set, BoundSubject is ignored.
	// +optional
	BoundClaims map[string]string `json:"boundClaims,omitempty"`

	// RoleType is the Vault JWT role type. Only "jwt" is supported.
	// Defaults to "jwt".
	// +kubebuilder:validation:Enum=jwt
	// +optional
	RoleType string `json:"roleType,omitempty"`
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

// VaultResourceBinding represents the explicit binding between a K8s resource
// and its corresponding Vault resource. Acts like a foreign key reference.
type VaultResourceBinding struct {
	// VaultPath is the full API path to the Vault resource
	// Example: "sys/policies/acl/prod-my-policy" or "auth/kubernetes/role/prod-my-role"
	// +optional
	VaultPath string `json:"vaultPath,omitempty"`

	// VaultResourceName is the name of the resource in Vault
	// Example: "prod-my-policy" or "prod-my-role"
	// +optional
	VaultResourceName string `json:"vaultResourceName,omitempty"`

	// AuthMount is the auth mount path (only for roles)
	// Example: "kubernetes" or "kubernetes-prod"
	// +optional
	AuthMount string `json:"authMount,omitempty"`

	// BoundAt is when the binding was established
	// +optional
	BoundAt *metav1.Time `json:"boundAt,omitempty"`

	// BindingVerified indicates the binding was verified against Vault
	// +optional
	BindingVerified bool `json:"bindingVerified,omitempty"`

	// LastVerifiedAt is when the binding was last verified
	// +optional
	LastVerifiedAt *metav1.Time `json:"lastVerifiedAt,omitempty"`
}

// PolicyBinding represents the binding between a role and its referenced policies
type PolicyBinding struct {
	// K8sRef is the K8s resource reference (kind/namespace/name)
	// Example: "VaultPolicy/prod/app-read" or "VaultClusterPolicy/admin-base"
	// +optional
	K8sRef string `json:"k8sRef,omitempty"`

	// VaultPolicyPath is the full Vault path to the policy
	// Example: "sys/policies/acl/prod-app-read"
	// +optional
	VaultPolicyPath string `json:"vaultPolicyPath,omitempty"`

	// Resolved indicates if the policy reference was successfully resolved
	// +optional
	Resolved bool `json:"resolved,omitempty"`
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
	ConditionTypeDependencyReady  = "DependencyReady"
	ConditionTypeDrifted          = "Drifted"
	ConditionTypeDeleting         = "Deleting"
	// ConditionTypeDryRun is True when the resource carries the
	// `vault.platform.io/dry-run=true` annotation and the operator
	// skipped one or more Vault-side writes during reconcile. Message
	// surfaces the would-be operation. IMPROVEMENTS Missing Features §I.
	ConditionTypeDryRun = "DryRun"
)

// ConditionReason constants
const (
	ReasonSucceeded             = "Succeeded"
	ReasonFailed                = "Failed"
	ReasonInProgress            = "InProgress"
	ReasonConflict              = "Conflict"
	ReasonValidationFailed      = "ValidationFailed"
	ReasonConnectionNotReady    = "ConnectionNotReady"
	ReasonPolicyNotFound        = "PolicyNotFound"
	ReasonDependencyNotReady    = "DependencyNotReady"
	ReasonDependencyReady       = "DependencyReady"
	ReasonDriftDetected         = "DriftDetected"
	ReasonDriftCorrected        = "DriftCorrected"
	ReasonNoDrift               = "NoDrift"
	ReasonDeletionBlocked       = "DeletionBlocked"
	ReasonDeletionInProgress    = "DeletionInProgress"
	ReasonChildrenExist         = "ChildrenExist"
	ReasonObservedGenStale      = "ObservedGenerationStale"
	ReasonPolicyNotInVault      = "PolicyNotInVault"
	ReasonImmutableFieldChanged = "ImmutableFieldChanged"

	// ReasonResourceNotFound is emitted when a referenced K8s resource
	// (Secret, ServiceAccount, etc.) can't be found. Distinct from
	// ReasonPolicyNotFound, which is specific to Vault policies.
	// IMPROVEMENTS §29.
	ReasonResourceNotFound = "ResourceNotFound"

	// ReasonNetworkError is emitted when transport-layer errors (DNS, TLS,
	// TCP, unreachable) prevent reaching Vault. Distinct from
	// ReasonFailed (generic) and ReasonConnectionNotReady (dependency
	// resolution). IMPROVEMENTS §29.
	ReasonNetworkError = "NetworkError"

	// ReasonDryRunSkipped is the condition reason for ConditionTypeDryRun
	// when the operator would have written/deleted but skipped because the
	// resource carries `vault.platform.io/dry-run=true`.
	// IMPROVEMENTS Missing Features §I.
	ReasonDryRunSkipped = "DryRunSkipped"

	// ReasonVaultSealed is set on Ready=False / Healthy=False when Vault
	// is reachable but in a sealed state. Distinct from ReasonNetworkError
	// (transport failure) and ReasonFailed (generic). Operators see this
	// reason when an external action (auto-unseal trigger, manual unseal)
	// is needed to recover the connection. IMPROVEMENTS Missing Features §C.
	ReasonVaultSealed = "VaultSealed"

	// ReasonVaultNotInitialized is the analog of ReasonVaultSealed for
	// the rarer case where Vault is reachable but `vault operator init`
	// hasn't run yet. Same dashboard treatment, different remediation.
	ReasonVaultNotInitialized = "VaultNotInitialized"
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

	// DriftDetected indicates whether the Vault resource differs from the desired state
	// +optional
	DriftDetected bool `json:"driftDetected,omitempty"`

	// LastDriftCheckAt is the time of the last drift detection check
	// +optional
	LastDriftCheckAt *metav1.Time `json:"lastDriftCheckAt,omitempty"`

	// EffectiveDriftMode is the resolved drift mode after considering resource and connection defaults
	// +optional
	EffectiveDriftMode DriftMode `json:"effectiveDriftMode,omitempty"`

	// DriftSummary provides a human-readable description of detected drift
	// Example: "policy content differs" or "fields differ: policies, bound_service_account_names"
	// +optional
	DriftSummary string `json:"driftSummary,omitempty"`

	// DriftCorrectedAt is the time when drift was last corrected
	// +optional
	DriftCorrectedAt *metav1.Time `json:"driftCorrectedAt,omitempty"`

	// DeletionStartedAt is the time when deletion was first attempted.
	// Used for tracking stuck finalizers and deletion timeouts.
	// +optional
	DeletionStartedAt *metav1.Time `json:"deletionStartedAt,omitempty"`

	// LastAppliedHash is the hash of the last applied spec.
	// Used to distinguish between spec changes and external Vault drift.
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// Binding contains the explicit reference to the Vault resource.
	// Acts like a foreign key to the Vault resource.
	// +optional
	Binding VaultResourceBinding `json:"binding,omitempty"`
}

// Finalizer name for the operator
const (
	FinalizerName = "vault.platform.io/finalizer"
)

// Annotation keys for adoption and safety controls
const (
	// AnnotationAdopt marks a CR for adoption of an existing Vault resource
	// Value should be "true" to enable adoption
	AnnotationAdopt = "vault.platform.io/adopt"

	// AnnotationAllowDestructive permits destructive drift corrections
	// Value should be "true" to allow overwriting existing Vault resources
	AnnotationAllowDestructive = "vault.platform.io/allow-destructive"

	// AnnotationDiscovered indicates resource was auto-generated from discovery
	// Value is the timestamp when the resource was discovered
	AnnotationDiscovered = "vault.platform.io/discovered-at"

	// AnnotationDiscoveredFrom names the VaultConnection that surfaced the resource.
	// Set by discovery auto-create alongside AnnotationDiscovered; informational only.
	AnnotationDiscoveredFrom = "vault.platform.io/discovered-from"

	// AnnotationDiscoveryPending marks an auto-created adoption CR whose spec
	// still contains placeholder values. Operators MUST skip writes to Vault
	// while this annotation is set to AnnotationValueTrue — otherwise the
	// placeholder would overwrite the adopted Vault resource. Users clear the
	// annotation after replacing placeholders with the real spec.
	AnnotationDiscoveryPending = "vault.platform.io/discovery-pending"

	// AnnotationReconcileNow, when set to any value, forces an immediate
	// reconcile of the annotated CR even if spec.generation didn't change.
	// Useful after a Vault-side manual fix to pull the operator back in sync
	// without bumping the spec.
	//
	// The handler clears this annotation at the end of a successful sync so
	// the trigger is single-shot — without that clearing step, the watcher
	// would re-enqueue on every reconcile and loop forever.
	//
	// IMPROVEMENTS Missing Features §H.
	AnnotationReconcileNow = "vault.platform.io/reconcile-now"

	// AnnotationRestoreManagedMarkers, when set to AnnotationValueTrue on a
	// VaultConnection, triggers a one-shot mass re-adoption: the connection
	// reconciler lists every dependent CR (VaultPolicy, VaultClusterPolicy,
	// VaultRole, VaultClusterRole) referencing this connection and re-writes
	// the managed-marker entry in Vault's KV store for each.
	//
	// Use case: someone wiped `secret/data/vault-access-operator/managed/`
	// (manual cleanup, accidental policy delete, KV mount restoration from
	// snapshot). Without the markers, every dependent CR is conflict-blocked
	// because the operator can't tell that it owns those Vault resources.
	// Setting this annotation recovers the cluster in one operation instead
	// of N annotations on N CRs.
	//
	// Auto-clears after a successful pass — single-shot trigger. Failures
	// during the pass are logged with per-resource detail; the operator
	// re-tries on the next reconcile until the user clears the annotation.
	//
	// IMPROVEMENTS Missing Features §G.
	AnnotationRestoreManagedMarkers = "vault.platform.io/restore-managed-markers"

	// AnnotationDryRun, when set to AnnotationValueTrue, makes the operator
	// SKIP all Vault-side writes (WriteToVault, MarkManaged, DeleteFromVault)
	// for the annotated resource and surface what it WOULD have written via
	// the `DryRun` status condition.
	//
	// Use case: preview a policy/role change ("what HCL would the operator
	// push?") or preview a delete ("what would happen if I removed this CR?")
	// without committing the change to Vault. Drift detection still runs so
	// the user can compare expected vs. actual.
	//
	// Persistent — does NOT auto-clear. Users remove the annotation when
	// ready to apply for real. Combine with `DriftMode: correct` to preview
	// what a drift-correction WOULD overwrite without overwriting it.
	//
	// IMPROVEMENTS Missing Features §I.
	AnnotationDryRun = "vault.platform.io/dry-run"

	// AnnotationValueTrue is the canonical value for boolean annotation flags
	AnnotationValueTrue = "true"

	// DiscoveryPlaceholderValue is the sentinel string the discovery
	// auto-create flow injects into VaultRole.Spec.ServiceAccounts and
	// VaultRole.Spec.Policies (and their cluster equivalents) so the
	// CR satisfies MinItems=1 schema validation while the user adopts
	// the resource. The discovery-pending annotation tells the
	// reconciler to skip Vault writes; the webhook ALSO refuses to
	// remove discovery-pending while this placeholder remains, so a
	// user can't accidentally write the placeholder to Vault by
	// clearing the annotation in isolation.
	//
	// Lifted from features/discovery/controller into the API package so
	// the role/cluster-role webhooks can reference the same string
	// without taking a controller-package dependency.
	DiscoveryPlaceholderValue = "discovery-placeholder-replace-me"
)
