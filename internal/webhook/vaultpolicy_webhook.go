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

package webhook

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/shared/markers"
)

// log is for logging in this package.
var vaultpolicylog = logf.Log.WithName("vaultpolicy-webhook")

// rejectAdoptIntentWithoutMarkers rejects a create/update that requests
// adoption/ownership semantics (ConflictPolicy: Adopt or the adopt annotation)
// while managed-marker tracking is disabled operator-wide — that intent cannot
// be honored without markers, so surfacing it at admission is clearer than a
// silent no-op at reconcile. No-op when markers are enabled or no adopt intent
// is present. Plain/defaulted ConflictPolicy: Fail is intentionally allowed.
func rejectAdoptIntentWithoutMarkers(annotations map[string]string, cp vaultv1alpha1.ConflictPolicy) error {
	if markers.Enabled() {
		return nil
	}
	if annotations[vaultv1alpha1.AnnotationAdopt] == vaultv1alpha1.AnnotationValueTrue ||
		cp == vaultv1alpha1.ConflictPolicyAdopt {
		return fmt.Errorf(
			"conflictPolicy: Adopt / %s=%s requires managed-marker tracking, which is disabled; "+
				"enable --managed-markers on the operator or remove the adoption request",
			vaultv1alpha1.AnnotationAdopt, vaultv1alpha1.AnnotationValueTrue)
	}
	return nil
}

// validCapabilities defines the set of valid Vault policy capabilities
var validCapabilities = map[vaultv1alpha1.Capability]bool{
	vaultv1alpha1.CapabilityCreate: true,
	vaultv1alpha1.CapabilityRead:   true,
	vaultv1alpha1.CapabilityUpdate: true,
	vaultv1alpha1.CapabilityDelete: true,
	vaultv1alpha1.CapabilityList:   true,
	vaultv1alpha1.CapabilitySudo:   true,
	vaultv1alpha1.CapabilityDeny:   true,
}

// pathPattern defines valid characters for Vault paths
var pathPattern = regexp.MustCompile(`^[a-zA-Z0-9/_*.{}\-+]+$`)

// namespaceVarPattern matches the {{namespace}} variable in paths
const namespaceVar = "{{namespace}}"

// VaultPolicyValidator implements admission.Validator for VaultPolicy
type VaultPolicyValidator struct {
	client client.Client
}

// VaultClusterPolicyValidator implements admission.Validator for VaultClusterPolicy
type VaultClusterPolicyValidator struct {
	client client.Client
}

// Ensure interfaces are implemented
var _ admission.Validator[*vaultv1alpha1.VaultPolicy] = &VaultPolicyValidator{}
var _ admission.Validator[*vaultv1alpha1.VaultClusterPolicy] = &VaultClusterPolicyValidator{}

// +kubebuilder:webhook:path=/validate-vault-platform-io-v1alpha1-vaultpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=vault.platform.io,resources=vaultpolicies,verbs=create;update,versions=v1alpha1,name=vvaultpolicy.kb.io,admissionReviewVersions=v1

// SetupVaultPolicyWebhookWithManager sets up the VaultPolicy webhook with the manager
func SetupVaultPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &vaultv1alpha1.VaultPolicy{}).
		WithValidator(&VaultPolicyValidator{client: mgr.GetClient()}).
		Complete()
}

// ValidateCreate implements admission.Validator
func (v *VaultPolicyValidator) ValidateCreate(ctx context.Context, policy *vaultv1alpha1.VaultPolicy) (admission.Warnings, error) {
	vaultpolicylog.Info("validating VaultPolicy create", "name", policy.Name, "namespace", policy.Namespace)

	if err := rejectAdoptIntentWithoutMarkers(policy.GetAnnotations(), policy.Spec.ConflictPolicy); err != nil {
		return nil, err
	}

	// No naming-collision checks (ADR 0010): the fixed 4-segment shape
	// vao.{identity}.{namespace}.{name} is injective — the CR name is the
	// last segment and the namespace segment is dot-free (cluster-scoped
	// CRs use the reserved "_", an invalid namespace label), so no two
	// distinct CRs can derive the same Vault name. The pre-0010 checks
	// guarded the ambiguous "{namespace}-{name}" dash join.

	warnings, err := v.validateVaultPolicy(policy)
	if err != nil {
		return warnings, err
	}
	// IMPROVEMENTS §36: warn if the referenced VaultConnection doesn't exist yet.
	warnings = append(warnings, checkConnectionRefExists(ctx, v.client, policy.Spec.ConnectionRef)...)
	return warnings, nil
}

// ValidateUpdate implements admission.Validator
func (v *VaultPolicyValidator) ValidateUpdate(ctx context.Context, oldPolicy, policy *vaultv1alpha1.VaultPolicy) (admission.Warnings, error) {
	vaultpolicylog.Info("validating VaultPolicy update", "name", policy.Name, "namespace", policy.Namespace)

	// connectionRef may only change when both connections point at the same
	// Vault instance (spec.address). Different addresses would move the policy
	// to a different Vault and silently orphan the original.
	if oldPolicy.Spec.ConnectionRef != policy.Spec.ConnectionRef {
		if err := v.checkConnectionRefSameAddress(ctx, oldPolicy.Spec.ConnectionRef, policy.Spec.ConnectionRef); err != nil {
			return nil, err
		}
	}

	return v.validateVaultPolicy(policy)
}

// ValidateDelete implements admission.Validator
func (v *VaultPolicyValidator) ValidateDelete(ctx context.Context, policy *vaultv1alpha1.VaultPolicy) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validateVaultPolicy validates a VaultPolicy resource
func (v *VaultPolicyValidator) validateVaultPolicy(policy *vaultv1alpha1.VaultPolicy) (admission.Warnings, error) {
	allErrors := make([]string, 0, len(policy.Spec.Rules))
	warnings := make(admission.Warnings, 0, len(policy.Spec.Rules))

	// Validate rules
	for i, rule := range policy.Spec.Rules {
		ruleErrors, ruleWarnings := validatePolicyRule(rule, i, policy.Spec.IsEnforceNamespaceBoundary())
		allErrors = append(allErrors, ruleErrors...)
		warnings = append(warnings, ruleWarnings...)
	}

	if len(allErrors) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(allErrors, "; "))
	}

	return warnings, nil
}

// +kubebuilder:webhook:path=/validate-vault-platform-io-v1alpha1-vaultclusterpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=vault.platform.io,resources=vaultclusterpolicies,verbs=create;update,versions=v1alpha1,name=vvaultclusterpolicy.kb.io,admissionReviewVersions=v1

// SetupVaultClusterPolicyWebhookWithManager sets up the VaultClusterPolicy webhook with the manager
func SetupVaultClusterPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &vaultv1alpha1.VaultClusterPolicy{}).
		WithValidator(&VaultClusterPolicyValidator{client: mgr.GetClient()}).
		Complete()
}

// ValidateCreate implements admission.Validator
func (v *VaultClusterPolicyValidator) ValidateCreate(ctx context.Context, policy *vaultv1alpha1.VaultClusterPolicy) (admission.Warnings, error) {
	vaultpolicylog.Info("validating VaultClusterPolicy create", "name", policy.Name)

	if err := rejectAdoptIntentWithoutMarkers(policy.GetAnnotations(), policy.Spec.ConflictPolicy); err != nil {
		return nil, err
	}

	// No naming-collision check against VaultPolicy (ADR 0010): the "_"
	// namespace segment of cluster-scoped names cannot equal a real
	// namespace, so cross-scope collisions are structurally impossible.

	warnings, err := v.validateVaultClusterPolicy(policy)
	if err != nil {
		return warnings, err
	}
	// IMPROVEMENTS §36.
	warnings = append(warnings, checkConnectionRefExists(ctx, v.client, policy.Spec.ConnectionRef)...)
	return warnings, nil
}

// ValidateUpdate implements admission.Validator
func (v *VaultClusterPolicyValidator) ValidateUpdate(ctx context.Context, oldPolicy, policy *vaultv1alpha1.VaultClusterPolicy) (admission.Warnings, error) {
	vaultpolicylog.Info("validating VaultClusterPolicy update", "name", policy.Name)

	// connectionRef may only change when both connections point at the same
	// Vault instance (spec.address). See VaultPolicy ValidateUpdate for rationale.
	if oldPolicy.Spec.ConnectionRef != policy.Spec.ConnectionRef {
		if err := checkConnectionRefSameAddress(ctx, v.client, oldPolicy.Spec.ConnectionRef, policy.Spec.ConnectionRef); err != nil {
			return nil, err
		}
	}

	return v.validateVaultClusterPolicy(policy)
}

// ValidateDelete implements admission.Validator
func (v *VaultClusterPolicyValidator) ValidateDelete(ctx context.Context, policy *vaultv1alpha1.VaultClusterPolicy) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validateVaultClusterPolicy validates a VaultClusterPolicy resource
func (v *VaultClusterPolicyValidator) validateVaultClusterPolicy(policy *vaultv1alpha1.VaultClusterPolicy) (admission.Warnings, error) {
	allErrors := make([]string, 0, len(policy.Spec.Rules))
	warnings := make(admission.Warnings, 0, len(policy.Spec.Rules))

	// Validate rules (namespace boundary enforcement is not applicable for cluster policies)
	for i, rule := range policy.Spec.Rules {
		ruleErrors, ruleWarnings := validatePolicyRule(rule, i, false)
		allErrors = append(allErrors, ruleErrors...)
		warnings = append(warnings, ruleWarnings...)
	}

	if len(allErrors) > 0 {
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(allErrors, "; "))
	}

	return warnings, nil
}

// validatePolicyRule validates a single policy rule
func validatePolicyRule(rule vaultv1alpha1.PolicyRule, index int, enforceNamespaceBoundary bool) ([]string, admission.Warnings) {
	var errors []string
	var warnings admission.Warnings

	// Validate path is not empty
	if strings.TrimSpace(rule.Path) == "" {
		errors = append(errors, fmt.Sprintf("rule[%d]: path cannot be empty", index))
	} else {
		// Validate path syntax
		if !pathPattern.MatchString(rule.Path) {
			errors = append(errors, fmt.Sprintf("rule[%d]: path %q contains invalid characters (allowed: a-zA-Z0-9/_*{}-+)", index, rule.Path))
		}

		// Validate namespace boundary enforcement
		if enforceNamespaceBoundary {
			if !strings.Contains(rule.Path, namespaceVar) {
				errors = append(errors, fmt.Sprintf("rule[%d]: path %q must contain %s when namespace boundary enforcement is enabled", index, rule.Path, namespaceVar))
			}

			// Check for wildcard before {{namespace}} variable (security risk)
			if err := validateNoWildcardBeforeNamespace(rule.Path, index); err != "" {
				errors = append(errors, err)
			}
		}
	}

	// Validate capabilities
	if len(rule.Capabilities) == 0 {
		errors = append(errors, fmt.Sprintf("rule[%d]: at least one capability is required", index))
	} else {
		for j, cap := range rule.Capabilities {
			if !validCapabilities[cap] {
				errors = append(errors, fmt.Sprintf("rule[%d].capabilities[%d]: invalid capability %q (valid: create, read, update, delete, list, sudo, deny)", index, j, cap))
			}
		}

		// Warn if both deny and other capabilities are specified
		hasDeny := false
		hasOther := false
		for _, cap := range rule.Capabilities {
			if cap == vaultv1alpha1.CapabilityDeny {
				hasDeny = true
			} else {
				hasOther = true
			}
		}
		if hasDeny && hasOther {
			warnings = append(warnings, fmt.Sprintf("rule[%d]: 'deny' capability combined with other capabilities; 'deny' takes precedence and other capabilities will be ignored", index))
		}
	}

	// Validate description (defense in depth against control character injection)
	if rule.Description != "" {
		if len(rule.Description) > 256 {
			errors = append(errors, fmt.Sprintf("rule[%d]: description must be at most 256 characters (got %d)", index, len(rule.Description)))
		}
		for _, r := range rule.Description {
			if unicode.IsControl(r) {
				errors = append(errors, fmt.Sprintf("rule[%d]: description must not contain control characters", index))
				break
			}
		}
	}

	return errors, warnings
}

// validateNoWildcardBeforeNamespace checks that there is no wildcard (*) before the {{namespace}} variable
// This is a security risk as it would allow access to paths in other namespaces
func validateNoWildcardBeforeNamespace(path string, index int) string {
	nsIndex := strings.Index(path, namespaceVar)
	if nsIndex == -1 {
		// No namespace variable, no validation needed here
		return ""
	}

	// Check for wildcard before the namespace variable
	beforeNs := path[:nsIndex]
	if strings.Contains(beforeNs, "*") {
		return fmt.Sprintf("rule[%d]: path %q contains wildcard (*) before %s which is a security risk as it may allow access to other namespaces", index, path, namespaceVar)
	}

	return ""
}

// ValidatePath validates a Vault path (exported for use in other packages)
func ValidatePath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("path cannot be empty")
	}
	if !pathPattern.MatchString(path) {
		return fmt.Errorf("path %q contains invalid characters (allowed: a-zA-Z0-9/_*{}-+)", path)
	}
	return nil
}

// ValidateCapability validates a Vault capability (exported for use in other packages)
func ValidateCapability(cap vaultv1alpha1.Capability) error {
	if !validCapabilities[cap] {
		return fmt.Errorf("invalid capability %q (valid: create, read, update, delete, list, sudo, deny)", cap)
	}
	return nil
}

// IsValidCapability checks if a capability is valid
func IsValidCapability(cap vaultv1alpha1.Capability) bool {
	return validCapabilities[cap]
}

// checkConnectionRefSameAddress is the VaultPolicyValidator method form.
func (v *VaultPolicyValidator) checkConnectionRefSameAddress(ctx context.Context, oldRef, newRef string) error {
	return checkConnectionRefSameAddress(ctx, v.client, oldRef, newRef)
}

// checkConnectionRefSameAddress allows a connectionRef change only when both
// the old and new VaultConnections resolve to the same spec.address. When one
// or both connections can't be fetched, we err on the side of the existing
// immutability behaviour and reject the change.
func checkConnectionRefSameAddress(ctx context.Context, c client.Client, oldRef, newRef string) error {
	if c == nil {
		// Without a client we can't compare addresses — preserve the old
		// immutability semantic to avoid silent migrations across Vault instances.
		return fmt.Errorf("spec.connectionRef is immutable (was %q, attempted %q)", oldRef, newRef)
	}

	oldConn := &vaultv1alpha1.VaultConnection{}
	if err := c.Get(ctx, types.NamespacedName{Name: oldRef}, oldConn); err != nil {
		return fmt.Errorf("spec.connectionRef change rejected: cannot resolve previous VaultConnection %q: %w", oldRef, err)
	}
	newConn := &vaultv1alpha1.VaultConnection{}
	if err := c.Get(ctx, types.NamespacedName{Name: newRef}, newConn); err != nil {
		return fmt.Errorf("spec.connectionRef change rejected: cannot resolve new VaultConnection %q: %w", newRef, err)
	}

	if oldConn.Spec.Address != newConn.Spec.Address {
		return fmt.Errorf(
			"spec.connectionRef change rejected: VaultConnection %q (address %q) and %q (address %q) target different Vault instances",
			oldRef, oldConn.Spec.Address, newRef, newConn.Spec.Address,
		)
	}

	return nil
}
