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
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// log is for logging in this package.
var vaultrolelog = logf.Log.WithName("vaultrole-webhook")

// Policy reference kinds.
const (
	PolicyKindVaultPolicy        = "VaultPolicy"
	PolicyKindVaultClusterPolicy = "VaultClusterPolicy"
)

// VaultRoleValidator validates VaultRole resources
type VaultRoleValidator struct {
	client client.Client
}

// VaultClusterRoleValidator validates VaultClusterRole resources
type VaultClusterRoleValidator struct {
	client client.Client
}

// Ensure interfaces are implemented
var _ admission.Validator[*vaultv1alpha1.VaultRole] = &VaultRoleValidator{}
var _ admission.Validator[*vaultv1alpha1.VaultClusterRole] = &VaultClusterRoleValidator{}

// SetupWebhookWithManager sets up the VaultRole webhook with the manager
func (v *VaultRoleValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	v.client = mgr.GetClient()
	return ctrl.NewWebhookManagedBy(mgr, &vaultv1alpha1.VaultRole{}).
		WithValidator(v).
		Complete()
}

// SetupWebhookWithManager sets up the VaultClusterRole webhook with the manager
func (v *VaultClusterRoleValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	v.client = mgr.GetClient()
	return ctrl.NewWebhookManagedBy(mgr, &vaultv1alpha1.VaultClusterRole{}).
		WithValidator(v).
		Complete()
}

// ValidateCreate implements admission.Validator for VaultRole
func (v *VaultRoleValidator) ValidateCreate(ctx context.Context, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	vaultrolelog.Info("validating VaultRole create", "name", role.Name, "namespace", role.Namespace)

	if err := rejectAdoptIntentWithoutMarkers(role.GetAnnotations(), role.Spec.ConflictPolicy); err != nil {
		return nil, err
	}

	// No naming-collision checks (ADR 0010): the fixed 4-segment shape
	// vao.{identity}.{namespace}.{name} is injective — no two distinct CRs
	// can derive the same Vault role name. The pre-0010 checks guarded the
	// ambiguous "{namespace}-{name}" dash join.

	return v.validateWithContext(ctx, role)
}

// ValidateUpdate implements admission.Validator for VaultRole
func (v *VaultRoleValidator) ValidateUpdate(ctx context.Context, oldRole, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	// connectionRef is immutable after creation — it pins the auth mount
	// the role is written to (roles carry no mount fields of their own).
	if oldRole.Spec.ConnectionRef != role.Spec.ConnectionRef {
		return nil, fmt.Errorf("spec.connectionRef is immutable (was %q, attempted %q)",
			oldRole.Spec.ConnectionRef, role.Spec.ConnectionRef)
	}

	return v.validateWithContext(ctx, role)
}

// ValidateDelete implements admission.Validator for VaultRole
func (v *VaultRoleValidator) ValidateDelete(ctx context.Context, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validate performs the client-free spec validation for VaultRole.
// Warnings all come from the client-backed checks in validateWithContext.
func (v *VaultRoleValidator) validate(role *vaultv1alpha1.VaultRole) error {
	var errs []string

	// Validate service accounts are not empty
	if len(role.Spec.ServiceAccounts) == 0 {
		errs = append(errs, "serviceAccounts must not be empty")
	}

	// Validate each service account is a simple name (no namespace prefix)
	for i, sa := range role.Spec.ServiceAccounts {
		if sa == "" {
			errs = append(errs, fmt.Sprintf("serviceAccounts[%d]: name must not be empty", i))
			continue
		}
		// Service accounts should be simple names without namespace prefix
		if strings.Contains(sa, "/") {
			errs = append(errs, fmt.Sprintf("serviceAccounts[%d]: must be a simple name without namespace prefix (got %q)", i, sa))
		}
	}

	// Validate policies
	if len(role.Spec.Policies) == 0 {
		errs = append(errs, "policies must not be empty")
	}

	for i, policy := range role.Spec.Policies {
		if err := validatePolicyReference(policy, i, true); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// JWT-specific constraints are validated in validateWithContext — the
	// backend family comes from the referenced VaultConnection, which needs
	// the API client.

	// Reject the discovery placeholder appearing without the
	// discovery-pending annotation. The discovery flow injects the
	// placeholder + annotation as a pair so MinItems=1 is satisfied
	// while the user adopts. If the user clears the annotation but
	// leaves the placeholder, a Vault write would push the literal
	// "discovery-placeholder-replace-me" string as a service account
	// name, producing a Vault role bound to a non-existent SA.
	if errStr := validateDiscoveryPlaceholderConsistency(
		role.Annotations, role.Spec.ServiceAccounts, role.Spec.Policies,
	); errStr != "" {
		errs = append(errs, errStr)
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return nil
}

// validateDiscoveryPlaceholderConsistency rejects a CR that contains
// the discovery placeholder string in any spec field but does NOT have
// the `vault.platform.io/discovery-pending=true` annotation. The pair
// is a single transactional state — clearing the annotation means
// "I've adopted this resource; here is the real spec." Leaving the
// placeholder while clearing the annotation is almost always a user
// mistake (forgot to replace placeholders) and would produce a Vault
// resource with garbage values.
//
// Returns "" when valid (placeholder absent OR annotation present) or
// when annotation is set (discovery-pending blocks the write anyway).
//
// Implements the followup to IMPROVEMENTS Missing Features §G via
// the audit finding F4.
func validateDiscoveryPlaceholderConsistency(
	annotations map[string]string,
	serviceAccounts []string,
	policies []vaultv1alpha1.PolicyReference,
) string {
	// If discovery-pending is set, the reconciler skips Vault writes;
	// placeholder is allowed in this transient state.
	if annotations[vaultv1alpha1.AnnotationDiscoveryPending] == vaultv1alpha1.AnnotationValueTrue {
		return ""
	}
	for _, sa := range serviceAccounts {
		if sa == vaultv1alpha1.DiscoveryPlaceholderValue {
			return "spec.serviceAccounts contains the discovery placeholder " +
				"(\"" + vaultv1alpha1.DiscoveryPlaceholderValue + "\") but the " +
				"vault.platform.io/discovery-pending annotation is not set; " +
				"replace the placeholder with real service account names before " +
				"clearing the annotation"
		}
	}
	for _, p := range policies {
		if p.Name == vaultv1alpha1.DiscoveryPlaceholderValue {
			return "spec.policies contains the discovery placeholder " +
				"(\"" + vaultv1alpha1.DiscoveryPlaceholderValue + "\") but the " +
				"vault.platform.io/discovery-pending annotation is not set; " +
				"replace with real policy references before clearing the annotation"
		}
	}
	return ""
}

// validateWithContext performs validation including dependency checks for VaultRole
func (v *VaultRoleValidator) validateWithContext(ctx context.Context, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	if err := v.validate(role); err != nil {
		return nil, err
	}

	// Connection-derived checks: the referenced VaultConnection is the sole
	// source of the role's auth mount and backend family.
	warnings, err := validateRoleMountFromConnection(
		ctx, v.client, role.Spec.ConnectionRef, role.Spec.JWT, len(role.Spec.ServiceAccounts))
	if err != nil {
		return warnings, err
	}

	// Check policy dependencies (returns warnings, not errors)
	depWarnings := v.checkPolicyDependencies(ctx, role.Spec.Policies, role.Namespace)
	warnings = append(warnings, depWarnings...)

	// IMPROVEMENTS §36: warn if the referenced VaultConnection doesn't exist yet.
	warnings = append(warnings, checkConnectionRefExists(ctx, v.client, role.Spec.ConnectionRef)...)

	return warnings, nil
}

// validateRoleMountFromConnection runs the admission checks that need the
// referenced VaultConnection: the connection must resolve a role-capable
// mount (deny when it exists but can't), and the resolved backend family
// gates the spec.jwt constraints. A missing connection (GitOps ordering) or
// a transient fetch failure skips these checks — the reconcile-time
// backstop (Handler.resolveRoleTarget) re-derives everything and surfaces
// permanent problems in status; checkConnectionRefExists already warns.
func validateRoleMountFromConnection(
	ctx context.Context, c client.Client, connRef string,
	jwt *vaultv1alpha1.VaultRoleJWTSpec, serviceAccountCount int,
) (admission.Warnings, error) {
	if c == nil || connRef == "" {
		return nil, nil
	}
	conn := &vaultv1alpha1.VaultConnection{}
	if err := c.Get(ctx, types.NamespacedName{Name: connRef}, conn); err != nil {
		if !apierrors.IsNotFound(err) {
			vaultrolelog.V(1).Info("failed to fetch VaultConnection for role-mount validation",
				"connection", connRef, "error", err.Error())
		}
		return nil, nil
	}

	_, backend, err := conn.RoleMount()
	if err != nil {
		return nil, fmt.Errorf(
			"validation failed: VaultConnection %q has no role-capable auth mount: %v", connRef, err)
	}

	isJWT := backend == vaultv1alpha1.AuthBackendTypeJWT
	jwtWarnings, jwtErrs := validateJWTSpec(isJWT, jwt, serviceAccountCount)
	if len(jwtErrs) > 0 {
		return jwtWarnings, fmt.Errorf("validation failed: %s", strings.Join(jwtErrs, "; "))
	}
	return jwtWarnings, nil
}

// checkPolicyDependencies checks if referenced policies exist and returns warnings if they don't
func (v *VaultRoleValidator) checkPolicyDependencies(ctx context.Context, policies []vaultv1alpha1.PolicyReference, roleNamespace string) admission.Warnings {
	if v.client == nil {
		return nil
	}

	var warnings admission.Warnings
	for _, ref := range policies {
		warning := v.checkPolicyExists(ctx, ref, roleNamespace)
		if warning != "" {
			warnings = append(warnings, warning)
		}
	}
	return warnings
}

// checkPolicyExists checks if a single policy reference exists and returns a warning message if not
func (v *VaultRoleValidator) checkPolicyExists(ctx context.Context, ref vaultv1alpha1.PolicyReference, roleNamespace string) string {
	switch ref.Kind {
	case PolicyKindVaultPolicy:
		ns := ref.Namespace
		if ns == "" {
			ns = roleNamespace
		}
		policy := &vaultv1alpha1.VaultPolicy{}
		if err := v.client.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ns}, policy); err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Sprintf("referenced VaultPolicy %s/%s does not exist", ns, ref.Name)
			}
			// Log but don't warn on other errors (might be transient)
			vaultrolelog.V(1).Info("failed to check policy existence", "policy", ref.Name, "namespace", ns, "error", err)
		}
	case PolicyKindVaultClusterPolicy:
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		if err := v.client.Get(ctx, types.NamespacedName{Name: ref.Name}, policy); err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Sprintf("referenced VaultClusterPolicy %s does not exist", ref.Name)
			}
			// Log but don't warn on other errors
			vaultrolelog.V(1).Info("failed to check cluster policy existence", "policy", ref.Name, "error", err)
		}
	}
	return ""
}

// ValidateCreate implements admission.Validator for VaultClusterRole
func (v *VaultClusterRoleValidator) ValidateCreate(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	vaultrolelog.Info("validating VaultClusterRole create", "name", role.Name)

	if err := rejectAdoptIntentWithoutMarkers(role.GetAnnotations(), role.Spec.ConflictPolicy); err != nil {
		return nil, err
	}

	// No naming-collision check against VaultRole (ADR 0010): the "_"
	// namespace segment of cluster-scoped names cannot equal a real
	// namespace, so cross-scope collisions are structurally impossible.

	return v.validateWithContext(ctx, role)
}

// ValidateUpdate implements admission.Validator for VaultClusterRole
func (v *VaultClusterRoleValidator) ValidateUpdate(ctx context.Context, oldRole, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	// connectionRef is immutable after creation — it pins the auth mount
	// the role is written to (roles carry no mount fields of their own).
	if oldRole.Spec.ConnectionRef != role.Spec.ConnectionRef {
		return nil, fmt.Errorf("spec.connectionRef is immutable (was %q, attempted %q)",
			oldRole.Spec.ConnectionRef, role.Spec.ConnectionRef)
	}

	return v.validateWithContext(ctx, role)
}

// ValidateDelete implements admission.Validator for VaultClusterRole
func (v *VaultClusterRoleValidator) ValidateDelete(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validate performs the client-free spec validation for VaultClusterRole.
// Warnings all come from the client-backed checks in validateWithContext.
func (v *VaultClusterRoleValidator) validate(role *vaultv1alpha1.VaultClusterRole) error {
	var errs []string

	// Validate service accounts are not empty
	if len(role.Spec.ServiceAccounts) == 0 {
		errs = append(errs, "serviceAccounts must not be empty")
	}

	// Validate each service account has both name and namespace
	for i, sa := range role.Spec.ServiceAccounts {
		if sa.Name == "" {
			errs = append(errs, fmt.Sprintf("serviceAccounts[%d].name: must not be empty", i))
		}
		if sa.Namespace == "" {
			errs = append(errs, fmt.Sprintf("serviceAccounts[%d].namespace: must not be empty", i))
		}
	}

	// Validate policies
	if len(role.Spec.Policies) == 0 {
		errs = append(errs, "policies must not be empty")
	}

	for i, policy := range role.Spec.Policies {
		// For VaultClusterRole, VaultPolicy references must have namespace specified
		if err := validatePolicyReference(policy, i, false); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// JWT-specific constraints are validated in validateWithContext — the
	// backend family comes from the referenced VaultConnection, which needs
	// the API client.

	// Mirror the placeholder check from VaultRole. ServiceAccountRef has
	// a different shape so we extract just the names for the shared helper.
	saNames := make([]string, len(role.Spec.ServiceAccounts))
	for i, ref := range role.Spec.ServiceAccounts {
		saNames[i] = ref.Name
	}
	if errStr := validateDiscoveryPlaceholderConsistency(
		role.Annotations, saNames, role.Spec.Policies,
	); errStr != "" {
		errs = append(errs, errStr)
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return nil
}

// validateJWTSpec enforces constraints on the optional spec.jwt sub-object
// given the backend family resolved from the referenced VaultConnection.
//
// Errors block admission; warnings are surfaced via the admission response
// without blocking. Errors cover correctness invariants:
//   - spec.jwt may only be set when the connection resolves to a
//     jwt/oidc-family role mount.
//   - spec.jwt.boundSubject and spec.jwt.{boundClaims,boundClaimsList}
//     are mutually exclusive.
//   - Multi-SA roles must pin identity via boundSubject, boundClaims, or
//     boundClaimsList — the operator cannot derive a single bound_subject
//     from multiple SAs.
//
// Warnings cover footgun bindings common in CI/CD JWT auth — most CI tokens
// (GitLab, GitHub Actions, etc.) carry a `ref` claim that must be paired
// with `ref_type` and `ref_protected` to avoid tag-spoof and unprotected-branch
// bypass.
func validateJWTSpec(
	isJWT bool, jwt *vaultv1alpha1.VaultRoleJWTSpec, serviceAccountCount int,
) (warnings, errs []string) {
	if jwt != nil && !isJWT {
		errs = append(errs,
			"spec.jwt may only be used when the referenced VaultConnection resolves to a "+
				"jwt/oidc-family role mount (its login mount or defaults.authPath)")
		return warnings, errs
	}

	if !isJWT {
		return warnings, errs
	}

	hasClaims := jwt != nil && (len(jwt.BoundClaims) > 0 || len(jwt.BoundClaimsList) > 0)

	if jwt != nil && jwt.BoundSubject != "" && hasClaims {
		errs = append(errs,
			"spec.jwt.boundSubject and spec.jwt.boundClaims/boundClaimsList are mutually exclusive")
	}

	// Derivation can only produce a single bound_subject; require explicit override for multi-SA.
	if serviceAccountCount > 1 {
		hasOverride := jwt != nil && (jwt.BoundSubject != "" || hasClaims)
		if !hasOverride {
			errs = append(errs,
				"JWT VaultRole with more than one serviceAccount must set "+
					"spec.jwt.boundSubject, spec.jwt.boundClaims, or spec.jwt.boundClaimsList explicitly")
		}
	}

	if jwt == nil {
		return warnings, errs
	}

	// BoundClaimsType without any claims is a no-op — likely user confusion.
	if jwt.BoundClaimsType != "" && !hasClaims {
		warnings = append(warnings,
			"spec.jwt.boundClaimsType is set but no bound_claims are defined; "+
				"the field has no effect without spec.jwt.boundClaims or spec.jwt.boundClaimsList")
	}

	// Duplicate key in BoundClaims AND BoundClaimsList — list wins silently.
	for k := range jwt.BoundClaims {
		if _, dup := jwt.BoundClaimsList[k]; dup {
			warnings = append(warnings, fmt.Sprintf(
				"spec.jwt.boundClaims[%q] is overridden by spec.jwt.boundClaimsList[%q]; "+
					"remove the scalar entry to silence this warning",
				k, k,
			))
		}
	}

	// CI/CD security guardrails for `ref` bindings (GitLab, GitHub Actions,
	// Buildkite, CircleCI all emit ref/ref_type/ref_protected style claims).
	if jwtClaimIsBound(jwt, "ref") {
		if !jwtClaimIsBound(jwt, "ref_type") {
			warnings = append(warnings,
				"spec.jwt binds 'ref' without 'ref_type'. A tag with the same name as a branch can satisfy this role. "+
					"Add ref_type: [\"branch\"] or [\"tag\"] to spec.jwt.boundClaimsList.")
		}
		if !jwtClaimIsBound(jwt, "ref_protected") {
			warnings = append(warnings,
				"spec.jwt binds 'ref' without 'ref_protected'. An attacker pushing an unprotected branch "+
					"with the same name can satisfy this role. For protected-branch-only bindings, add "+
					"ref_protected: [\"true\"] to spec.jwt.boundClaimsList (note: this is the string \"true\", "+
					"not a YAML boolean).")
		}
	}

	return warnings, errs
}

// jwtClaimIsBound reports whether the given claim key is bound by either
// BoundClaims (deprecated scalars) or BoundClaimsList (lists).
func jwtClaimIsBound(jwt *vaultv1alpha1.VaultRoleJWTSpec, key string) bool {
	if jwt == nil {
		return false
	}
	if _, ok := jwt.BoundClaims[key]; ok {
		return true
	}
	_, ok := jwt.BoundClaimsList[key]
	return ok
}

// validateWithContext performs validation including dependency checks for VaultClusterRole
func (v *VaultClusterRoleValidator) validateWithContext(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	if err := v.validate(role); err != nil {
		return nil, err
	}

	// Connection-derived checks: the referenced VaultConnection is the sole
	// source of the role's auth mount and backend family.
	warnings, err := validateRoleMountFromConnection(
		ctx, v.client, role.Spec.ConnectionRef, role.Spec.JWT, len(role.Spec.ServiceAccounts))
	if err != nil {
		return warnings, err
	}

	// Check policy dependencies (returns warnings, not errors)
	depWarnings := v.checkPolicyDependencies(ctx, role.Spec.Policies)
	warnings = append(warnings, depWarnings...)

	// IMPROVEMENTS §36.
	warnings = append(warnings, checkConnectionRefExists(ctx, v.client, role.Spec.ConnectionRef)...)

	return warnings, nil
}

// checkPolicyDependencies checks if referenced policies exist and returns warnings if they don't
func (v *VaultClusterRoleValidator) checkPolicyDependencies(ctx context.Context, policies []vaultv1alpha1.PolicyReference) admission.Warnings {
	if v.client == nil {
		return nil
	}

	var warnings admission.Warnings
	for _, ref := range policies {
		warning := v.checkPolicyExists(ctx, ref)
		if warning != "" {
			warnings = append(warnings, warning)
		}
	}
	return warnings
}

// checkPolicyExists checks if a single policy reference exists and returns a warning message if not
func (v *VaultClusterRoleValidator) checkPolicyExists(ctx context.Context, ref vaultv1alpha1.PolicyReference) string {
	switch ref.Kind {
	case PolicyKindVaultPolicy:
		// For VaultClusterRole, namespace is always specified
		policy := &vaultv1alpha1.VaultPolicy{}
		if err := v.client.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, policy); err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Sprintf("referenced VaultPolicy %s/%s does not exist", ref.Namespace, ref.Name)
			}
			vaultrolelog.V(1).Info("failed to check policy existence", "policy", ref.Name, "namespace", ref.Namespace, "error", err)
		}
	case PolicyKindVaultClusterPolicy:
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		if err := v.client.Get(ctx, types.NamespacedName{Name: ref.Name}, policy); err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Sprintf("referenced VaultClusterPolicy %s does not exist", ref.Name)
			}
			vaultrolelog.V(1).Info("failed to check cluster policy existence", "policy", ref.Name, "error", err)
		}
	}
	return ""
}

// validatePolicyReference validates a PolicyReference
// allowDefaultNamespace indicates whether namespace can be omitted for VaultPolicy references
func validatePolicyReference(ref vaultv1alpha1.PolicyReference, index int, allowDefaultNamespace bool) error {
	// Validate kind
	switch ref.Kind {
	case "VaultPolicy", "VaultClusterPolicy":
		// Valid kinds
	default:
		return fmt.Errorf("policies[%d].kind: must be VaultPolicy or VaultClusterPolicy (got %q)", index, ref.Kind)
	}

	// Validate name is not empty
	if ref.Name == "" {
		return fmt.Errorf("policies[%d].name: must not be empty", index)
	}

	// Validate namespace based on kind
	switch ref.Kind {
	case PolicyKindVaultPolicy:
		if ref.Namespace == "" && !allowDefaultNamespace {
			return fmt.Errorf("policies[%d].namespace: must be specified for VaultPolicy references in VaultClusterRole", index)
		}
		// Note: When namespace is empty and allowDefaultNamespace is true (VaultRole case),
		// the controller will default to the VaultRole's namespace
	case PolicyKindVaultClusterPolicy:
		// VaultClusterPolicy is cluster-scoped, namespace should not be specified
		if ref.Namespace != "" {
			return fmt.Errorf("policies[%d].namespace: must not be specified for VaultClusterPolicy references", index)
		}
	}

	return nil
}
