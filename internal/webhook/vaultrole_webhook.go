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

	// Check for naming collision with VaultClusterRole
	// VaultRole "namespace/name" maps to Vault role "{namespace}-{name}"
	// VaultClusterRole "name" maps to Vault role "{name}"
	// Collision occurs if VaultClusterRole with name "{namespace}-{name}" exists
	vaultRoleName := fmt.Sprintf("%s-%s", role.Namespace, role.Name)
	if err := v.checkRoleNameCollision(ctx, vaultRoleName, role.Namespace, role.Name); err != nil {
		return nil, err
	}

	// Check for naming collision with OTHER VaultRoles. The `namespace-name`
	// join is ambiguous: "ns1/foo-bar" and "ns1-foo/bar" both compute to
	// "ns1-foo-bar". Without this check, the second CR to be created would
	// hit a runtime Phase=Conflict instead of a clear admission error, and
	// with the adopt annotation both CRs would race on the same Vault
	// resource (overwriting each other on every reconcile).
	if err := v.checkVaultRoleCollision(ctx, vaultRoleName, role.Namespace, role.Name); err != nil {
		return nil, err
	}

	return v.validateWithContext(ctx, role)
}

// ValidateUpdate implements admission.Validator for VaultRole
func (v *VaultRoleValidator) ValidateUpdate(ctx context.Context, oldRole, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	// connectionRef is immutable after creation
	if oldRole.Spec.ConnectionRef != role.Spec.ConnectionRef {
		return nil, fmt.Errorf("spec.connectionRef is immutable (was %q, attempted %q)",
			oldRole.Spec.ConnectionRef, role.Spec.ConnectionRef)
	}

	// authPath is immutable after creation (changing it targets a different Vault auth mount)
	if oldRole.Spec.AuthPath != role.Spec.AuthPath {
		return nil, fmt.Errorf("spec.authPath is immutable (was %q, attempted %q)",
			oldRole.Spec.AuthPath, role.Spec.AuthPath)
	}

	return v.validateWithContext(ctx, role)
}

// ValidateDelete implements admission.Validator for VaultRole
func (v *VaultRoleValidator) ValidateDelete(ctx context.Context, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validate performs validation for VaultRole
func (v *VaultRoleValidator) validate(role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	var warnings admission.Warnings
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

	// Validate JWT-specific constraints (warnings non-blocking; errors block).
	jwtWarnings, jwtErrs := validateJWTSpec(
		string(role.Spec.AuthType), role.Spec.AuthPath, role.Spec.JWT, len(role.Spec.ServiceAccounts))
	warnings = append(warnings, jwtWarnings...)
	errs = append(errs, jwtErrs...)

	// IMPROVEMENTS §7: reject authPath values that target a Vault auth
	// backend the operator doesn't yet implement at the *role-write* level.
	// Operators can still authenticate *themselves* via AWS/GCP/OIDC/AppRole
	// (see VaultConnection.spec.auth), but the VaultRole CR can only write
	// role data to kubernetes or jwt mounts for now. An explicit spec.authType
	// lets a custom-named mount opt in to the jwt/kubernetes write path.
	// Catching this at admission time is clearer than waiting for the
	// reconcile-time ValidationError to surface in status.
	if authErr := validateAuthPathSupported(role.Spec.AuthPath, string(role.Spec.AuthType)); authErr != "" {
		errs = append(errs, authErr)
	}

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
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return warnings, nil
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
	warnings, err := v.validate(role)
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

	// Check for naming collision with VaultRole
	// VaultClusterRole "name" maps to Vault role "{name}"
	// VaultRole "namespace/name" maps to Vault role "{namespace}-{name}"
	// Collision occurs if any VaultRole's Vault name equals this role's name
	if err := v.checkClusterRoleNameCollision(ctx, role.Name); err != nil {
		return nil, err
	}

	return v.validateWithContext(ctx, role)
}

// ValidateUpdate implements admission.Validator for VaultClusterRole
func (v *VaultClusterRoleValidator) ValidateUpdate(ctx context.Context, oldRole, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	// connectionRef is immutable after creation
	if oldRole.Spec.ConnectionRef != role.Spec.ConnectionRef {
		return nil, fmt.Errorf("spec.connectionRef is immutable (was %q, attempted %q)",
			oldRole.Spec.ConnectionRef, role.Spec.ConnectionRef)
	}

	// authPath is immutable after creation (changing it targets a different Vault auth mount)
	if oldRole.Spec.AuthPath != role.Spec.AuthPath {
		return nil, fmt.Errorf("spec.authPath is immutable (was %q, attempted %q)",
			oldRole.Spec.AuthPath, role.Spec.AuthPath)
	}

	return v.validateWithContext(ctx, role)
}

// ValidateDelete implements admission.Validator for VaultClusterRole
func (v *VaultClusterRoleValidator) ValidateDelete(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validate performs validation for VaultClusterRole
func (v *VaultClusterRoleValidator) validate(role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	var warnings admission.Warnings
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

	// Validate JWT-specific constraints (warnings non-blocking; errors block).
	jwtWarnings, jwtErrs := validateJWTSpec(
		string(role.Spec.AuthType), role.Spec.AuthPath, role.Spec.JWT, len(role.Spec.ServiceAccounts))
	warnings = append(warnings, jwtWarnings...)
	errs = append(errs, jwtErrs...)

	// IMPROVEMENTS §7: reject authPath values that target a Vault auth
	// backend the operator doesn't yet implement at the *role-write* level.
	// Operators can still authenticate *themselves* via AWS/GCP/OIDC/AppRole
	// (see VaultConnection.spec.auth), but the VaultRole CR can only write
	// role data to kubernetes or jwt mounts for now. An explicit spec.authType
	// lets a custom-named mount opt in to the jwt/kubernetes write path.
	// Catching this at admission time is clearer than waiting for the
	// reconcile-time ValidationError to surface in status.
	if authErr := validateAuthPathSupported(role.Spec.AuthPath, string(role.Spec.AuthType)); authErr != "" {
		errs = append(errs, authErr)
	}

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
		return warnings, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return warnings, nil
}

// validateAuthPathSupported returns a non-empty error string if the given
// authPath does not resolve to a backend the role handler can write to.
// Empty/default authPath is fine (it resolves to the Kubernetes default).
//
// Accepts both the full Vault mount form (`auth/kubernetes`, `auth/jwt`)
// and the bare short form (`kubernetes`, `jwt`) — both appear in our
// user-facing docs and existing CRDs. Anything else (aws, gcp, approle,
// ldap, etc.) is rejected with a reference to the §7 coverage roadmap.
//
// Introduced for IMPROVEMENTS §7: previously this validation lived only at
// reconcile time (handler.go's backend switch returned ValidationError),
// which meant an unsupported authPath could be accepted into etcd and only
// surface in status after reconcile. Admission-time rejection gives the
// user immediate feedback.
func validateAuthPathSupported(authPath, authType string) string {
	// An explicit spec.authType is authoritative: it declares the backend
	// family directly, so the mount-path name no longer has to match a
	// naming convention. A custom mount like `auth/custom-oidc` is then
	// accepted. The CRD enum restricts authType to kubernetes/jwt.
	switch authType {
	case string(vaultv1alpha1.AuthBackendTypeJWT):
		// JWT writes need a concrete mount path; an empty authPath would
		// normalize to auth/kubernetes, contradicting the declared family.
		if strings.TrimRight(strings.TrimPrefix(authPath, "auth/"), "/") == "" {
			return "spec.authPath is required when spec.authType is jwt"
		}
		return ""
	case string(vaultv1alpha1.AuthBackendTypeKubernetes):
		return ""
	}

	// No explicit authType — infer the family from the path name.
	// Empty is the default — resolves to Kubernetes at sync time.
	if authPath == "" {
		return ""
	}
	// Accept both full (`auth/kubernetes`) and bare (`kubernetes`) forms.
	// Strip the `auth/` prefix if present, then test against the known
	// backend prefix set. This mirrors how AuthBackendForPath recognises
	// submounts like `auth/kubernetes-prod`.
	stripped := strings.TrimPrefix(authPath, "auth/")
	stripped = strings.TrimRight(stripped, "/")
	if stripped == "" {
		return ""
	}
	seg, _, _ := strings.Cut(stripped, "/")
	if strings.HasPrefix(seg, "kubernetes") || strings.HasPrefix(seg, "jwt") {
		return ""
	}
	return fmt.Sprintf(
		"spec.authPath %q targets an unsupported Vault auth backend "+
			"(only auth/kubernetes/* and auth/jwt/* are implemented for role writes; "+
			"set spec.authType to use a custom mount path). "+
			"See IMPROVEMENTS.md §7 for the backend coverage roadmap",
		authPath,
	)
}

// validateJWTSpec enforces constraints on the optional spec.jwt sub-object
// and the combination of authPath / serviceAccounts / jwt.
//
// Errors block admission; warnings are surfaced via the admission response
// without blocking. Errors cover correctness invariants:
//   - spec.jwt may only be set when authPath targets a JWT auth mount.
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
	authType, authPath string, jwt *vaultv1alpha1.VaultRoleJWTSpec, serviceAccountCount int,
) (warnings, errs []string) {
	isJWT := resolveIsJWT(authType, authPath)

	if jwt != nil && !isJWT {
		errs = append(errs,
			"spec.jwt may only be used when the role targets a JWT auth mount "+
				"(set spec.authType: jwt, or use an authPath under auth/jwt)")
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

// isJWTAuthPath returns true if the given authPath identifies a JWT auth mount.
// Mirrors vault.AuthBackendForPath without taking a dependency on pkg/vault
// from the webhook package.
// resolveIsJWT reports whether a role targets a JWT auth mount, honoring an
// explicit authType override and otherwise inferring from the path name.
// Mirrors pkg/vault.ResolveAuthBackend so admission and reconcile agree.
func resolveIsJWT(authType, authPath string) bool {
	switch authType {
	case string(vaultv1alpha1.AuthBackendTypeJWT):
		return true
	case string(vaultv1alpha1.AuthBackendTypeKubernetes):
		return false
	default:
		return isJWTAuthPath(authPath)
	}
}

func isJWTAuthPath(authPath string) bool {
	p := strings.TrimRight(authPath, "/")
	const prefix = "auth/"
	if !strings.HasPrefix(p, prefix) {
		return false
	}
	rest := p[len(prefix):]
	seg, _, _ := strings.Cut(rest, "/")
	return seg == "jwt" || strings.HasPrefix(seg, "jwt")
}

// validateWithContext performs validation including dependency checks for VaultClusterRole
func (v *VaultClusterRoleValidator) validateWithContext(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	warnings, err := v.validate(role)
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

// checkRoleNameCollision checks if a VaultClusterRole exists that would create a naming collision
// with the given VaultRole. A collision occurs when a VaultClusterRole has the same name as the
// Vault role name that would be generated for this VaultRole (i.e., "{namespace}-{name}").
func (v *VaultRoleValidator) checkRoleNameCollision(ctx context.Context, vaultRoleName, namespace, name string) error {
	if v.client == nil {
		// Client not available (e.g., in tests without client setup)
		return nil
	}

	// Check if a VaultClusterRole exists with the name that matches the Vault role name
	clusterRole := &vaultv1alpha1.VaultClusterRole{}
	err := v.client.Get(ctx, types.NamespacedName{Name: vaultRoleName}, clusterRole)
	if err == nil {
		// VaultClusterRole exists with conflicting name
		return fmt.Errorf("naming collision: VaultClusterRole %q already exists and would map to the same Vault role name %q as VaultRole %s/%s",
			vaultRoleName, vaultRoleName, namespace, name)
	}
	if !apierrors.IsNotFound(err) {
		// Unexpected error
		return fmt.Errorf("failed to check for naming collision: %w", err)
	}

	// No collision
	return nil
}

// checkVaultRoleCollision checks if any OTHER VaultRole in the cluster
// computes to the same Vault role name. The `namespace-name` join is
// ambiguous (see the collision example in ValidateCreate). Skipped on
// update since the vaultName is derived from immutable fields — a
// collision would have been caught at create.
//
// Compares namespace+name as a tuple to distinguish "this is me being
// updated/recreated" (same namespace+name) from "there's another CR
// that collides" (different namespace+name with same computed name).
func (v *VaultRoleValidator) checkVaultRoleCollision(
	ctx context.Context, vaultRoleName, namespace, name string,
) error {
	if v.client == nil {
		return nil
	}
	roleList := &vaultv1alpha1.VaultRoleList{}
	if err := v.client.List(ctx, roleList); err != nil {
		return fmt.Errorf("failed to list VaultRoles for collision check: %w", err)
	}
	for _, r := range roleList.Items {
		// Skip the CR being created/updated itself.
		if r.Namespace == namespace && r.Name == name {
			continue
		}
		existingVaultName := fmt.Sprintf("%s-%s", r.Namespace, r.Name)
		if existingVaultName == vaultRoleName {
			return fmt.Errorf(
				"naming collision: VaultRole %s/%s already maps to Vault role name %q — "+
					"rename this CR (or the existing one) so `<namespace>-<name>` is unique",
				r.Namespace, r.Name, vaultRoleName)
		}
	}
	return nil
}

// checkClusterRoleNameCollision checks if any VaultRole exists that would create a naming collision
// with the given VaultClusterRole. A collision occurs when any VaultRole's generated Vault role name
// (i.e., "{namespace}-{name}") matches this VaultClusterRole's name.
func (v *VaultClusterRoleValidator) checkClusterRoleNameCollision(ctx context.Context, clusterRoleName string) error {
	if v.client == nil {
		// Client not available (e.g., in tests without client setup)
		return nil
	}

	// List all VaultRoles and check if any would collide
	roleList := &vaultv1alpha1.VaultRoleList{}
	if err := v.client.List(ctx, roleList); err != nil {
		return fmt.Errorf("failed to list VaultRoles for collision check: %w", err)
	}

	for _, r := range roleList.Items {
		// Check if the VaultRole's Vault name would match this cluster role's name
		vaultRoleName := fmt.Sprintf("%s-%s", r.Namespace, r.Name)
		if vaultRoleName == clusterRoleName {
			return fmt.Errorf("naming collision: VaultRole %s/%s already maps to Vault role name %q which conflicts with VaultClusterRole %q",
				r.Namespace, r.Name, vaultRoleName, clusterRoleName)
		}
	}

	// No collision
	return nil
}
