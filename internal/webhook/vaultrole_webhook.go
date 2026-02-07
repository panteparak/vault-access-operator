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

	// Check for naming collision with VaultClusterRole
	// VaultRole "namespace/name" maps to Vault role "{namespace}-{name}"
	// VaultClusterRole "name" maps to Vault role "{name}"
	// Collision occurs if VaultClusterRole with name "{namespace}-{name}" exists
	vaultRoleName := fmt.Sprintf("%s-%s", role.Namespace, role.Name)
	if err := v.checkRoleNameCollision(ctx, vaultRoleName, role.Namespace, role.Name); err != nil {
		return nil, err
	}

	return v.validateWithContext(ctx, role)
}

// ValidateUpdate implements admission.Validator for VaultRole
func (v *VaultRoleValidator) ValidateUpdate(ctx context.Context, oldRole, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	return v.validateWithContext(ctx, role)
}

// ValidateDelete implements admission.Validator for VaultRole
func (v *VaultRoleValidator) ValidateDelete(ctx context.Context, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validate performs validation for VaultRole
//
//nolint:unparam // Warnings return is for future use and interface consistency
func (v *VaultRoleValidator) validate(role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
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

	if len(errs) > 0 {
		return nil, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return nil, nil
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
	return v.validateWithContext(ctx, role)
}

// ValidateDelete implements admission.Validator for VaultClusterRole
func (v *VaultClusterRoleValidator) ValidateDelete(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validate performs validation for VaultClusterRole
//
//nolint:unparam // Warnings return is for future use and interface consistency
func (v *VaultClusterRoleValidator) validate(role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
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

	if len(errs) > 0 {
		return nil, fmt.Errorf("validation failed: %s", strings.Join(errs, "; "))
	}

	return nil, nil
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
