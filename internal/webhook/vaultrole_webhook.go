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

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// VaultRoleValidator validates VaultRole resources
type VaultRoleValidator struct{}

// VaultClusterRoleValidator validates VaultClusterRole resources
type VaultClusterRoleValidator struct{}

// Ensure interfaces are implemented
var _ admission.Validator[*vaultv1alpha1.VaultRole] = &VaultRoleValidator{}
var _ admission.Validator[*vaultv1alpha1.VaultClusterRole] = &VaultClusterRoleValidator{}

// SetupWebhookWithManager sets up the VaultRole webhook with the manager
func (v *VaultRoleValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &vaultv1alpha1.VaultRole{}).
		WithValidator(v).
		Complete()
}

// SetupWebhookWithManager sets up the VaultClusterRole webhook with the manager
func (v *VaultClusterRoleValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &vaultv1alpha1.VaultClusterRole{}).
		WithValidator(v).
		Complete()
}

// ValidateCreate implements admission.Validator for VaultRole
func (v *VaultRoleValidator) ValidateCreate(ctx context.Context, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	return v.validate(role)
}

// ValidateUpdate implements admission.Validator for VaultRole
func (v *VaultRoleValidator) ValidateUpdate(ctx context.Context, oldRole, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	return v.validate(role)
}

// ValidateDelete implements admission.Validator for VaultRole
func (v *VaultRoleValidator) ValidateDelete(ctx context.Context, role *vaultv1alpha1.VaultRole) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validate performs validation for VaultRole
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

// ValidateCreate implements admission.Validator for VaultClusterRole
func (v *VaultClusterRoleValidator) ValidateCreate(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	return v.validate(role)
}

// ValidateUpdate implements admission.Validator for VaultClusterRole
func (v *VaultClusterRoleValidator) ValidateUpdate(ctx context.Context, oldRole, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	return v.validate(role)
}

// ValidateDelete implements admission.Validator for VaultClusterRole
func (v *VaultClusterRoleValidator) ValidateDelete(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) (admission.Warnings, error) {
	// No validation needed for delete
	return nil, nil
}

// validate performs validation for VaultClusterRole
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
	case "VaultPolicy":
		if ref.Namespace == "" && !allowDefaultNamespace {
			return fmt.Errorf("policies[%d].namespace: must be specified for VaultPolicy references in VaultClusterRole", index)
		}
		// Note: When namespace is empty and allowDefaultNamespace is true (VaultRole case),
		// the controller will default to the VaultRole's namespace
	case "VaultClusterPolicy":
		// VaultClusterPolicy is cluster-scoped, namespace should not be specified
		if ref.Namespace != "" {
			return fmt.Errorf("policies[%d].namespace: must not be specified for VaultClusterPolicy references", index)
		}
	}

	return nil
}
