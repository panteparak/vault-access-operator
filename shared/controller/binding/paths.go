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

// Package binding provides utilities for constructing and managing
// Vault resource bindings - explicit references from K8s resources
// to their corresponding Vault resources (like foreign keys).
package binding

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

const (
	// DefaultAuthMount is the default Kubernetes auth mount path
	DefaultAuthMount = "kubernetes"

	// ManagedResourcePrefix is the KV path prefix for managed resource metadata
	ManagedResourcePrefix = "secret/data/vault-access-operator/managed"

	// KindVaultPolicy is the kind name for VaultPolicy resources
	KindVaultPolicy = "VaultPolicy"

	// KindVaultClusterPolicy is the kind name for VaultClusterPolicy resources
	KindVaultClusterPolicy = "VaultClusterPolicy"

	// KindVaultRole is the kind name for VaultRole resources
	KindVaultRole = "VaultRole"

	// KindVaultClusterRole is the kind name for VaultClusterRole resources
	KindVaultClusterRole = "VaultClusterRole"
)

// PolicyPath returns the full Vault API path for an ACL policy.
// Example: PolicyPath("my-policy") returns "sys/policies/acl/my-policy"
func PolicyPath(policyName string) string {
	return fmt.Sprintf("sys/policies/acl/%s", policyName)
}

// RolePath returns the full Vault API path for a Kubernetes auth role.
// Example: RolePath("kubernetes", "my-role") returns "auth/kubernetes/role/my-role"
func RolePath(authMount, roleName string) string {
	if authMount == "" {
		authMount = DefaultAuthMount
	}
	return fmt.Sprintf("auth/%s/role/%s", authMount, roleName)
}

// ManagedMetadataPath returns the KV path where managed resource metadata is stored.
// This is used to track which Vault resources are managed by the operator.
// Example: ManagedMetadataPath("policy", "my-policy") returns
// "secret/data/vault-access-operator/managed/policy/my-policy"
func ManagedMetadataPath(resourceType, resourceName string) string {
	return fmt.Sprintf("%s/%s/%s", ManagedResourcePrefix, resourceType, resourceName)
}

// PolicyK8sRef returns the K8s reference string for a policy.
// For VaultPolicy: "VaultPolicy/namespace/name"
// For VaultClusterPolicy: "VaultClusterPolicy/name"
func PolicyK8sRef(kind, namespace, name string) string {
	if kind == KindVaultClusterPolicy || namespace == "" {
		return fmt.Sprintf("%s/%s", kind, name)
	}
	return fmt.Sprintf("%s/%s/%s", kind, namespace, name)
}

// RoleK8sRef returns the K8s reference string for a role.
// For VaultRole: "VaultRole/namespace/name"
// For VaultClusterRole: "VaultClusterRole/name"
func RoleK8sRef(kind, namespace, name string) string {
	if kind == KindVaultClusterRole || namespace == "" {
		return fmt.Sprintf("%s/%s", kind, name)
	}
	return fmt.Sprintf("%s/%s/%s", kind, namespace, name)
}

// NewPolicyBinding creates a new VaultResourceBinding for a policy.
func NewPolicyBinding(policyName string) vaultv1alpha1.VaultResourceBinding {
	now := metav1.NewTime(time.Now())
	return vaultv1alpha1.VaultResourceBinding{
		VaultPath:         PolicyPath(policyName),
		VaultResourceName: policyName,
		BoundAt:           &now,
		BindingVerified:   true,
		LastVerifiedAt:    &now,
	}
}

// NewRoleBinding creates a new VaultResourceBinding for a Kubernetes auth role.
func NewRoleBinding(authMount, roleName string) vaultv1alpha1.VaultResourceBinding {
	if authMount == "" {
		authMount = DefaultAuthMount
	}
	now := metav1.NewTime(time.Now())
	return vaultv1alpha1.VaultResourceBinding{
		VaultPath:         RolePath(authMount, roleName),
		VaultResourceName: roleName,
		AuthMount:         authMount,
		BoundAt:           &now,
		BindingVerified:   true,
		LastVerifiedAt:    &now,
	}
}

// UpdateBindingVerification updates the verification timestamp on a binding.
func UpdateBindingVerification(binding *vaultv1alpha1.VaultResourceBinding) {
	now := metav1.NewTime(time.Now())
	binding.BindingVerified = true
	binding.LastVerifiedAt = &now
}

// NewPolicyBindingRef creates a PolicyBinding reference for a role's policy.
func NewPolicyBindingRef(
	policyRef vaultv1alpha1.PolicyReference,
	namespace, vaultPolicyName string,
	resolved bool,
) vaultv1alpha1.PolicyBinding {
	var k8sRef string
	switch policyRef.Kind {
	case KindVaultPolicy:
		ns := policyRef.Namespace
		if ns == "" {
			ns = namespace
		}
		k8sRef = PolicyK8sRef(KindVaultPolicy, ns, policyRef.Name)
	case KindVaultClusterPolicy:
		k8sRef = PolicyK8sRef(KindVaultClusterPolicy, "", policyRef.Name)
	default:
		k8sRef = fmt.Sprintf("%s/%s", policyRef.Kind, policyRef.Name)
	}

	return vaultv1alpha1.PolicyBinding{
		K8sRef:          k8sRef,
		VaultPolicyPath: PolicyPath(vaultPolicyName),
		Resolved:        resolved,
	}
}

// VaultPolicyName computes the Vault policy name from a PolicyReference.
// For VaultPolicy: "{namespace}-{name}"
// For VaultClusterPolicy: "{name}"
func VaultPolicyName(ref vaultv1alpha1.PolicyReference, defaultNamespace string) string {
	switch ref.Kind {
	case KindVaultPolicy:
		ns := ref.Namespace
		if ns == "" {
			ns = defaultNamespace
		}
		return fmt.Sprintf("%s-%s", ns, ref.Name)
	case KindVaultClusterPolicy:
		return ref.Name
	default:
		return ref.Name
	}
}
