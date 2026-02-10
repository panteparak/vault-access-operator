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

package utils

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// NewTestVaultConnection creates a VaultConnection resource for testing.
func NewTestVaultConnection(name string) *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault.vault.svc.cluster.local:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Token: &vaultv1alpha1.TokenAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name: "vault-token",
						Key:  "token",
					},
				},
			},
		},
	}
}

// NewTestVaultConnectionWithAddress creates a VaultConnection with a custom address.
func NewTestVaultConnectionWithAddress(name, address string) *vaultv1alpha1.VaultConnection {
	conn := NewTestVaultConnection(name)
	conn.Spec.Address = address
	return conn
}

// NewTestVaultConnectionWithKubernetesAuth creates a VaultConnection with Kubernetes auth.
func NewTestVaultConnectionWithKubernetesAuth(name, role string) *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault.vault.svc.cluster.local:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{
					Role:     role,
					AuthPath: "kubernetes",
				},
			},
		},
	}
}

// NewTestVaultPolicy creates a VaultPolicy resource for testing.
func NewTestVaultPolicy(name, namespace string) *vaultv1alpha1.VaultPolicy {
	return &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "vault-connection",
			Rules: []vaultv1alpha1.PolicyRule{
				{
					Path: "secret/data/{{namespace}}/*",
					Capabilities: []vaultv1alpha1.Capability{
						vaultv1alpha1.CapabilityRead,
						vaultv1alpha1.CapabilityList,
					},
				},
			},
		},
	}
}

// NewTestVaultPolicyWithRules creates a VaultPolicy with custom rules.
func NewTestVaultPolicyWithRules(name, namespace string, rules []vaultv1alpha1.PolicyRule) *vaultv1alpha1.VaultPolicy {
	policy := NewTestVaultPolicy(name, namespace)
	policy.Spec.Rules = rules
	return policy
}

// NewTestVaultPolicyWithNamespaceBoundary creates a VaultPolicy with namespace boundary enforcement.
func NewTestVaultPolicyWithNamespaceBoundary(name, namespace string, enforce bool) *vaultv1alpha1.VaultPolicy {
	policy := NewTestVaultPolicy(name, namespace)
	policy.Spec.EnforceNamespaceBoundary = &enforce
	return policy
}

// NewTestVaultClusterPolicy creates a VaultClusterPolicy resource for testing.
func NewTestVaultClusterPolicy(name string) *vaultv1alpha1.VaultClusterPolicy {
	return &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: vaultv1alpha1.VaultClusterPolicySpec{
			ConnectionRef: "vault-connection",
			Rules: []vaultv1alpha1.PolicyRule{
				{
					Path: "secret/data/shared/*",
					Capabilities: []vaultv1alpha1.Capability{
						vaultv1alpha1.CapabilityRead,
					},
				},
			},
		},
	}
}

// NewTestVaultRole creates a VaultRole resource for testing.
func NewTestVaultRole(name, namespace string) *vaultv1alpha1.VaultRole {
	return &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "vault-connection",
			AuthPath:        "kubernetes",
			ServiceAccounts: []string{"default"},
			Policies: []vaultv1alpha1.PolicyReference{
				{
					Kind:      "VaultPolicy",
					Name:      "test-policy",
					Namespace: namespace,
				},
			},
			TokenTTL:    "1h",
			TokenMaxTTL: "24h",
		},
	}
}

// NewTestVaultRoleWithPolicies creates a VaultRole with custom policies.
func NewTestVaultRoleWithPolicies(
	name, namespace string,
	policies []vaultv1alpha1.PolicyReference,
) *vaultv1alpha1.VaultRole {
	role := NewTestVaultRole(name, namespace)
	role.Spec.Policies = policies
	return role
}

// NewTestVaultRoleWithServiceAccounts creates a VaultRole with custom service accounts.
func NewTestVaultRoleWithServiceAccounts(
	name, namespace string,
	serviceAccounts []string,
) *vaultv1alpha1.VaultRole {
	role := NewTestVaultRole(name, namespace)
	role.Spec.ServiceAccounts = serviceAccounts
	return role
}

// NewTestVaultClusterRole creates a VaultClusterRole resource for testing.
func NewTestVaultClusterRole(name string) *vaultv1alpha1.VaultClusterRole {
	return &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			ConnectionRef: "vault-connection",
			AuthPath:      "kubernetes",
			ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{
					Name:      "default",
					Namespace: "default",
				},
			},
			Policies: []vaultv1alpha1.PolicyReference{
				{
					Kind: "VaultClusterPolicy",
					Name: "cluster-policy",
				},
			},
			TokenTTL:    "1h",
			TokenMaxTTL: "24h",
		},
	}
}

// NewTestVaultClusterRoleWithServiceAccounts creates a VaultClusterRole with custom service accounts.
func NewTestVaultClusterRoleWithServiceAccounts(
	name string,
	serviceAccounts []vaultv1alpha1.ServiceAccountRef,
) *vaultv1alpha1.VaultClusterRole {
	role := NewTestVaultClusterRole(name)
	role.Spec.ServiceAccounts = serviceAccounts
	return role
}

// TestPolicyRules returns a set of common policy rules for testing.
func TestPolicyRules() []vaultv1alpha1.PolicyRule {
	return []vaultv1alpha1.PolicyRule{
		{
			Path: "secret/data/{{namespace}}/*",
			Capabilities: []vaultv1alpha1.Capability{
				vaultv1alpha1.CapabilityCreate,
				vaultv1alpha1.CapabilityRead,
				vaultv1alpha1.CapabilityUpdate,
				vaultv1alpha1.CapabilityDelete,
				vaultv1alpha1.CapabilityList,
			},
		},
		{
			Path: "secret/metadata/{{namespace}}/*",
			Capabilities: []vaultv1alpha1.Capability{
				vaultv1alpha1.CapabilityList,
				vaultv1alpha1.CapabilityRead,
			},
		},
	}
}

// TestClusterPolicyRules returns policy rules suitable for cluster-scoped policies.
func TestClusterPolicyRules() []vaultv1alpha1.PolicyRule {
	return []vaultv1alpha1.PolicyRule{
		{
			Path: "secret/data/shared/*",
			Capabilities: []vaultv1alpha1.Capability{
				vaultv1alpha1.CapabilityRead,
				vaultv1alpha1.CapabilityList,
			},
		},
		{
			Path: "auth/token/lookup-self",
			Capabilities: []vaultv1alpha1.Capability{
				vaultv1alpha1.CapabilityRead,
			},
		},
	}
}

// NewPolicyReference creates a PolicyReference for testing.
func NewPolicyReference(kind, name, namespace string) vaultv1alpha1.PolicyReference {
	return vaultv1alpha1.PolicyReference{
		Kind:      kind,
		Name:      name,
		Namespace: namespace,
	}
}

// NewVaultPolicyReference creates a PolicyReference for a VaultPolicy.
func NewVaultPolicyReference(name, namespace string) vaultv1alpha1.PolicyReference {
	return NewPolicyReference("VaultPolicy", name, namespace)
}

// NewVaultClusterPolicyReference creates a PolicyReference for a VaultClusterPolicy.
func NewVaultClusterPolicyReference(name string) vaultv1alpha1.PolicyReference {
	return NewPolicyReference("VaultClusterPolicy", name, "")
}

// NewTestVaultConnectionWithBootstrap creates a VaultConnection with bootstrap and K8s auth.
// This simulates the bootstrap flow where a bootstrap token is used to set up Kubernetes auth.
func NewTestVaultConnectionWithBootstrap(
	name, bootstrapSecretName, bootstrapSecretNamespace, role string,
) *vaultv1alpha1.VaultConnection {
	autoRevoke := true
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault.vault.svc.cluster.local:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Bootstrap: &vaultv1alpha1.BootstrapAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name:      bootstrapSecretName,
						Key:       "token",
						Namespace: bootstrapSecretNamespace,
					},
					AutoRevoke: &autoRevoke,
				},
				Kubernetes: &vaultv1alpha1.KubernetesAuth{
					Role:     role,
					AuthPath: "kubernetes",
				},
			},
		},
	}
}

// NewTestVaultConnectionWithTokenDuration creates a VaultConnection with custom token duration.
// This is useful for testing token renewal with shorter durations.
func NewTestVaultConnectionWithTokenDuration(
	name, role string, duration metav1.Duration,
) *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault.vault.svc.cluster.local:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{
					Role:          role,
					AuthPath:      "kubernetes",
					TokenDuration: duration,
				},
			},
		},
	}
}

// =============================================================================
// Test Fixture Validators
// =============================================================================
// These validators ensure test fixtures match CRD requirements.
// They panic on invalid fixtures to fail tests early during setup.

// ValidateTestVaultRole panics if the VaultRole is missing required fields.
// Use this to catch invalid fixtures at test setup time rather than runtime.
func ValidateTestVaultRole(role *vaultv1alpha1.VaultRole) {
	if role.Spec.ConnectionRef == "" {
		panic("test fixture error: VaultRole.Spec.ConnectionRef is required")
	}
	if len(role.Spec.ServiceAccounts) == 0 {
		panic("test fixture error: VaultRole.Spec.ServiceAccounts must not be empty")
	}
	if len(role.Spec.Policies) == 0 {
		panic("test fixture error: VaultRole.Spec.Policies must not be empty (CRD requires MinItems=1)")
	}
}

// ValidateTestVaultClusterRole panics if the VaultClusterRole is missing required fields.
func ValidateTestVaultClusterRole(role *vaultv1alpha1.VaultClusterRole) {
	if role.Spec.ConnectionRef == "" {
		panic("test fixture error: VaultClusterRole.Spec.ConnectionRef is required")
	}
	if len(role.Spec.ServiceAccounts) == 0 {
		panic("test fixture error: VaultClusterRole.Spec.ServiceAccounts must not be empty (CRD requires MinItems=1)")
	}
	if len(role.Spec.Policies) == 0 {
		panic("test fixture error: VaultClusterRole.Spec.Policies must not be empty (CRD requires MinItems=1)")
	}
}

// ValidateTestVaultPolicy panics if the VaultPolicy is missing required fields.
func ValidateTestVaultPolicy(policy *vaultv1alpha1.VaultPolicy) {
	if policy.Spec.ConnectionRef == "" {
		panic("test fixture error: VaultPolicy.Spec.ConnectionRef is required")
	}
	if len(policy.Spec.Rules) == 0 {
		panic("test fixture error: VaultPolicy.Spec.Rules must not be empty (CRD requires MinItems=1)")
	}
}

// ValidateTestVaultClusterPolicy panics if the VaultClusterPolicy is missing required fields.
func ValidateTestVaultClusterPolicy(policy *vaultv1alpha1.VaultClusterPolicy) {
	if policy.Spec.ConnectionRef == "" {
		panic("test fixture error: VaultClusterPolicy.Spec.ConnectionRef is required")
	}
	if len(policy.Spec.Rules) == 0 {
		panic("test fixture error: VaultClusterPolicy.Spec.Rules must not be empty (CRD requires MinItems=1)")
	}
}

// ValidateTestVaultConnection panics if the VaultConnection is missing required fields.
func ValidateTestVaultConnection(conn *vaultv1alpha1.VaultConnection) {
	if conn.Spec.Address == "" {
		panic("test fixture error: VaultConnection.Spec.Address is required")
	}
	hasAuth := conn.Spec.Auth.Token != nil ||
		conn.Spec.Auth.Kubernetes != nil ||
		conn.Spec.Auth.AppRole != nil ||
		conn.Spec.Auth.JWT != nil
	if !hasAuth {
		panic("test fixture error: VaultConnection.Spec.Auth must have at least one auth method")
	}
}
