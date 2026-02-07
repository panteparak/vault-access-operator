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

package binding

import (
	"testing"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

func TestPolicyPath(t *testing.T) {
	tests := []struct {
		name       string
		policyName string
		want       string
	}{
		{
			name:       "simple policy name",
			policyName: "my-policy",
			want:       "sys/policies/acl/my-policy",
		},
		{
			name:       "namespaced policy name",
			policyName: "prod-app-read",
			want:       "sys/policies/acl/prod-app-read",
		},
		{
			name:       "policy with underscores",
			policyName: "my_policy_name",
			want:       "sys/policies/acl/my_policy_name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PolicyPath(tt.policyName); got != tt.want {
				t.Errorf("PolicyPath(%q) = %q, want %q", tt.policyName, got, tt.want)
			}
		})
	}
}

func TestRolePath(t *testing.T) {
	tests := []struct {
		name      string
		authMount string
		roleName  string
		want      string
	}{
		{
			name:      "default auth mount",
			authMount: "",
			roleName:  "my-role",
			want:      "auth/kubernetes/role/my-role",
		},
		{
			name:      "explicit kubernetes mount",
			authMount: "kubernetes",
			roleName:  "app-role",
			want:      "auth/kubernetes/role/app-role",
		},
		{
			name:      "custom auth mount",
			authMount: "kubernetes-prod",
			roleName:  "prod-role",
			want:      "auth/kubernetes-prod/role/prod-role",
		},
		{
			name:      "namespaced role name",
			authMount: "kubernetes",
			roleName:  "prod-app-role",
			want:      "auth/kubernetes/role/prod-app-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RolePath(tt.authMount, tt.roleName); got != tt.want {
				t.Errorf("RolePath(%q, %q) = %q, want %q", tt.authMount, tt.roleName, got, tt.want)
			}
		})
	}
}

func TestManagedMetadataPath(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		resourceName string
		want         string
	}{
		{
			name:         "policy metadata",
			resourceType: "policy",
			resourceName: "my-policy",
			want:         "secret/data/vault-access-operator/managed/policy/my-policy",
		},
		{
			name:         "role metadata",
			resourceType: "role",
			resourceName: "my-role",
			want:         "secret/data/vault-access-operator/managed/role/my-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ManagedMetadataPath(tt.resourceType, tt.resourceName); got != tt.want {
				t.Errorf("ManagedMetadataPath(%q, %q) = %q, want %q", tt.resourceType, tt.resourceName, got, tt.want)
			}
		})
	}
}

func TestPolicyK8sRef(t *testing.T) {
	tests := []struct {
		name      string
		kind      string
		namespace string
		objName   string
		want      string
	}{
		{
			name:      "VaultPolicy with namespace",
			kind:      "VaultPolicy",
			namespace: "prod",
			objName:   "app-read",
			want:      "VaultPolicy/prod/app-read",
		},
		{
			name:      "VaultClusterPolicy no namespace",
			kind:      "VaultClusterPolicy",
			namespace: "",
			objName:   "admin-base",
			want:      "VaultClusterPolicy/admin-base",
		},
		{
			name:      "VaultClusterPolicy ignores namespace",
			kind:      "VaultClusterPolicy",
			namespace: "should-be-ignored",
			objName:   "cluster-policy",
			want:      "VaultClusterPolicy/cluster-policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PolicyK8sRef(tt.kind, tt.namespace, tt.objName); got != tt.want {
				t.Errorf("PolicyK8sRef(%q, %q, %q) = %q, want %q", tt.kind, tt.namespace, tt.objName, got, tt.want)
			}
		})
	}
}

func TestRoleK8sRef(t *testing.T) {
	tests := []struct {
		name      string
		kind      string
		namespace string
		objName   string
		want      string
	}{
		{
			name:      "VaultRole with namespace",
			kind:      "VaultRole",
			namespace: "prod",
			objName:   "app-role",
			want:      "VaultRole/prod/app-role",
		},
		{
			name:      "VaultClusterRole no namespace",
			kind:      "VaultClusterRole",
			namespace: "",
			objName:   "admin-role",
			want:      "VaultClusterRole/admin-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RoleK8sRef(tt.kind, tt.namespace, tt.objName); got != tt.want {
				t.Errorf("RoleK8sRef(%q, %q, %q) = %q, want %q", tt.kind, tt.namespace, tt.objName, got, tt.want)
			}
		})
	}
}

func TestNewPolicyBinding(t *testing.T) {
	binding := NewPolicyBinding("prod-my-policy")

	if binding.VaultPath != "sys/policies/acl/prod-my-policy" {
		t.Errorf("VaultPath = %q, want %q", binding.VaultPath, "sys/policies/acl/prod-my-policy")
	}
	if binding.VaultResourceName != "prod-my-policy" {
		t.Errorf("VaultResourceName = %q, want %q", binding.VaultResourceName, "prod-my-policy")
	}
	if binding.AuthMount != "" {
		t.Errorf("AuthMount = %q, want empty for policy", binding.AuthMount)
	}
	if !binding.BindingVerified {
		t.Error("BindingVerified = false, want true")
	}
	if binding.BoundAt == nil {
		t.Error("BoundAt = nil, want non-nil")
	}
	if binding.LastVerifiedAt == nil {
		t.Error("LastVerifiedAt = nil, want non-nil")
	}
}

func TestNewRoleBinding(t *testing.T) {
	tests := []struct {
		name       string
		authMount  string
		roleName   string
		wantPath   string
		wantAuthMt string
	}{
		{
			name:       "default auth mount",
			authMount:  "",
			roleName:   "my-role",
			wantPath:   "auth/kubernetes/role/my-role",
			wantAuthMt: "kubernetes",
		},
		{
			name:       "custom auth mount",
			authMount:  "kubernetes-prod",
			roleName:   "prod-role",
			wantPath:   "auth/kubernetes-prod/role/prod-role",
			wantAuthMt: "kubernetes-prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := NewRoleBinding(tt.authMount, tt.roleName)

			if binding.VaultPath != tt.wantPath {
				t.Errorf("VaultPath = %q, want %q", binding.VaultPath, tt.wantPath)
			}
			if binding.VaultResourceName != tt.roleName {
				t.Errorf("VaultResourceName = %q, want %q", binding.VaultResourceName, tt.roleName)
			}
			if binding.AuthMount != tt.wantAuthMt {
				t.Errorf("AuthMount = %q, want %q", binding.AuthMount, tt.wantAuthMt)
			}
			if !binding.BindingVerified {
				t.Error("BindingVerified = false, want true")
			}
		})
	}
}

func TestUpdateBindingVerification(t *testing.T) {
	binding := &vaultv1alpha1.VaultResourceBinding{
		VaultPath:       "sys/policies/acl/test",
		BindingVerified: false,
	}

	UpdateBindingVerification(binding)

	if !binding.BindingVerified {
		t.Error("BindingVerified = false after update, want true")
	}
	if binding.LastVerifiedAt == nil {
		t.Error("LastVerifiedAt = nil after update, want non-nil")
	}
}

func TestNewPolicyBindingRef(t *testing.T) {
	tests := []struct {
		name            string
		policyRef       vaultv1alpha1.PolicyReference
		namespace       string
		vaultPolicyName string
		resolved        bool
		wantK8sRef      string
		wantVaultPath   string
	}{
		{
			name: "VaultPolicy with explicit namespace",
			policyRef: vaultv1alpha1.PolicyReference{
				Kind:      "VaultPolicy",
				Name:      "app-read",
				Namespace: "prod",
			},
			namespace:       "default",
			vaultPolicyName: "prod-app-read",
			resolved:        true,
			wantK8sRef:      "VaultPolicy/prod/app-read",
			wantVaultPath:   "sys/policies/acl/prod-app-read",
		},
		{
			name: "VaultPolicy inherits namespace",
			policyRef: vaultv1alpha1.PolicyReference{
				Kind: "VaultPolicy",
				Name: "app-read",
				// No namespace specified
			},
			namespace:       "staging",
			vaultPolicyName: "staging-app-read",
			resolved:        true,
			wantK8sRef:      "VaultPolicy/staging/app-read",
			wantVaultPath:   "sys/policies/acl/staging-app-read",
		},
		{
			name: "VaultClusterPolicy",
			policyRef: vaultv1alpha1.PolicyReference{
				Kind: "VaultClusterPolicy",
				Name: "admin-base",
			},
			namespace:       "prod",
			vaultPolicyName: "admin-base",
			resolved:        false,
			wantK8sRef:      "VaultClusterPolicy/admin-base",
			wantVaultPath:   "sys/policies/acl/admin-base",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := NewPolicyBindingRef(tt.policyRef, tt.namespace, tt.vaultPolicyName, tt.resolved)

			if binding.K8sRef != tt.wantK8sRef {
				t.Errorf("K8sRef = %q, want %q", binding.K8sRef, tt.wantK8sRef)
			}
			if binding.VaultPolicyPath != tt.wantVaultPath {
				t.Errorf("VaultPolicyPath = %q, want %q", binding.VaultPolicyPath, tt.wantVaultPath)
			}
			if binding.Resolved != tt.resolved {
				t.Errorf("Resolved = %v, want %v", binding.Resolved, tt.resolved)
			}
		})
	}
}

func TestVaultPolicyName(t *testing.T) {
	tests := []struct {
		name             string
		ref              vaultv1alpha1.PolicyReference
		defaultNamespace string
		want             string
	}{
		{
			name: "VaultPolicy with explicit namespace",
			ref: vaultv1alpha1.PolicyReference{
				Kind:      "VaultPolicy",
				Name:      "app-read",
				Namespace: "prod",
			},
			defaultNamespace: "default",
			want:             "prod-app-read",
		},
		{
			name: "VaultPolicy inherits default namespace",
			ref: vaultv1alpha1.PolicyReference{
				Kind: "VaultPolicy",
				Name: "app-read",
			},
			defaultNamespace: "staging",
			want:             "staging-app-read",
		},
		{
			name: "VaultClusterPolicy has no namespace prefix",
			ref: vaultv1alpha1.PolicyReference{
				Kind: "VaultClusterPolicy",
				Name: "admin-base",
			},
			defaultNamespace: "prod",
			want:             "admin-base",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VaultPolicyName(tt.ref, tt.defaultNamespace); got != tt.want {
				t.Errorf("VaultPolicyName() = %q, want %q", got, tt.want)
			}
		})
	}
}
