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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

func TestVaultRoleValidator_ValidateCreate(t *testing.T) {
	tests := []struct {
		name        string
		role        *vaultv1alpha1.VaultRole
		wantErr     bool
		errContains string
	}{
		{
			name: "valid role with single service account",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid role with multiple service accounts",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"sa-1", "sa-2", "sa-3"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid role with VaultClusterPolicy reference",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "shared-policy",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid role with multiple policy references",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "app-policy",
						},
						{
							Kind: "VaultClusterPolicy",
							Name: "shared-policy",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty service accounts list",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "serviceAccounts must not be empty",
		},
		{
			name: "empty service account name in list",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"valid-sa", ""},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "name must not be empty",
		},
		{
			name: "service account with namespace prefix is rejected",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"other-namespace/my-sa"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "must be a simple name without namespace prefix",
		},
		{
			name: "service account with slash in name is rejected",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my/service/account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "must be a simple name without namespace prefix",
		},
		{
			name: "empty policies list",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies:        []vaultv1alpha1.PolicyReference{},
				},
			},
			wantErr:     true,
			errContains: "policies must not be empty",
		},
		{
			name: "invalid policy kind",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "InvalidKind",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "must be VaultPolicy or VaultClusterPolicy",
		},
		{
			name: "empty policy name",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "name: must not be empty",
		},
		{
			name: "VaultClusterPolicy with namespace is rejected",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultClusterPolicy",
							Name:      "shared-policy",
							Namespace: "some-namespace",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "must not be specified for VaultClusterPolicy",
		},
		{
			name: "VaultPolicy with explicit namespace is valid",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultPolicy",
							Name:      "my-policy",
							Namespace: "default",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "VaultPolicy without namespace uses default (valid for VaultRole)",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
							// Namespace not specified - will default to VaultRole's namespace
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VaultRoleValidator{}
			_, err := v.ValidateCreate(context.Background(), tt.role)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateCreate() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestVaultRoleValidator_ValidateUpdate(t *testing.T) {
	tests := []struct {
		name        string
		oldRole     *vaultv1alpha1.VaultRole
		newRole     *vaultv1alpha1.VaultRole
		wantErr     bool
		errContains string
	}{
		{
			name: "valid update adding service account",
			oldRole: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"sa-1"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			newRole: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"sa-1", "sa-2"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid update with namespace-prefixed service account",
			oldRole: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"sa-1"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			newRole: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"other-ns/sa-1"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "must be a simple name without namespace prefix",
		},
		{
			name: "connectionRef changed (immutable)",
			oldRole: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-role", Namespace: "default"},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "old-connection",
					ServiceAccounts: []string{"sa-1"},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p1"}},
				},
			},
			newRole: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-role", Namespace: "default"},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "new-connection",
					ServiceAccounts: []string{"sa-1"},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p1"}},
				},
			},
			wantErr:     true,
			errContains: "spec.connectionRef is immutable",
		},
		{
			name: "authPath changed (immutable)",
			oldRole: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-role", Namespace: "default"},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					AuthPath:        "kubernetes",
					ServiceAccounts: []string{"sa-1"},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p1"}},
				},
			},
			newRole: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-role", Namespace: "default"},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					AuthPath:        "kubernetes-v2",
					ServiceAccounts: []string{"sa-1"},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p1"}},
				},
			},
			wantErr:     true,
			errContains: "spec.authPath is immutable",
		},
		{
			name: "connectionRef and authPath unchanged (allowed)",
			oldRole: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-role", Namespace: "default"},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					AuthPath:        "kubernetes",
					ServiceAccounts: []string{"sa-1"},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p1"}},
				},
			},
			newRole: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-role", Namespace: "default"},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					AuthPath:        "kubernetes",
					ServiceAccounts: []string{"sa-1", "sa-2"},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p1"}},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VaultRoleValidator{}
			_, err := v.ValidateUpdate(context.Background(), tt.oldRole, tt.newRole)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateUpdate() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestVaultRoleValidator_ValidateDelete(t *testing.T) {
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "default",
		},
	}

	v := &VaultRoleValidator{}
	warnings, err := v.ValidateDelete(context.Background(), role)
	if err != nil {
		t.Errorf("ValidateDelete() unexpected error = %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateDelete() unexpected warnings = %v", warnings)
	}
}

func TestVaultClusterRoleValidator_ValidateCreate(t *testing.T) {
	tests := []struct {
		name        string
		role        *vaultv1alpha1.VaultClusterRole
		wantErr     bool
		errContains string
	}{
		{
			name: "valid cluster role with namespaced service account",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "my-service-account",
							Namespace: "my-namespace",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultPolicy",
							Name:      "my-policy",
							Namespace: "my-namespace",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid cluster role with multiple service accounts from different namespaces",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "sa-1",
							Namespace: "namespace-1",
						},
						{
							Name:      "sa-2",
							Namespace: "namespace-2",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "shared-policy",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid cluster role with VaultClusterPolicy",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "my-service-account",
							Namespace: "my-namespace",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "cluster-policy",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty service accounts list",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "shared-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "serviceAccounts must not be empty",
		},
		{
			name: "service account missing name",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "",
							Namespace: "my-namespace",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "shared-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "name: must not be empty",
		},
		{
			name: "service account missing namespace",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "my-service-account",
							Namespace: "",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "shared-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "namespace: must not be empty",
		},
		{
			name: "empty policies list",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "my-service-account",
							Namespace: "my-namespace",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{},
				},
			},
			wantErr:     true,
			errContains: "policies must not be empty",
		},
		{
			name: "VaultPolicy without namespace is rejected for VaultClusterRole",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "my-service-account",
							Namespace: "my-namespace",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
							// Namespace is missing - should fail for VaultClusterRole
						},
					},
				},
			},
			wantErr:     true,
			errContains: "must be specified for VaultPolicy references in VaultClusterRole",
		},
		{
			name: "VaultClusterPolicy with namespace is rejected",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "my-service-account",
							Namespace: "my-namespace",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultClusterPolicy",
							Name:      "cluster-policy",
							Namespace: "some-namespace",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "must not be specified for VaultClusterPolicy",
		},
		{
			name: "invalid policy kind",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "my-service-account",
							Namespace: "my-namespace",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "InvalidKind",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "must be VaultPolicy or VaultClusterPolicy",
		},
		{
			name: "empty policy name",
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "my-service-account",
							Namespace: "my-namespace",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultPolicy",
							Name:      "",
							Namespace: "my-namespace",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "name: must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VaultClusterRoleValidator{}
			_, err := v.ValidateCreate(context.Background(), tt.role)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateCreate() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestVaultClusterRoleValidator_ValidateUpdate(t *testing.T) {
	tests := []struct {
		name        string
		oldRole     *vaultv1alpha1.VaultClusterRole
		newRole     *vaultv1alpha1.VaultClusterRole
		wantErr     bool
		errContains string
	}{
		{
			name: "valid update adding service account",
			oldRole: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "sa-1",
							Namespace: "ns-1",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "shared-policy",
						},
					},
				},
			},
			newRole: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "sa-1",
							Namespace: "ns-1",
						},
						{
							Name:      "sa-2",
							Namespace: "ns-2",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "shared-policy",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid update with service account missing namespace",
			oldRole: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "sa-1",
							Namespace: "ns-1",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "shared-policy",
						},
					},
				},
			},
			newRole: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      "sa-1",
							Namespace: "",
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "shared-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "namespace: must not be empty",
		},
		{
			name: "connectionRef changed (immutable)",
			oldRole: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-role"},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef:   "old-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{{Name: "sa-1", Namespace: "ns-1"}},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultClusterPolicy", Name: "p1"}},
				},
			},
			newRole: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-role"},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef:   "new-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{{Name: "sa-1", Namespace: "ns-1"}},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultClusterPolicy", Name: "p1"}},
				},
			},
			wantErr:     true,
			errContains: "spec.connectionRef is immutable",
		},
		{
			name: "authPath changed (immutable)",
			oldRole: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-role"},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef:   "test-connection",
					AuthPath:        "kubernetes",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{{Name: "sa-1", Namespace: "ns-1"}},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultClusterPolicy", Name: "p1"}},
				},
			},
			newRole: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-role"},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef:   "test-connection",
					AuthPath:        "kubernetes-v2",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{{Name: "sa-1", Namespace: "ns-1"}},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultClusterPolicy", Name: "p1"}},
				},
			},
			wantErr:     true,
			errContains: "spec.authPath is immutable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VaultClusterRoleValidator{}
			_, err := v.ValidateUpdate(context.Background(), tt.oldRole, tt.newRole)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateUpdate() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestVaultClusterRoleValidator_ValidateDelete(t *testing.T) {
	role := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-role",
		},
	}

	v := &VaultClusterRoleValidator{}
	warnings, err := v.ValidateDelete(context.Background(), role)
	if err != nil {
		t.Errorf("ValidateDelete() unexpected error = %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateDelete() unexpected warnings = %v", warnings)
	}
}

func TestValidatePolicyReference(t *testing.T) {
	tests := []struct {
		name                  string
		ref                   vaultv1alpha1.PolicyReference
		index                 int
		allowDefaultNamespace bool
		wantErr               bool
		errContains           string
	}{
		{
			name: "valid VaultPolicy with namespace",
			ref: vaultv1alpha1.PolicyReference{
				Kind:      "VaultPolicy",
				Name:      "my-policy",
				Namespace: "my-namespace",
			},
			index:                 0,
			allowDefaultNamespace: false,
			wantErr:               false,
		},
		{
			name: "valid VaultPolicy without namespace when allowed",
			ref: vaultv1alpha1.PolicyReference{
				Kind: "VaultPolicy",
				Name: "my-policy",
			},
			index:                 0,
			allowDefaultNamespace: true,
			wantErr:               false,
		},
		{
			name: "valid VaultClusterPolicy without namespace",
			ref: vaultv1alpha1.PolicyReference{
				Kind: "VaultClusterPolicy",
				Name: "shared-policy",
			},
			index:                 0,
			allowDefaultNamespace: false,
			wantErr:               false,
		},
		{
			name: "VaultPolicy without namespace when not allowed",
			ref: vaultv1alpha1.PolicyReference{
				Kind: "VaultPolicy",
				Name: "my-policy",
			},
			index:                 0,
			allowDefaultNamespace: false,
			wantErr:               true,
			errContains:           "must be specified for VaultPolicy references in VaultClusterRole",
		},
		{
			name: "VaultClusterPolicy with namespace",
			ref: vaultv1alpha1.PolicyReference{
				Kind:      "VaultClusterPolicy",
				Name:      "shared-policy",
				Namespace: "some-namespace",
			},
			index:                 0,
			allowDefaultNamespace: false,
			wantErr:               true,
			errContains:           "must not be specified for VaultClusterPolicy",
		},
		{
			name: "invalid kind",
			ref: vaultv1alpha1.PolicyReference{
				Kind: "InvalidKind",
				Name: "my-policy",
			},
			index:                 0,
			allowDefaultNamespace: false,
			wantErr:               true,
			errContains:           "must be VaultPolicy or VaultClusterPolicy",
		},
		{
			name: "empty name",
			ref: vaultv1alpha1.PolicyReference{
				Kind: "VaultPolicy",
				Name: "",
			},
			index:                 0,
			allowDefaultNamespace: true,
			wantErr:               true,
			errContains:           "name: must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePolicyReference(tt.ref, tt.index, tt.allowDefaultNamespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePolicyReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("validatePolicyReference() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

// NOTE: Type casting tests removed - with Go generics in controller-runtime v0.23.0,
// type safety is now enforced at compile time, making runtime type assertion tests obsolete.

// ─────────────────────────────────────────────────────────────────────────────
// Naming Collision Detection Tests
// ─────────────────────────────────────────────────────────────────────────────

func newRoleTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	return scheme
}

func TestVaultRoleValidator_CollisionDetection(t *testing.T) {
	tests := []struct {
		name            string
		existingObjects []runtime.Object
		role            *vaultv1alpha1.VaultRole
		wantErr         bool
		errContains     string
	}{
		{
			name:            "no collision when no existing resources",
			existingObjects: []runtime.Object{},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "collision with existing VaultClusterRole",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default-test-role", // Would collide with VaultRole default/test-role
					},
					Spec: vaultv1alpha1.VaultClusterRoleSpec{
						ConnectionRef: "test-connection",
						ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
							{Name: "sa", Namespace: "ns"},
						},
						Policies: []vaultv1alpha1.PolicyReference{
							{Kind: "VaultClusterPolicy", Name: "policy"},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "naming collision",
		},
		{
			name: "no collision with differently named VaultClusterRole",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "other-cluster-role",
					},
					Spec: vaultv1alpha1.VaultClusterRoleSpec{
						ConnectionRef: "test-connection",
						ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
							{Name: "sa", Namespace: "ns"},
						},
						Policies: []vaultv1alpha1.PolicyReference{
							{Kind: "VaultClusterPolicy", Name: "policy"},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "collision with different namespace prefix",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "prod-app-role", // Would collide with VaultRole prod/app-role
					},
					Spec: vaultv1alpha1.VaultClusterRoleSpec{
						ConnectionRef: "test-connection",
						ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
							{Name: "sa", Namespace: "ns"},
						},
						Policies: []vaultv1alpha1.PolicyReference{
							{Kind: "VaultClusterPolicy", Name: "policy"},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-role",
					Namespace: "prod",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-service-account"},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: "my-policy",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "naming collision",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newRoleTestScheme()
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(tt.existingObjects...).
				Build()

			v := &VaultRoleValidator{client: fakeClient}
			_, err := v.ValidateCreate(context.Background(), tt.role)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateCreate() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestVaultClusterRoleValidator_CollisionDetection(t *testing.T) {
	tests := []struct {
		name            string
		existingObjects []runtime.Object
		role            *vaultv1alpha1.VaultClusterRole
		wantErr         bool
		errContains     string
	}{
		{
			name:            "no collision when no existing resources",
			existingObjects: []runtime.Object{},
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{Name: "sa", Namespace: "ns"},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "policy"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "collision with existing VaultRole",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "test-connection",
						ServiceAccounts: []string{"my-service-account"},
						Policies: []vaultv1alpha1.PolicyReference{
							{Kind: "VaultPolicy", Name: "my-policy"},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default-test-role", // Would collide with VaultRole default/test-role
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{Name: "sa", Namespace: "ns"},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "policy"},
					},
				},
			},
			wantErr:     true,
			errContains: "naming collision",
		},
		{
			name: "no collision with differently named VaultRole",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "other-role",
						Namespace: "other-namespace",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "test-connection",
						ServiceAccounts: []string{"my-service-account"},
						Policies: []vaultv1alpha1.PolicyReference{
							{Kind: "VaultPolicy", Name: "my-policy"},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{Name: "sa", Namespace: "ns"},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "policy"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "collision with VaultRole in different namespace",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "app-role",
						Namespace: "prod",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "test-connection",
						ServiceAccounts: []string{"my-service-account"},
						Policies: []vaultv1alpha1.PolicyReference{
							{Kind: "VaultPolicy", Name: "my-policy"},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "prod-app-role", // Would collide with VaultRole prod/app-role
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{Name: "sa", Namespace: "ns"},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "policy"},
					},
				},
			},
			wantErr:     true,
			errContains: "naming collision",
		},
		{
			name: "no collision when multiple VaultRoles exist but none collide",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-a",
						Namespace: "ns-a",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "test-connection",
						ServiceAccounts: []string{"sa"},
						Policies: []vaultv1alpha1.PolicyReference{
							{Kind: "VaultPolicy", Name: "policy"},
						},
					},
				},
				&vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-b",
						Namespace: "ns-b",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "test-connection",
						ServiceAccounts: []string{"sa"},
						Policies: []vaultv1alpha1.PolicyReference{
							{Kind: "VaultPolicy", Name: "policy"},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "global-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{Name: "sa", Namespace: "ns"},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "policy"},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newRoleTestScheme()
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(tt.existingObjects...).
				Build()

			v := &VaultClusterRoleValidator{client: fakeClient}
			_, err := v.ValidateCreate(context.Background(), tt.role)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateCreate() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestVaultRoleValidator_CollisionWithNilClient(t *testing.T) {
	// Test that validation still works when client is nil (skip collision check)
	v := &VaultRoleValidator{client: nil}
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "default",
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "test-connection",
			ServiceAccounts: []string{"my-service-account"},
			Policies: []vaultv1alpha1.PolicyReference{
				{
					Kind: "VaultPolicy",
					Name: "my-policy",
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), role)
	if err != nil {
		t.Errorf("ValidateCreate() with nil client should not error, got: %v", err)
	}
}

func TestVaultClusterRoleValidator_CollisionWithNilClient(t *testing.T) {
	// Test that validation still works when client is nil (skip collision check)
	v := &VaultClusterRoleValidator{client: nil}
	role := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-role",
		},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			ConnectionRef: "test-connection",
			ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "sa", Namespace: "ns"},
			},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultClusterPolicy", Name: "policy"},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), role)
	if err != nil {
		t.Errorf("ValidateCreate() with nil client should not error, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Dependency Validation Tests (P4)
// ─────────────────────────────────────────────────────────────────────────────

func TestVaultRoleValidator_DependencyValidation(t *testing.T) {
	tests := []struct {
		name            string
		existingObjects []runtime.Object
		role            *vaultv1alpha1.VaultRole
		wantErr         bool
		wantWarnings    int
		warningContains string
	}{
		{
			name: "no warning when VaultPolicy exists",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-sa"},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultPolicy", Name: "my-policy"},
					},
				},
			},
			wantErr:      false,
			wantWarnings: 0,
		},
		{
			name:            "warning when VaultPolicy does not exist",
			existingObjects: []runtime.Object{},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-sa"},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultPolicy", Name: "missing-policy"},
					},
				},
			},
			wantErr:         false,
			wantWarnings:    1,
			warningContains: "VaultPolicy default/missing-policy does not exist",
		},
		{
			name:            "warning when VaultClusterPolicy does not exist",
			existingObjects: []runtime.Object{},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-sa"},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "missing-cluster-policy"},
					},
				},
			},
			wantErr:         false,
			wantWarnings:    1,
			warningContains: "VaultClusterPolicy missing-cluster-policy does not exist",
		},
		{
			name: "no warning when VaultClusterPolicy exists",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultClusterPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "shared-policy",
					},
					Spec: vaultv1alpha1.VaultClusterPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-sa"},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "shared-policy"},
					},
				},
			},
			wantErr:      false,
			wantWarnings: 0,
		},
		{
			name:            "multiple warnings for multiple missing policies",
			existingObjects: []runtime.Object{},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-sa"},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultPolicy", Name: "missing-1"},
						{Kind: "VaultClusterPolicy", Name: "missing-2"},
					},
				},
			},
			wantErr:      false,
			wantWarnings: 2,
		},
		{
			name: "warning for missing policy but existing policy has no warning",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-sa"},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultPolicy", Name: "existing-policy"},
						{Kind: "VaultPolicy", Name: "missing-policy"},
					},
				},
			},
			wantErr:         false,
			wantWarnings:    1,
			warningContains: "missing-policy",
		},
		{
			name: "VaultPolicy with explicit namespace",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "other-policy",
						Namespace: "other-ns",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "test-connection",
					ServiceAccounts: []string{"my-sa"},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultPolicy", Name: "other-policy", Namespace: "other-ns"},
					},
				},
			},
			wantErr:      false,
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newRoleTestScheme()
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(tt.existingObjects...).
				Build()

			v := &VaultRoleValidator{client: fakeClient}
			warnings, err := v.ValidateCreate(context.Background(), tt.role)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(warnings) != tt.wantWarnings {
				t.Errorf("ValidateCreate() warnings count = %d, want %d, warnings: %v", len(warnings), tt.wantWarnings, warnings)
				return
			}

			if tt.warningContains != "" && tt.wantWarnings > 0 {
				found := false
				for _, w := range warnings {
					if strings.Contains(w, tt.warningContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ValidateCreate() warnings = %v, want warning containing %q", warnings, tt.warningContains)
				}
			}
		})
	}
}

func TestVaultClusterRoleValidator_DependencyValidation(t *testing.T) {
	tests := []struct {
		name            string
		existingObjects []runtime.Object
		role            *vaultv1alpha1.VaultClusterRole
		wantErr         bool
		wantWarnings    int
		warningContains string
	}{
		{
			name: "no warning when VaultPolicy exists",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-policy",
						Namespace: "my-ns",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{Name: "sa", Namespace: "ns"},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultPolicy", Name: "my-policy", Namespace: "my-ns"},
					},
				},
			},
			wantErr:      false,
			wantWarnings: 0,
		},
		{
			name:            "warning when VaultPolicy does not exist",
			existingObjects: []runtime.Object{},
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{Name: "sa", Namespace: "ns"},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultPolicy", Name: "missing-policy", Namespace: "some-ns"},
					},
				},
			},
			wantErr:         false,
			wantWarnings:    1,
			warningContains: "VaultPolicy some-ns/missing-policy does not exist",
		},
		{
			name:            "warning when VaultClusterPolicy does not exist",
			existingObjects: []runtime.Object{},
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{Name: "sa", Namespace: "ns"},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "missing-cluster-policy"},
					},
				},
			},
			wantErr:         false,
			wantWarnings:    1,
			warningContains: "VaultClusterPolicy missing-cluster-policy does not exist",
		},
		{
			name: "no warning when VaultClusterPolicy exists",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultClusterPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "shared-policy",
					},
					Spec: vaultv1alpha1.VaultClusterPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{Path: "secret/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
						},
					},
				},
			},
			role: &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: "test-connection",
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{Name: "sa", Namespace: "ns"},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "shared-policy"},
					},
				},
			},
			wantErr:      false,
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newRoleTestScheme()
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(tt.existingObjects...).
				Build()

			v := &VaultClusterRoleValidator{client: fakeClient}
			warnings, err := v.ValidateCreate(context.Background(), tt.role)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(warnings) != tt.wantWarnings {
				t.Errorf("ValidateCreate() warnings count = %d, want %d, warnings: %v", len(warnings), tt.wantWarnings, warnings)
				return
			}

			if tt.warningContains != "" && tt.wantWarnings > 0 {
				found := false
				for _, w := range warnings {
					if strings.Contains(w, tt.warningContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ValidateCreate() warnings = %v, want warning containing %q", warnings, tt.warningContains)
				}
			}
		})
	}
}

func TestVaultRoleValidator_DependencyValidationOnUpdate(t *testing.T) {
	// Test that dependency validation also runs on update
	scheme := newRoleTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	v := &VaultRoleValidator{client: fakeClient}

	oldRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "default",
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "test-connection",
			ServiceAccounts: []string{"sa"},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "old-policy"},
			},
		},
	}

	newRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "default",
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "test-connection",
			ServiceAccounts: []string{"sa"},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "new-missing-policy"},
			},
		},
	}

	warnings, err := v.ValidateUpdate(context.Background(), oldRole, newRole)
	if err != nil {
		t.Errorf("ValidateUpdate() unexpected error: %v", err)
	}

	if len(warnings) != 1 {
		t.Errorf("ValidateUpdate() expected 1 warning, got %d: %v", len(warnings), warnings)
	}
}
