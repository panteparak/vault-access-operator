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

// TestVaultRoleValidator_VaultRoleCollision pins the fix for the gap
// where two VaultRoles with ambiguous namespace+name concatenations
// could silently map to the same Vault role. Pre-fix the second CR
// hit runtime Phase=Conflict (confusing for the user — spec is valid,
// just another CR claims the same name); now the webhook rejects at
// `kubectl apply` time with a clear message pointing at the conflicting
// existing CR.
func TestVaultRoleValidator_VaultRoleCollision(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	// Existing role: namespace="my-app", name="foo" → vaultName="my-app-foo"
	existing := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "my-app"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "conn",
			ServiceAccounts: []string{"sa"},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
	v := &VaultRoleValidator{client: c}

	// New role: namespace="my", name="app-foo" → vaultName="my-app-foo" (collision!)
	newRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "app-foo", Namespace: "my"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "conn",
			ServiceAccounts: []string{"sa"},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p"},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), newRole)
	if err == nil {
		t.Fatal("expected collision error, got nil")
	}
	if !strings.Contains(err.Error(), "my-app/foo") {
		t.Errorf("error should name the conflicting existing CR: %v", err)
	}
	if !strings.Contains(err.Error(), "my-app-foo") {
		t.Errorf("error should include the conflicting Vault name: %v", err)
	}
}

// TestVaultRoleValidator_VaultRoleNoSelfCollision confirms that
// updating (or re-validating) the same CR doesn't trigger a false
// positive — the collision check skips the CR being validated itself.
func TestVaultRoleValidator_VaultRoleNoSelfCollision(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "my-app"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "conn",
			ServiceAccounts: []string{"sa"},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p"},
			},
		},
	}
	// The same role exists in the fake client — simulating re-validation.
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(role).Build()
	v := &VaultRoleValidator{client: c}

	_, err := v.ValidateCreate(context.Background(), role)
	if err != nil {
		t.Errorf("self should not collide with self, got %v", err)
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
			// IMPROVEMENTS §36: pre-populate the connectionRef so these tests
			// stay focused on policy dependency warnings.
			existing := append([]runtime.Object{testConnectionStub()}, tt.existingObjects...)
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(existing...).
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
			// IMPROVEMENTS §36: the validator now also warns on missing
			// connectionRef. Pre-populate the referenced VaultConnection so
			// these tests keep focus on their original purpose (policy
			// dependency checks) rather than counting an unrelated warning.
			existing := append([]runtime.Object{testConnectionStub()}, tt.existingObjects...)
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(existing...).
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
	// No test-connection pre-populated: this test already expects 2 warnings
	// (1 missing-policy + 1 missing-connection). The wantWarnings assertion
	// below was updated accordingly.
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

	// Expect 2 warnings: (a) the missing-policy dependency + (b) the new
	// §36 check — "test-connection" doesn't exist in the fake client, so the
	// connectionRef existence check also emits. Both are non-blocking.
	if len(warnings) != 2 {
		t.Errorf("ValidateUpdate() expected 2 warnings (missing policy + missing connection), got %d: %v", len(warnings), warnings)
	}
}

const authPathJWT = "auth/jwt"

func TestIsJWTAuthPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"", false},
		{"auth/kubernetes", false},
		{"auth/kubernetes-prod", false},
		{"auth/jwt", true},
		{"auth/jwt/", true},
		{"auth/jwt/gitlab", true},
		{"auth/jwt-gitlab", true},
		{"auth/approle", false},
		{"jwt", false},
	}
	for _, tc := range cases {
		if got := isJWTAuthPath(tc.path); got != tc.want {
			t.Errorf("isJWTAuthPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestValidateJWTSpec(t *testing.T) {
	cases := []struct {
		name                 string
		authPath             string
		jwt                  *vaultv1alpha1.VaultRoleJWTSpec
		serviceAccountCount  int
		wantErrSubstring     string
		wantWarningSubstring string
		wantNoWarning        bool
	}{
		{
			name:                "non-jwt path with no jwt spec",
			authPath:            "auth/kubernetes",
			serviceAccountCount: 1,
			wantNoWarning:       true,
		},
		{
			name:                "jwt path with single SA, no override",
			authPath:            authPathJWT,
			serviceAccountCount: 1,
			wantNoWarning:       true,
		},
		{
			name:                "jwt path with multi-SA and explicit boundSubject",
			authPath:            authPathJWT,
			jwt:                 &vaultv1alpha1.VaultRoleJWTSpec{BoundSubject: "sub"},
			serviceAccountCount: 3,
			wantNoWarning:       true,
		},
		{
			name:                "jwt path with multi-SA and explicit boundClaims",
			authPath:            authPathJWT,
			jwt:                 &vaultv1alpha1.VaultRoleJWTSpec{BoundClaims: map[string]string{"project_id": "111"}},
			serviceAccountCount: 2,
			wantNoWarning:       true,
		},
		{
			name:                "jwt path with multi-SA and explicit boundClaimsList",
			authPath:            authPathJWT,
			jwt:                 &vaultv1alpha1.VaultRoleJWTSpec{BoundClaimsList: map[string][]string{"project_id": {"111"}}},
			serviceAccountCount: 2,
			wantNoWarning:       true,
		},
		{
			name:                "jwt path with multi-SA, no override, rejected",
			authPath:            authPathJWT,
			serviceAccountCount: 2,
			wantErrSubstring:    "more than one serviceAccount",
		},
		{
			name:                "jwt set but authPath is k8s, rejected",
			authPath:            "auth/kubernetes",
			jwt:                 &vaultv1alpha1.VaultRoleJWTSpec{BoundSubject: "x"},
			serviceAccountCount: 1,
			wantErrSubstring:    "may only be used when authPath targets a JWT auth mount",
		},
		{
			name:                "boundSubject and boundClaims mutually exclusive",
			authPath:            authPathJWT,
			jwt:                 &vaultv1alpha1.VaultRoleJWTSpec{BoundSubject: "x", BoundClaims: map[string]string{"project_id": "111"}},
			serviceAccountCount: 1,
			wantErrSubstring:    "mutually exclusive",
		},
		{
			name:                "boundSubject and boundClaimsList mutually exclusive",
			authPath:            authPathJWT,
			jwt:                 &vaultv1alpha1.VaultRoleJWTSpec{BoundSubject: "x", BoundClaimsList: map[string][]string{"project_id": {"111"}}},
			serviceAccountCount: 1,
			wantErrSubstring:    "mutually exclusive",
		},
		{
			name:     "ref bound without ref_type warns",
			authPath: authPathJWT,
			jwt: &vaultv1alpha1.VaultRoleJWTSpec{
				BoundClaimsList: map[string][]string{
					"project_id":    {"111"},
					"ref":           {"develop"},
					"ref_protected": {"true"},
				},
			},
			serviceAccountCount:  1,
			wantWarningSubstring: "without 'ref_type'",
		},
		{
			name:     "ref bound without ref_protected warns",
			authPath: authPathJWT,
			jwt: &vaultv1alpha1.VaultRoleJWTSpec{
				BoundClaimsList: map[string][]string{
					"project_id": {"111"},
					"ref":        {"develop"},
					"ref_type":   {"branch"},
				},
			},
			serviceAccountCount:  1,
			wantWarningSubstring: "without 'ref_protected'",
		},
		{
			name:     "fully-pinned ref binding emits no warnings",
			authPath: authPathJWT,
			jwt: &vaultv1alpha1.VaultRoleJWTSpec{
				BoundClaimsList: map[string][]string{
					"project_id":    {"111"},
					"ref":           {"develop"},
					"ref_type":      {"branch"},
					"ref_protected": {"true"},
				},
			},
			serviceAccountCount: 1,
			wantNoWarning:       true,
		},
		{
			name:     "boundClaimsType without claims warns",
			authPath: authPathJWT,
			jwt: &vaultv1alpha1.VaultRoleJWTSpec{
				BoundClaimsType: "glob",
				BoundSubject:    "sub",
			},
			serviceAccountCount:  1,
			wantWarningSubstring: "no effect without",
		},
		{
			name:     "duplicate key in boundClaims and boundClaimsList warns",
			authPath: authPathJWT,
			jwt: &vaultv1alpha1.VaultRoleJWTSpec{
				BoundClaims:     map[string]string{"project_id": "stale"},
				BoundClaimsList: map[string][]string{"project_id": {"111"}},
			},
			serviceAccountCount:  1,
			wantWarningSubstring: "overridden by spec.jwt.boundClaimsList",
		},
		{
			name:     "boundClaims-only (no ref) emits no warnings",
			authPath: authPathJWT,
			jwt: &vaultv1alpha1.VaultRoleJWTSpec{
				BoundClaimsList: map[string][]string{"project_id": {"111"}},
			},
			serviceAccountCount: 1,
			wantNoWarning:       true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warnings, errs := validateJWTSpec(tc.authPath, tc.jwt, tc.serviceAccountCount)
			if tc.wantErrSubstring == "" {
				if len(errs) > 0 {
					t.Errorf("expected no errors, got %v", errs)
				}
			} else {
				if len(errs) == 0 {
					t.Fatalf("expected error containing %q, got none", tc.wantErrSubstring)
				}
				if !strings.Contains(strings.Join(errs, "; "), tc.wantErrSubstring) {
					t.Errorf("expected error containing %q, got %v", tc.wantErrSubstring, errs)
				}
			}
			if tc.wantNoWarning && len(warnings) > 0 {
				t.Errorf("expected no warnings, got %v", warnings)
			}
			if tc.wantWarningSubstring != "" {
				if len(warnings) == 0 {
					t.Fatalf("expected warning containing %q, got none", tc.wantWarningSubstring)
				}
				if !strings.Contains(strings.Join(warnings, "; "), tc.wantWarningSubstring) {
					t.Errorf("expected warning containing %q, got %v", tc.wantWarningSubstring, warnings)
				}
			}
		})
	}
}

func TestVaultRoleValidator_ValidateCreate_JWT(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	v := &VaultRoleValidator{client: client}

	cases := []struct {
		name        string
		role        *vaultv1alpha1.VaultRole
		wantErr     bool
		errContains string
	}{
		{
			name: "jwt single SA",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "ns"},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "c",
					AuthPath:        authPathJWT,
					ServiceAccounts: []string{"sa1"},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultClusterPolicy", Name: "p"}},
				},
			},
		},
		{
			name: "jwt multi SA without override rejected",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{Name: "r2", Namespace: "ns"},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "c",
					AuthPath:        authPathJWT,
					ServiceAccounts: []string{"sa1", "sa2"},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultClusterPolicy", Name: "p"}},
				},
			},
			wantErr:     true,
			errContains: "more than one serviceAccount",
		},
		{
			name: "jwt sub-spec with k8s auth path rejected",
			role: &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{Name: "r3", Namespace: "ns"},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "c",
					AuthPath:        "auth/kubernetes",
					ServiceAccounts: []string{"sa1"},
					Policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultClusterPolicy", Name: "p"}},
					JWT:             &vaultv1alpha1.VaultRoleJWTSpec{BoundSubject: "x"},
				},
			},
			wantErr:     true,
			errContains: "may only be used when authPath",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.ValidateCreate(ctx, tc.role)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateAuthPathSupported pins IMPROVEMENTS §7: the webhook must
// reject VaultRole CRs whose authPath targets a Vault auth backend the
// role handler doesn't implement (aws/gcp/approle/ldap/etc.), while still
// accepting all the forms that appear in our docs and fixtures:
//   - empty (defaults to auth/kubernetes)
//   - bare mount name: "kubernetes", "jwt"
//   - full form: "auth/kubernetes", "auth/jwt"
//   - submounts: "auth/kubernetes-prod", "auth/jwt/gitlab"
func TestValidateAuthPathSupported(t *testing.T) {
	cases := []struct {
		name             string
		authPath         string
		wantErrSubstring string // empty means expect accept
	}{
		{name: "empty defaults to kubernetes", authPath: ""},
		{name: "bare kubernetes (docs form)", authPath: "kubernetes"},
		{name: "bare jwt (docs form)", authPath: "jwt"},
		{name: "full kubernetes path", authPath: "auth/kubernetes"},
		{name: "full jwt path", authPath: "auth/jwt"},
		{name: "kubernetes submount", authPath: "auth/kubernetes-prod"},
		{name: "jwt submount", authPath: "auth/jwt/gitlab"},
		{name: "jwt path with trailing slash", authPath: "auth/jwt/"},
		{
			name:             "aws backend rejected",
			authPath:         "auth/aws",
			wantErrSubstring: "unsupported Vault auth backend",
		},
		{
			name:             "gcp backend rejected",
			authPath:         "auth/gcp",
			wantErrSubstring: "unsupported Vault auth backend",
		},
		{
			name:             "approle backend rejected",
			authPath:         "auth/approle",
			wantErrSubstring: "unsupported Vault auth backend",
		},
		{
			name:             "ldap backend rejected",
			authPath:         "auth/ldap",
			wantErrSubstring: "unsupported Vault auth backend",
		},
		{
			name:             "bare aws rejected",
			authPath:         "aws",
			wantErrSubstring: "unsupported Vault auth backend",
		},
		{
			name:             "§7 roadmap reference present in rejection",
			authPath:         "auth/approle",
			wantErrSubstring: "IMPROVEMENTS.md §7",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := validateAuthPathSupported(tc.authPath)
			if tc.wantErrSubstring == "" {
				if got != "" {
					t.Errorf("validateAuthPathSupported(%q) = %q, want accept", tc.authPath, got)
				}
				return
			}
			if !strings.Contains(got, tc.wantErrSubstring) {
				t.Errorf("validateAuthPathSupported(%q) = %q, want error containing %q",
					tc.authPath, got, tc.wantErrSubstring)
			}
		})
	}
}

// TestValidateDiscoveryPlaceholderConsistency pins the F4 fix from
// the parallel features audit. Discovery auto-creates a CR with
// `discovery-placeholder-replace-me` in spec.serviceAccounts/policies
// AND a `vault.platform.io/discovery-pending=true` annotation. The
// pair is transactional — clearing the annotation while leaving the
// placeholder would push the literal placeholder string to Vault as
// an SA name, producing a Vault role bound to a non-existent SA.
func TestValidateDiscoveryPlaceholderConsistency(t *testing.T) {
	pendingAnnotation := map[string]string{
		vaultv1alpha1.AnnotationDiscoveryPending: vaultv1alpha1.AnnotationValueTrue,
	}
	cases := []struct {
		name             string
		annotations      map[string]string
		serviceAccounts  []string
		policies         []vaultv1alpha1.PolicyReference
		wantErrSubstring string // empty means valid
	}{
		{
			name:            "no placeholder, no annotation — valid (normal CR)",
			serviceAccounts: []string{"my-app"},
			policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p1"}},
		},
		{
			name:            "placeholder + pending annotation — valid (discovery state)",
			annotations:     pendingAnnotation,
			serviceAccounts: []string{vaultv1alpha1.DiscoveryPlaceholderValue},
			policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: vaultv1alpha1.DiscoveryPlaceholderValue},
			},
		},
		{
			name:             "placeholder SA without annotation — REJECTED",
			serviceAccounts:  []string{vaultv1alpha1.DiscoveryPlaceholderValue},
			policies:         []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p1"}},
			wantErrSubstring: "discovery placeholder",
		},
		{
			name:            "placeholder policy without annotation — REJECTED",
			serviceAccounts: []string{"my-app"},
			policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: vaultv1alpha1.DiscoveryPlaceholderValue},
			},
			wantErrSubstring: "discovery placeholder",
		},
		{
			name:            "real values + pending annotation — valid (mid-adoption)",
			annotations:     pendingAnnotation,
			serviceAccounts: []string{"real-sa"},
			policies:        []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "real-policy"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateDiscoveryPlaceholderConsistency(
				tc.annotations, tc.serviceAccounts, tc.policies)
			if tc.wantErrSubstring == "" {
				if got != "" {
					t.Errorf("expected no error, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantErrSubstring) {
				t.Errorf("expected error containing %q, got %q", tc.wantErrSubstring, got)
			}
		})
	}
}
