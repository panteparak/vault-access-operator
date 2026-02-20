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

func TestVaultPolicyValidator_ValidateCreate(t *testing.T) {
	enforceTrue := true
	enforceFalse := false

	tests := []struct {
		name        string
		policy      *vaultv1alpha1.VaultPolicy
		wantErr     bool
		errContains string
	}{
		{
			name: "valid policy with namespace variable",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/{{namespace}}/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid policy with multiple rules",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/{{namespace}}/app1/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead, vaultv1alpha1.CapabilityList},
						},
						{
							Path:         "secret/metadata/{{namespace}}/app1/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid policy with all capabilities",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
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
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid policy without namespace enforcement",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/myapp/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid path syntax with special characters",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/myapp/$invalid",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "contains invalid characters",
		},
		{
			name: "invalid path syntax with spaces",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/my app",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "contains invalid characters",
		},
		{
			name: "invalid capability",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/myapp/*",
							Capabilities: []vaultv1alpha1.Capability{"invalid"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "invalid capability",
		},
		{
			name: "empty capabilities",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/myapp/*",
							Capabilities: []vaultv1alpha1.Capability{},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "at least one capability is required",
		},
		{
			name: "namespace boundary enforcement - path without namespace variable",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/myapp/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "must contain {{namespace}}",
		},
		{
			name: "namespace boundary enforcement - default disabled allows path without namespace variable",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: "test-connection",
					// EnforceNamespaceBoundary defaults to false
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/myapp/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "wildcard before namespace variable is rejected",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*/{{namespace}}/secrets",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "contains wildcard (*) before {{namespace}}",
		},
		{
			name: "wildcard after namespace variable is allowed",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/{{namespace}}/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty path is rejected",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "path cannot be empty",
		},
		{
			name: "whitespace-only path is rejected",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "   ",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "path cannot be empty",
		},
		{
			name: "valid path with plus sign",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/{{namespace}}/app+name",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid path with hyphen",
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/{{namespace}}/my-app",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VaultPolicyValidator{}
			_, err := v.ValidateCreate(context.Background(), tt.policy)
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

func TestVaultPolicyValidator_ValidateUpdate(t *testing.T) {
	enforceTrue := true

	tests := []struct {
		name        string
		oldPolicy   *vaultv1alpha1.VaultPolicy
		newPolicy   *vaultv1alpha1.VaultPolicy
		wantErr     bool
		errContains string
	}{
		{
			name: "valid update",
			oldPolicy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/{{namespace}}/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			newPolicy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/{{namespace}}/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead, vaultv1alpha1.CapabilityList},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid update with bad path",
			oldPolicy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/{{namespace}}/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			newPolicy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceTrue,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*/{{namespace}}/secrets",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "contains wildcard (*) before {{namespace}}",
		},
		{
			name: "connectionRef changed (immutable)",
			oldPolicy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: "old-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{Path: "secret/data/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
					},
				},
			},
			newPolicy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: "new-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{Path: "secret/data/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
					},
				},
			},
			wantErr:     true,
			errContains: "spec.connectionRef is immutable",
		},
		{
			name: "connectionRef unchanged (allowed)",
			oldPolicy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: "same-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{Path: "secret/data/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
					},
				},
			},
			newPolicy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: "same-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{Path: "secret/data/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead, vaultv1alpha1.CapabilityList}},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VaultPolicyValidator{}
			_, err := v.ValidateUpdate(context.Background(), tt.oldPolicy, tt.newPolicy)
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

func TestVaultPolicyValidator_ValidateDelete(t *testing.T) {
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	v := &VaultPolicyValidator{}
	warnings, err := v.ValidateDelete(context.Background(), policy)
	if err != nil {
		t.Errorf("ValidateDelete() unexpected error = %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateDelete() unexpected warnings = %v", warnings)
	}
}

func TestVaultClusterPolicyValidator_ValidateCreate(t *testing.T) {
	tests := []struct {
		name        string
		policy      *vaultv1alpha1.VaultClusterPolicy
		wantErr     bool
		errContains string
	}{
		{
			name: "valid cluster policy without namespace variable",
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/shared/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid cluster policy with multiple capabilities",
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path: "secret/data/shared/*",
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityCreate,
								vaultv1alpha1.CapabilityRead,
								vaultv1alpha1.CapabilityUpdate,
								vaultv1alpha1.CapabilityDelete,
								vaultv1alpha1.CapabilityList,
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "cluster policy does not require namespace boundary",
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/admin/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "cluster policy with namespace variable is also valid",
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/{{namespace}}/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "cluster policy with wildcard before namespace is allowed (no namespace enforcement)",
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*/{{namespace}}/secrets",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid path syntax in cluster policy",
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/$invalid",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "contains invalid characters",
		},
		{
			name: "invalid capability in cluster policy",
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/shared/*",
							Capabilities: []vaultv1alpha1.Capability{"execute"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "invalid capability",
		},
		{
			name: "empty capabilities in cluster policy",
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/shared/*",
							Capabilities: []vaultv1alpha1.Capability{},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "at least one capability is required",
		},
		{
			name: "empty path in cluster policy",
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "path cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VaultClusterPolicyValidator{}
			_, err := v.ValidateCreate(context.Background(), tt.policy)
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

func TestVaultClusterPolicyValidator_ValidateUpdate(t *testing.T) {
	tests := []struct {
		name        string
		oldPolicy   *vaultv1alpha1.VaultClusterPolicy
		newPolicy   *vaultv1alpha1.VaultClusterPolicy
		wantErr     bool
		errContains string
	}{
		{
			name: "valid update",
			oldPolicy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/shared/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			newPolicy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/shared/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead, vaultv1alpha1.CapabilityList},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid update with bad capability",
			oldPolicy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/shared/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			newPolicy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/shared/*",
							Capabilities: []vaultv1alpha1.Capability{"invalid"},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "invalid capability",
		},
		{
			name: "connectionRef changed (immutable)",
			oldPolicy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-policy"},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "old-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{Path: "secret/data/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
					},
				},
			},
			newPolicy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-policy"},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "new-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{Path: "secret/data/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
					},
				},
			},
			wantErr:     true,
			errContains: "spec.connectionRef is immutable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VaultClusterPolicyValidator{}
			_, err := v.ValidateUpdate(context.Background(), tt.oldPolicy, tt.newPolicy)
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

func TestVaultClusterPolicyValidator_ValidateDelete(t *testing.T) {
	policy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-policy",
		},
	}

	v := &VaultClusterPolicyValidator{}
	warnings, err := v.ValidateDelete(context.Background(), policy)
	if err != nil {
		t.Errorf("ValidateDelete() unexpected error = %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateDelete() unexpected warnings = %v", warnings)
	}
}

func TestValidatePolicyRule(t *testing.T) {
	tests := []struct {
		name                     string
		rule                     vaultv1alpha1.PolicyRule
		index                    int
		enforceNamespaceBoundary bool
		wantErrors               bool
		errContains              string
		wantWarnings             bool
	}{
		{
			name: "valid rule with namespace",
			rule: vaultv1alpha1.PolicyRule{
				Path:         "secret/data/{{namespace}}/*",
				Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
			},
			index:                    0,
			enforceNamespaceBoundary: true,
			wantErrors:               false,
		},
		{
			name: "deny with other capabilities produces warning",
			rule: vaultv1alpha1.PolicyRule{
				Path:         "secret/data/{{namespace}}/*",
				Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityDeny, vaultv1alpha1.CapabilityRead},
			},
			index:                    0,
			enforceNamespaceBoundary: true,
			wantErrors:               false,
			wantWarnings:             true,
		},
		{
			name: "deny capability alone is valid",
			rule: vaultv1alpha1.PolicyRule{
				Path:         "secret/data/{{namespace}}/restricted/*",
				Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityDeny},
			},
			index:                    0,
			enforceNamespaceBoundary: true,
			wantErrors:               false,
			wantWarnings:             false,
		},
		{
			name: "sudo capability is valid",
			rule: vaultv1alpha1.PolicyRule{
				Path:         "secret/data/{{namespace}}/admin/*",
				Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilitySudo, vaultv1alpha1.CapabilityRead},
			},
			index:                    0,
			enforceNamespaceBoundary: true,
			wantErrors:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors, warnings := validatePolicyRule(tt.rule, tt.index, tt.enforceNamespaceBoundary)
			if (len(errors) > 0) != tt.wantErrors {
				t.Errorf("validatePolicyRule() errors = %v, wantErrors %v", errors, tt.wantErrors)
			}
			if tt.wantErrors && tt.errContains != "" {
				found := false
				for _, e := range errors {
					if strings.Contains(e, tt.errContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("validatePolicyRule() errors = %v, want error containing %q", errors, tt.errContains)
				}
			}
			if (len(warnings) > 0) != tt.wantWarnings {
				t.Errorf("validatePolicyRule() warnings = %v, wantWarnings %v", warnings, tt.wantWarnings)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid simple path",
			path:    "secret/data/myapp",
			wantErr: false,
		},
		{
			name:    "valid path with wildcard",
			path:    "secret/data/myapp/*",
			wantErr: false,
		},
		{
			name:    "valid path with namespace variable",
			path:    "secret/data/{{namespace}}/myapp",
			wantErr: false,
		},
		{
			name:    "valid path with underscore",
			path:    "secret/data/my_app",
			wantErr: false,
		},
		{
			name:    "valid path with hyphen",
			path:    "secret/data/my-app",
			wantErr: false,
		},
		{
			name:    "valid path with plus",
			path:    "secret/data/app+name",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "path with spaces",
			path:    "secret/data/my app",
			wantErr: true,
		},
		{
			name:    "path with dollar sign",
			path:    "secret/data/$myapp",
			wantErr: true,
		},
		{
			name:    "path with at sign",
			path:    "secret/data/@myapp",
			wantErr: true,
		},
		{
			name:    "path with exclamation mark",
			path:    "secret/data/myapp!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCapability(t *testing.T) {
	tests := []struct {
		name       string
		capability vaultv1alpha1.Capability
		wantErr    bool
	}{
		{
			name:       "valid create",
			capability: vaultv1alpha1.CapabilityCreate,
			wantErr:    false,
		},
		{
			name:       "valid read",
			capability: vaultv1alpha1.CapabilityRead,
			wantErr:    false,
		},
		{
			name:       "valid update",
			capability: vaultv1alpha1.CapabilityUpdate,
			wantErr:    false,
		},
		{
			name:       "valid delete",
			capability: vaultv1alpha1.CapabilityDelete,
			wantErr:    false,
		},
		{
			name:       "valid list",
			capability: vaultv1alpha1.CapabilityList,
			wantErr:    false,
		},
		{
			name:       "valid sudo",
			capability: vaultv1alpha1.CapabilitySudo,
			wantErr:    false,
		},
		{
			name:       "valid deny",
			capability: vaultv1alpha1.CapabilityDeny,
			wantErr:    false,
		},
		{
			name:       "invalid capability",
			capability: "execute",
			wantErr:    true,
		},
		{
			name:       "invalid empty capability",
			capability: "",
			wantErr:    true,
		},
		{
			name:       "invalid uppercase capability",
			capability: "READ",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCapability(tt.capability)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCapability() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsValidCapability(t *testing.T) {
	tests := []struct {
		name       string
		capability vaultv1alpha1.Capability
		want       bool
	}{
		{
			name:       "valid create",
			capability: vaultv1alpha1.CapabilityCreate,
			want:       true,
		},
		{
			name:       "valid read",
			capability: vaultv1alpha1.CapabilityRead,
			want:       true,
		},
		{
			name:       "invalid capability",
			capability: "invalid",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidCapability(tt.capability); got != tt.want {
				t.Errorf("IsValidCapability() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateNoWildcardBeforeNamespace(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		index       int
		wantErr     bool
		errContains string
	}{
		{
			name:    "no namespace variable",
			path:    "secret/data/myapp/*",
			index:   0,
			wantErr: false,
		},
		{
			name:    "namespace variable without wildcard before",
			path:    "secret/data/{{namespace}}/myapp",
			index:   0,
			wantErr: false,
		},
		{
			name:    "wildcard after namespace variable",
			path:    "secret/data/{{namespace}}/*",
			index:   0,
			wantErr: false,
		},
		{
			name:        "wildcard before namespace variable",
			path:        "secret/data/*/{{namespace}}/secrets",
			index:       0,
			wantErr:     true,
			errContains: "contains wildcard (*) before {{namespace}}",
		},
		{
			name:        "wildcard at start before namespace variable",
			path:        "*/{{namespace}}/secrets",
			index:       0,
			wantErr:     true,
			errContains: "contains wildcard (*) before {{namespace}}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateNoWildcardBeforeNamespace(tt.path, tt.index)
			hasErr := result != ""
			if hasErr != tt.wantErr {
				t.Errorf("validateNoWildcardBeforeNamespace() = %q, wantErr %v", result, tt.wantErr)
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(result, tt.errContains) {
					t.Errorf("validateNoWildcardBeforeNamespace() = %q, want containing %q", result, tt.errContains)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Naming Collision Detection Tests
// ─────────────────────────────────────────────────────────────────────────────

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	return scheme
}

func TestVaultPolicyValidator_CollisionDetection(t *testing.T) {
	enforceFalse := false

	tests := []struct {
		name            string
		existingObjects []runtime.Object
		policy          *vaultv1alpha1.VaultPolicy
		wantErr         bool
		errContains     string
	}{
		{
			name:            "no collision when no existing resources",
			existingObjects: []runtime.Object{},
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "collision with existing VaultClusterPolicy",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultClusterPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default-test-policy", // Would collide with VaultPolicy default/test-policy
					},
					Spec: vaultv1alpha1.VaultClusterPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				},
			},
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "naming collision",
		},
		{
			name: "no collision with differently named VaultClusterPolicy",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultClusterPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "other-cluster-policy", // Different name, no collision
					},
					Spec: vaultv1alpha1.VaultClusterPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				},
			},
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "collision with different namespace prefix",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultClusterPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "prod-app-secrets", // Would collide with VaultPolicy prod/app-secrets
					},
					Spec: vaultv1alpha1.VaultClusterPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				},
			},
			policy: &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-secrets",
					Namespace: "prod",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef:            "test-connection",
					EnforceNamespaceBoundary: &enforceFalse,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
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
			scheme := newTestScheme()
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(tt.existingObjects...).
				Build()

			v := &VaultPolicyValidator{client: fakeClient}
			_, err := v.ValidateCreate(context.Background(), tt.policy)

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

func TestVaultClusterPolicyValidator_CollisionDetection(t *testing.T) {
	tests := []struct {
		name            string
		existingObjects []runtime.Object
		policy          *vaultv1alpha1.VaultClusterPolicy
		wantErr         bool
		errContains     string
	}{
		{
			name:            "no collision when no existing resources",
			existingObjects: []runtime.Object{},
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "collision with existing VaultPolicy",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				},
			},
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default-test-policy", // Would collide with VaultPolicy default/test-policy
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "naming collision",
		},
		{
			name: "no collision with differently named VaultPolicy",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "other-policy",
						Namespace: "other-namespace",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				},
			},
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "collision with VaultPolicy in different namespace",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "app-secrets",
						Namespace: "prod",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				},
			},
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "prod-app-secrets", // Would collide with VaultPolicy prod/app-secrets
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "naming collision",
		},
		{
			name: "no collision when multiple VaultPolicies exist but none collide",
			existingObjects: []runtime.Object{
				&vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-a",
						Namespace: "ns-a",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				},
				&vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-b",
						Namespace: "ns-b",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "test-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				},
			},
			policy: &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "global-policy",
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: "test-connection",
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newTestScheme()
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(tt.existingObjects...).
				Build()

			v := &VaultClusterPolicyValidator{client: fakeClient}
			_, err := v.ValidateCreate(context.Background(), tt.policy)

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

func TestVaultPolicyValidator_CollisionWithNilClient(t *testing.T) {
	enforceFalse := false
	// Test that validation still works when client is nil (skip collision check)
	v := &VaultPolicyValidator{client: nil}
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:            "test-connection",
			EnforceNamespaceBoundary: &enforceFalse,
			Rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/*",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), policy)
	if err != nil {
		t.Errorf("ValidateCreate() with nil client should not error, got: %v", err)
	}
}

func TestVaultClusterPolicyValidator_CollisionWithNilClient(t *testing.T) {
	// Test that validation still works when client is nil (skip collision check)
	v := &VaultClusterPolicyValidator{client: nil}
	policy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-policy",
		},
		Spec: vaultv1alpha1.VaultClusterPolicySpec{
			ConnectionRef: "test-connection",
			Rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/*",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), policy)
	if err != nil {
		t.Errorf("ValidateCreate() with nil client should not error, got: %v", err)
	}
}
