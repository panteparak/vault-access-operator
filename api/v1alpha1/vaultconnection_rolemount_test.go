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

package v1alpha1

import (
	"strings"
	"testing"
)

func TestRoleMount(t *testing.T) {
	tests := []struct {
		name        string
		auth        AuthConfig
		defaults    *ConnectionDefaults
		wantMount   string
		wantFamily  AuthBackendType
		wantErrPart string // substring the error must contain; "" = no error
	}{
		{
			name:       "kubernetes login, schema default mount",
			auth:       AuthConfig{Kubernetes: &KubernetesAuth{Role: "op"}},
			wantMount:  "kubernetes",
			wantFamily: AuthBackendTypeKubernetes,
		},
		{
			name:       "kubernetes login, custom mount",
			auth:       AuthConfig{Kubernetes: &KubernetesAuth{Role: "op", AuthPath: "kubernetes-pe"}},
			wantMount:  "kubernetes-pe",
			wantFamily: AuthBackendTypeKubernetes,
		},
		{
			name:       "kubernetes login, auth/-prefixed mount tolerated",
			auth:       AuthConfig{Kubernetes: &KubernetesAuth{Role: "op", AuthPath: "auth/k8s-prod"}},
			wantMount:  "k8s-prod",
			wantFamily: AuthBackendTypeKubernetes,
		},
		{
			name:       "jwt login inherits jwt family regardless of mount name",
			auth:       AuthConfig{JWT: &JWTAuth{Role: "op", AuthPath: "ep-digital-pe"}},
			wantMount:  "ep-digital-pe",
			wantFamily: AuthBackendTypeJWT,
		},
		{
			name:       "jwt login, schema default mount",
			auth:       AuthConfig{JWT: &JWTAuth{Role: "op"}},
			wantMount:  "jwt",
			wantFamily: AuthBackendTypeJWT,
		},
		{
			name:       "oidc login is jwt family",
			auth:       AuthConfig{OIDC: &OIDCAuth{Role: "op"}},
			wantMount:  "oidc",
			wantFamily: AuthBackendTypeJWT,
		},
		{
			name:       "bootstrap+kubernetes pair uses kubernetes",
			auth:       AuthConfig{Bootstrap: &BootstrapAuth{}, Kubernetes: &KubernetesAuth{Role: "op"}},
			wantMount:  "kubernetes",
			wantFamily: AuthBackendTypeKubernetes,
		},
		{
			name:       "defaults.authPath overrides the login mount",
			auth:       AuthConfig{JWT: &JWTAuth{Role: "op", AuthPath: "ep-digital-pe"}},
			defaults:   &ConnectionDefaults{AuthPath: "kubernetes-pe"},
			wantMount:  "kubernetes-pe",
			wantFamily: AuthBackendTypeKubernetes,
		},
		{
			name:       "defaults.authPath with explicit family for custom name",
			auth:       AuthConfig{Token: &TokenAuth{}},
			defaults:   &ConnectionDefaults{AuthPath: "custom-oidc", AuthType: AuthBackendTypeJWT},
			wantMount:  "custom-oidc",
			wantFamily: AuthBackendTypeJWT,
		},
		{
			name:       "defaults.authPath jwt name heuristic with separator",
			auth:       AuthConfig{Token: &TokenAuth{}},
			defaults:   &ConnectionDefaults{AuthPath: "jwt-gitlab"},
			wantMount:  "jwt-gitlab",
			wantFamily: AuthBackendTypeJWT,
		},
		{
			name:       "defaults.authPath auth/-prefixed tolerated",
			auth:       AuthConfig{Token: &TokenAuth{}},
			defaults:   &ConnectionDefaults{AuthPath: "auth/kubernetes"},
			wantMount:  "kubernetes",
			wantFamily: AuthBackendTypeKubernetes,
		},
		{
			name:        "defaults.authPath no-separator name is not silently classified",
			auth:        AuthConfig{Token: &TokenAuth{}},
			defaults:    &ConnectionDefaults{AuthPath: "kubernetestest"},
			wantErrPart: "defaults.authType",
		},
		{
			name:        "defaults.authPath custom name without authType errors",
			auth:        AuthConfig{Kubernetes: &KubernetesAuth{Role: "op"}},
			defaults:    &ConnectionDefaults{AuthPath: "my-mount"},
			wantErrPart: "defaults.authType",
		},
		{
			name:        "token login without defaults has no role mount",
			auth:        AuthConfig{Token: &TokenAuth{}},
			wantErrPart: "token",
		},
		{
			name:        "appRole login without defaults has no role mount",
			auth:        AuthConfig{AppRole: &AppRoleAuth{}},
			wantErrPart: "appRole",
		},
		{
			name:        "aws login without defaults has no role mount",
			auth:        AuthConfig{AWS: &AWSAuth{}},
			wantErrPart: "aws",
		},
		{
			name:        "gcp login without defaults has no role mount",
			auth:        AuthConfig{GCP: &GCPAuth{}},
			wantErrPart: "gcp",
		},
		{
			name:        "bootstrap-only has no role mount",
			auth:        AuthConfig{Bootstrap: &BootstrapAuth{}},
			wantErrPart: "bootstrap",
		},
		{
			name:       "empty defaults block falls through to login mount",
			auth:       AuthConfig{Kubernetes: &KubernetesAuth{Role: "op", AuthPath: "k8s"}},
			defaults:   &ConnectionDefaults{DriftMode: DriftModeDetect},
			wantMount:  "k8s",
			wantFamily: AuthBackendTypeKubernetes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &VaultConnection{Spec: VaultConnectionSpec{Auth: tt.auth, Defaults: tt.defaults}}
			mount, family, err := conn.RoleMount()

			if tt.wantErrPart != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got mount=%q family=%q", tt.wantErrPart, mount, family)
				}
				if !strings.Contains(err.Error(), tt.wantErrPart) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErrPart)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mount != tt.wantMount {
				t.Errorf("mount: got %q, want %q", mount, tt.wantMount)
			}
			if family != tt.wantFamily {
				t.Errorf("family: got %q, want %q", family, tt.wantFamily)
			}
		})
	}
}
