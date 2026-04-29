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

package authprovider

import (
	"context"
	"strings"
	"testing"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

func TestOIDCProvider_Applies(t *testing.T) {
	p := NewOIDCProvider(&fakeSecretReader{}, &fakeTokenProvider{})
	if !p.Applies(vaultv1alpha1.AuthConfig{OIDC: &vaultv1alpha1.OIDCAuth{}}) {
		t.Error("expected Applies true")
	}
	if p.Applies(vaultv1alpha1.AuthConfig{}) {
		t.Error("expected Applies false")
	}
}

func TestOIDCProvider_UsesSecretWhenSet(t *testing.T) {
	reader := &fakeSecretReader{data: map[string]string{"ns/oidc-sec/key": "external-oidc-jwt"}}
	p := NewOIDCProvider(reader, &fakeTokenProvider{})
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				OIDC: &vaultv1alpha1.OIDCAuth{
					Role:         "oidc-role",
					AuthPath:     "custom-oidc",
					JWTSecretRef: &vaultv1alpha1.SecretKeySelector{Name: "oidc-sec", Namespace: "ns", Key: "key"},
				},
			},
		},
	}

	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.oidcAuth.jwt != "external-oidc-jwt" {
		t.Errorf("expected external JWT, got %q", vc.oidcAuth.jwt)
	}
}

func TestOIDCProvider_FallsBackToServiceAccountTokenByDefault(t *testing.T) {
	p := NewOIDCProvider(&fakeSecretReader{}, &fakeTokenProvider{token: "sa-oidc-jwt"})
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				OIDC: &vaultv1alpha1.OIDCAuth{Role: "r", ProviderURL: "https://issuer.example/oidc"},
			},
		},
	}
	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.oidcAuth.jwt != "sa-oidc-jwt" || vc.oidcAuth.mountPath != "oidc" {
		t.Errorf("unexpected auth args: %+v", vc.oidcAuth)
	}
}

func TestOIDCProvider_ExplicitlyDisabledSATokenErrors(t *testing.T) {
	useSA := false
	p := NewOIDCProvider(&fakeSecretReader{}, &fakeTokenProvider{token: "should-not-be-used"})
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				OIDC: &vaultv1alpha1.OIDCAuth{Role: "r", UseServiceAccountToken: &useSA},
			},
		},
	}
	err := p.Authenticate(context.Background(), &fakeAuthenticator{}, conn)
	const wantMsg = "OIDC auth requires either jwtSecretRef or useServiceAccountToken=true"
	if err == nil || !strings.Contains(err.Error(), wantMsg) {
		t.Errorf("expected OIDC-config error, got %v", err)
	}
}
