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

func TestJWTProvider_Applies(t *testing.T) {
	p := NewJWTProvider(&fakeSecretReader{}, &fakeTokenProvider{})
	if !p.Applies(vaultv1alpha1.AuthConfig{JWT: &vaultv1alpha1.JWTAuth{}}) {
		t.Error("expected Applies true when JWT config set")
	}
	if p.Applies(vaultv1alpha1.AuthConfig{}) {
		t.Error("expected Applies false when JWT config nil")
	}
}

func TestJWTProvider_UsesSecretWhenJWTSecretRefSet(t *testing.T) {
	reader := &fakeSecretReader{data: map[string]string{"ns/jwt-sec/key": "pre-signed-jwt"}}
	p := NewJWTProvider(reader, &fakeTokenProvider{token: "sa-jwt-should-not-be-used"})
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				JWT: &vaultv1alpha1.JWTAuth{
					Role:         "jwt-role",
					AuthPath:     "custom-jwt",
					JWTSecretRef: &vaultv1alpha1.SecretKeySelector{Name: "jwt-sec", Namespace: "ns", Key: "key"},
				},
			},
		},
	}

	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.jwtAuth.jwt != "pre-signed-jwt" {
		t.Errorf("expected secret JWT to be used, got %q", vc.jwtAuth.jwt)
	}
	if vc.jwtAuth.role != "jwt-role" || vc.jwtAuth.mountPath != "custom-jwt" {
		t.Errorf("unexpected auth args: %+v", vc.jwtAuth)
	}
}

func TestJWTProvider_FallsBackToTokenRequestAPI(t *testing.T) {
	p := NewJWTProvider(&fakeSecretReader{}, &fakeTokenProvider{token: "tr-api-jwt"})
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				JWT: &vaultv1alpha1.JWTAuth{Role: "r"},
			},
		},
	}

	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.jwtAuth.jwt != "tr-api-jwt" {
		t.Errorf("expected TokenRequest JWT, got %q", vc.jwtAuth.jwt)
	}
	if vc.jwtAuth.mountPath != "jwt" {
		t.Errorf("expected default mountPath 'jwt', got %q", vc.jwtAuth.mountPath)
	}
}

func TestJWTProvider_RequiresTokenProviderWhenNoSecret(t *testing.T) {
	p := NewJWTProvider(&fakeSecretReader{}, nil)
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{JWT: &vaultv1alpha1.JWTAuth{Role: "r"}},
		},
	}
	err := p.Authenticate(context.Background(), &fakeAuthenticator{}, conn)
	if err == nil || !strings.Contains(err.Error(), "token provider not configured for JWT auth") {
		t.Errorf("expected token-provider error, got %v", err)
	}
}
