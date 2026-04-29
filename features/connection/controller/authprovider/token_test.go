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
	"errors"
	"strings"
	"testing"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

func TestTokenProvider_AppliesWhenTokenConfigured(t *testing.T) {
	p := NewTokenProvider(&fakeSecretReader{})
	auth := vaultv1alpha1.AuthConfig{Token: &vaultv1alpha1.TokenAuth{}}
	if !p.Applies(auth) {
		t.Error("expected Applies to be true when Token config is set")
	}
}

func TestTokenProvider_DoesNotApplyWithoutTokenConfig(t *testing.T) {
	p := NewTokenProvider(&fakeSecretReader{})
	if p.Applies(vaultv1alpha1.AuthConfig{}) {
		t.Error("expected Applies to be false when Token config is nil")
	}
}

func TestTokenProvider_ReadsSecretAndAuthenticates(t *testing.T) {
	reader := &fakeSecretReader{
		data: map[string]string{"ns/sec/key": "s.vault-token-value"},
	}
	p := NewTokenProvider(reader)
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				Token: &vaultv1alpha1.TokenAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{Name: "sec", Namespace: "ns", Key: "key"},
				},
			},
		},
	}

	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !vc.tokenAuth.called {
		t.Fatal("expected AuthenticateToken to be called")
	}
	if vc.tokenAuth.token != "s.vault-token-value" {
		t.Errorf("expected token 's.vault-token-value', got %q", vc.tokenAuth.token)
	}
}

func TestTokenProvider_WrapsSecretReadError(t *testing.T) {
	reader := &fakeSecretReader{err: errors.New("secret missing")}
	p := NewTokenProvider(reader)
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				Token: &vaultv1alpha1.TokenAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{Name: "sec", Namespace: "ns", Key: "key"},
				},
			},
		},
	}

	err := p.Authenticate(context.Background(), &fakeAuthenticator{}, conn)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to get token from secret") {
		t.Errorf("expected wrapped error, got %v", err)
	}
}
