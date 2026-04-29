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
	"github.com/panteparak/vault-access-operator/pkg/vault/auth"
)

func TestGCPProvider_Applies(t *testing.T) {
	p := NewGCPProvider(&fakeSecretReader{}, stubGCPSigners{})
	if !p.Applies(vaultv1alpha1.AuthConfig{GCP: &vaultv1alpha1.GCPAuth{}}) {
		t.Error("expected Applies true")
	}
	if p.Applies(vaultv1alpha1.AuthConfig{}) {
		t.Error("expected Applies false")
	}
}

type stubGCPSigners struct {
	iamJWT string
	iamErr error
	gceJWT string
	gceErr error
}

func (s stubGCPSigners) GenerateIAMJWT(_ context.Context, _ auth.GCPAuthOptions) (string, error) {
	if s.iamErr != nil {
		return "", s.iamErr
	}
	return s.iamJWT, nil
}
func (s stubGCPSigners) GenerateGCELoginData(
	_ context.Context, _ auth.GCPAuthOptions,
) (map[string]interface{}, error) {
	if s.gceErr != nil {
		return nil, s.gceErr
	}
	return map[string]interface{}{"jwt": s.gceJWT}, nil
}

func TestGCPProvider_IAMDefault(t *testing.T) {
	p := NewGCPProvider(&fakeSecretReader{}, stubGCPSigners{iamJWT: "gcp-iam-jwt"})
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{GCP: &vaultv1alpha1.GCPAuth{Role: "gcp-role"}},
		},
	}
	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.gcpAuth.signedJWT != "gcp-iam-jwt" || vc.gcpAuth.mountPath != "gcp" {
		t.Errorf("unexpected auth args: %+v", vc.gcpAuth)
	}
}

func TestGCPProvider_GCEType(t *testing.T) {
	p := NewGCPProvider(&fakeSecretReader{}, stubGCPSigners{gceJWT: "gce-identity-jwt"})
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				GCP: &vaultv1alpha1.GCPAuth{Role: "r", AuthType: "gce"},
			},
		},
	}
	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.gcpAuth.signedJWT != "gce-identity-jwt" {
		t.Errorf("expected GCE JWT, got %q", vc.gcpAuth.signedJWT)
	}
}

func TestGCPProvider_ReadsCredentialsSecret(t *testing.T) {
	reader := &fakeSecretReader{data: map[string]string{"ns/gcp/key": `{"type":"service_account"}`}}
	p := NewGCPProvider(reader, stubGCPSigners{iamJWT: "jwt"})
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				GCP: &vaultv1alpha1.GCPAuth{
					Role:                 "r",
					CredentialsSecretRef: &vaultv1alpha1.SecretKeySelector{Name: "gcp", Namespace: "ns", Key: "key"},
				},
			},
		},
	}
	if err := p.Authenticate(context.Background(), &fakeAuthenticator{}, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGCPProvider_WrapsGCECredentialError(t *testing.T) {
	p := NewGCPProvider(&fakeSecretReader{err: errors.New("missing")}, stubGCPSigners{})
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				GCP: &vaultv1alpha1.GCPAuth{
					Role:                 "r",
					CredentialsSecretRef: &vaultv1alpha1.SecretKeySelector{Name: "gcp", Namespace: "ns", Key: "key"},
				},
			},
		},
	}
	err := p.Authenticate(context.Background(), &fakeAuthenticator{}, conn)
	if err == nil || !strings.Contains(err.Error(), "failed to get GCP credentials from secret") {
		t.Errorf("expected wrapped credentials error, got %v", err)
	}
}
