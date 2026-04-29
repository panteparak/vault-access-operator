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

func TestAppRoleProvider_Applies(t *testing.T) {
	p := NewAppRoleProvider(&fakeSecretReader{})
	if !p.Applies(vaultv1alpha1.AuthConfig{AppRole: &vaultv1alpha1.AppRoleAuth{}}) {
		t.Error("expected Applies true when AppRole set")
	}
	if p.Applies(vaultv1alpha1.AuthConfig{}) {
		t.Error("expected Applies false when AppRole nil")
	}
}

func TestAppRoleProvider_UsesConfiguredMountPath(t *testing.T) {
	reader := &fakeSecretReader{data: map[string]string{"ns/secid/key": "secret-id-value"}}
	p := NewAppRoleProvider(reader)
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				AppRole: &vaultv1alpha1.AppRoleAuth{
					RoleID: "role-id-123",
					SecretIDRef: vaultv1alpha1.SecretKeySelector{
						Name: "secid", Namespace: "ns", Key: "key",
					},
					MountPath: "custom-approle",
				},
			},
		},
	}

	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !vc.appRoleAuth.called {
		t.Fatal("expected AppRole auth to be called")
	}
	if vc.appRoleAuth.roleID != "role-id-123" ||
		vc.appRoleAuth.secretID != "secret-id-value" ||
		vc.appRoleAuth.mountPath != "custom-approle" {
		t.Errorf("unexpected auth args: %+v", vc.appRoleAuth)
	}
}

func TestAppRoleProvider_DefaultsMountPath(t *testing.T) {
	reader := &fakeSecretReader{data: map[string]string{"ns/secid/key": "sid"}}
	p := NewAppRoleProvider(reader)
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				AppRole: &vaultv1alpha1.AppRoleAuth{
					RoleID:      "r",
					SecretIDRef: vaultv1alpha1.SecretKeySelector{Name: "secid", Namespace: "ns", Key: "key"},
				},
			},
		},
	}

	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.appRoleAuth.mountPath != "approle" {
		t.Errorf("expected default mountPath 'approle', got %q", vc.appRoleAuth.mountPath)
	}
}

func TestAppRoleProvider_WrapsSecretError(t *testing.T) {
	p := NewAppRoleProvider(&fakeSecretReader{err: errNotFound("sid")})
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				AppRole: &vaultv1alpha1.AppRoleAuth{
					RoleID:      "r",
					SecretIDRef: vaultv1alpha1.SecretKeySelector{Name: "secid", Namespace: "ns", Key: "key"},
				},
			},
		},
	}
	err := p.Authenticate(context.Background(), &fakeAuthenticator{}, conn)
	if err == nil || !strings.Contains(err.Error(), "failed to get secret ID from secret") {
		t.Errorf("expected wrapped secret-ID error, got %v", err)
	}
}

type notFoundErr struct{ what string }

func (e notFoundErr) Error() string { return e.what + " not found" }

func errNotFound(what string) error { return notFoundErr{what: what} }
