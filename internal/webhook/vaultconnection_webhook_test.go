/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
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

// TestVaultConnectionValidator_AuthExactlyOne is the centerpiece regression
// test for IMPROVEMENTS §8. The common user mistake this catches: two auth
// sub-structs set simultaneously (e.g., `token` + `kubernetes`). Before §8
// the operator silently used whichever branch came first in the dispatch
// chain and the unused branch was dead configuration.
func TestVaultConnectionValidator_AuthExactlyOne(t *testing.T) {
	v := &VaultConnectionValidator{}
	ctx := context.Background()

	cases := []struct {
		name        string
		auth        vaultv1alpha1.AuthConfig
		wantErr     bool
		errContains string
	}{
		{
			name:        "no auth method",
			auth:        vaultv1alpha1.AuthConfig{},
			wantErr:     true,
			errContains: "one auth method must be configured",
		},
		{
			name:    "only kubernetes",
			auth:    vaultv1alpha1.AuthConfig{Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"}},
			wantErr: false,
		},
		{
			name:    "only token",
			auth:    vaultv1alpha1.AuthConfig{Token: &vaultv1alpha1.TokenAuth{SecretRef: vaultv1alpha1.SecretKeySelector{Name: "s", Namespace: "ns", Key: "t"}}},
			wantErr: false,
		},
		{
			name: "bootstrap + kubernetes (legal transition pair)",
			auth: vaultv1alpha1.AuthConfig{
				Bootstrap:  &vaultv1alpha1.BootstrapAuth{SecretRef: vaultv1alpha1.SecretKeySelector{Name: "s", Namespace: "ns", Key: "t"}},
				Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"},
			},
			wantErr: false,
		},
		{
			name: "token + kubernetes (two full methods)",
			auth: vaultv1alpha1.AuthConfig{
				Token:      &vaultv1alpha1.TokenAuth{SecretRef: vaultv1alpha1.SecretKeySelector{Name: "s", Namespace: "ns", Key: "t"}},
				Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"},
			},
			wantErr:     true,
			errContains: "exactly one auth method",
		},
		{
			name: "three methods",
			auth: vaultv1alpha1.AuthConfig{
				Token:      &vaultv1alpha1.TokenAuth{SecretRef: vaultv1alpha1.SecretKeySelector{Name: "s", Namespace: "ns", Key: "t"}},
				Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"},
				AppRole:    &vaultv1alpha1.AppRoleAuth{RoleID: "x", SecretIDRef: vaultv1alpha1.SecretKeySelector{Name: "s", Namespace: "ns", Key: "t"}},
			},
			wantErr:     true,
			errContains: "3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "c"},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: "https://vault.example.com",
					Auth:    tc.auth,
				},
			}
			_, err := v.ValidateCreate(ctx, conn)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateCreate err = %v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("err %q should contain %q", err.Error(), tc.errContains)
			}
		})
	}
}

// TestVaultConnectionValidator_AddressImmutable pins the update rule that
// `spec.address` cannot change. Moving a connection to a different Vault
// instance would orphan every policy/role it manages.
func TestVaultConnectionValidator_AddressImmutable(t *testing.T) {
	v := &VaultConnectionValidator{}
	ctx := context.Background()

	oldConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault-a.example.com",
			Auth:    vaultv1alpha1.AuthConfig{Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"}},
		},
	}
	newConn := oldConn.DeepCopy()
	newConn.Spec.Address = "https://vault-b.example.com"

	_, err := v.ValidateUpdate(ctx, oldConn, newConn)
	if err == nil {
		t.Fatal("expected address-change to be rejected; got nil error")
	}
	if !strings.Contains(err.Error(), "immutable") {
		t.Errorf("error should mention immutability: %v", err)
	}
}

// TestVaultConnectionValidator_AppRoleRequiresRoleID catches a common
// mistake: configuring AppRole with only SecretIDRef set.
func TestVaultConnectionValidator_AppRoleRequiresRoleID(t *testing.T) {
	v := &VaultConnectionValidator{}
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault.example.com",
			Auth: vaultv1alpha1.AuthConfig{
				AppRole: &vaultv1alpha1.AppRoleAuth{
					// RoleID deliberately empty
					SecretIDRef: vaultv1alpha1.SecretKeySelector{Name: "s", Namespace: "ns", Key: "t"},
				},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), conn)
	if err == nil || !strings.Contains(err.Error(), "roleId is required") {
		t.Fatalf("want roleID-missing error, got %v", err)
	}
}

// TestVaultConnectionValidator_OIDCRequiresAtLeastOneTokenSource ensures
// that the combination `UseServiceAccountToken=false` + no JWTSecretRef
// is rejected. The operator would have no way to obtain a JWT.
func TestVaultConnectionValidator_OIDCRequiresAtLeastOneTokenSource(t *testing.T) {
	v := &VaultConnectionValidator{}
	useSA := false
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault.example.com",
			Auth: vaultv1alpha1.AuthConfig{
				OIDC: &vaultv1alpha1.OIDCAuth{
					Role:                   "r",
					UseServiceAccountToken: &useSA,
					// JWTSecretRef deliberately nil
				},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), conn)
	if err == nil || !strings.Contains(err.Error(), "useServiceAccountToken") {
		t.Fatalf("want OIDC no-token-source error, got %v", err)
	}
}

// TestVaultConnectionValidator_DiscoveryAutoCreateRequiresTargetNamespace
// catches one of the most common discovery-autoCreate footguns.
func TestVaultConnectionValidator_DiscoveryAutoCreateRequiresTargetNamespace(t *testing.T) {
	v := &VaultConnectionValidator{}
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault.example.com",
			Auth:    vaultv1alpha1.AuthConfig{Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"}},
			Discovery: &vaultv1alpha1.DiscoveryConfig{
				AutoCreateCRs: true,
				// TargetNamespace deliberately empty
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), conn)
	if err == nil || !strings.Contains(err.Error(), "targetNamespace is required") {
		t.Fatalf("want targetNamespace-required error, got %v", err)
	}
}

// TestVaultConnectionValidator_InvalidDiscoveryPattern pins the fix
// that wires scanner.ValidatePatterns into the webhook. Pre-fix, the
// scanner's filepath.Match silently swallowed ErrBadPattern and every
// policy/role failed to match — users saw "0 discovered resources"
// with no explanation and no way to debug. Now malformed patterns are
// rejected at `kubectl apply` time with a clear message pointing at
// the bad index.
func TestVaultConnectionValidator_InvalidDiscoveryPattern(t *testing.T) {
	v := &VaultConnectionValidator{}
	cases := []struct {
		name     string
		policies []string
		roles    []string
		want     string
	}{
		{
			name:     "unclosed bracket in policyPatterns",
			policies: []string{"[admin*"},
			want:     `spec.discovery.policyPatterns[0] "[admin*" is invalid`,
		},
		{
			name:  "unclosed bracket in rolePatterns",
			roles: []string{"*", "bad["},
			want:  `spec.discovery.rolePatterns[1] "bad[" is invalid`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "c"},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: "https://vault:8200",
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name: "s", Namespace: "ns", Key: "t",
							},
						},
					},
					Discovery: &vaultv1alpha1.DiscoveryConfig{
						PolicyPatterns: tc.policies,
						RolePatterns:   tc.roles,
					},
				},
			}
			_, err := v.ValidateCreate(context.Background(), conn)
			if err == nil {
				t.Fatal("expected error for invalid pattern, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should contain %q", err.Error(), tc.want)
			}
		})
	}
}

// TestVaultConnectionValidator_ValidDiscoveryPatterns confirms the
// negative case: well-formed patterns pass the new check.
func TestVaultConnectionValidator_ValidDiscoveryPatterns(t *testing.T) {
	v := &VaultConnectionValidator{}
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Token: &vaultv1alpha1.TokenAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name: "s", Namespace: "ns", Key: "t",
					},
				},
			},
			Discovery: &vaultv1alpha1.DiscoveryConfig{
				PolicyPatterns: []string{"admin-*", "app-[abc]*"},
				RolePatterns:   []string{"*"},
			},
		},
	}
	if _, err := v.ValidateCreate(context.Background(), conn); err != nil {
		t.Errorf("valid patterns should pass, got %v", err)
	}
}

// TestVaultConnectionValidator_SecretRefNamespaceRequired pins the
// fix for the silent footgun where SecretRef.Namespace="" fell back to
// "default". Because VaultConnection is cluster-scoped there's no
// implicit namespace; the previous behavior could pick up an unrelated
// secret in the "default" namespace, including one planted by another
// tenant. The webhook now rejects empty namespaces at admission so the
// user sees the failure immediately instead of "secret not found in
// default" hours later.
func TestVaultConnectionValidator_SecretRefNamespaceRequired(t *testing.T) {
	v := &VaultConnectionValidator{}
	cases := []struct {
		name string
		auth vaultv1alpha1.AuthConfig
		want string
	}{
		{
			name: "bootstrap secret missing namespace",
			auth: vaultv1alpha1.AuthConfig{
				Bootstrap: &vaultv1alpha1.BootstrapAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{Name: "boot", Key: "token"},
				},
				Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"},
			},
			want: "spec.auth.bootstrap.secretRef.namespace is required",
		},
		{
			name: "token secret missing namespace",
			auth: vaultv1alpha1.AuthConfig{
				Token: &vaultv1alpha1.TokenAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{Name: "tok", Key: "v"},
				},
			},
			want: "spec.auth.token.secretRef.namespace is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "c"},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: "https://vault:8200",
					Auth:    tc.auth,
				},
			}
			_, err := v.ValidateCreate(context.Background(), conn)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should contain %q", err.Error(), tc.want)
			}
		})
	}
}

// TestVaultConnectionValidator_SecretRefNamespacePresent confirms a
// fully-specified namespace passes (no false-positive on the new check).
func TestVaultConnectionValidator_SecretRefNamespacePresent(t *testing.T) {
	v := &VaultConnectionValidator{}
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Token: &vaultv1alpha1.TokenAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name: "tok", Namespace: "vault-system", Key: "v",
					},
				},
			},
		},
	}
	if _, err := v.ValidateCreate(context.Background(), conn); err != nil {
		t.Errorf("explicit namespace should pass, got %v", err)
	}
}

// TestVaultConnectionValidator_HTTPAddressEmitsWarning is a UX warning:
// http:// is not rejected (local testing is a valid use case) but the user
// should know they're sending credentials in the clear.
func TestVaultConnectionValidator_HTTPAddressEmitsWarning(t *testing.T) {
	v := &VaultConnectionValidator{}
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault.local:8200",
			Auth:    vaultv1alpha1.AuthConfig{Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"}},
		},
	}
	warnings, err := v.ValidateCreate(context.Background(), conn)
	if err != nil {
		t.Fatalf("http:// should be a warning, not an error; got %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warning about http://")
	}
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "http://") {
		t.Errorf("warning should mention http://: %v", warnings)
	}
}

// TestVaultConnectionValidator_DefaultsAuthPathNeedsType pins the admission
// half of the RoleMount rule: a defaults.authPath whose name the family
// heuristic can't classify must declare defaults.authType at apply time,
// not fail at first role reconcile.
func TestVaultConnectionValidator_DefaultsAuthPathNeedsType(t *testing.T) {
	v := &VaultConnectionValidator{}
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address:  "https://vault.example.com",
			Auth:     vaultv1alpha1.AuthConfig{Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"}},
			Defaults: &vaultv1alpha1.ConnectionDefaults{AuthPath: "my-mount"},
		},
	}

	_, err := v.ValidateCreate(context.Background(), conn)
	if err == nil || !strings.Contains(err.Error(), "defaults.authType") {
		t.Fatalf("want defaults.authType error for unclassifiable mount name, got %v", err)
	}

	conn.Spec.Defaults.AuthType = vaultv1alpha1.AuthBackendTypeJWT
	if _, err := v.ValidateCreate(context.Background(), conn); err != nil {
		t.Fatalf("explicit defaults.authType should validate, got %v", err)
	}
}

// TestVaultConnectionValidator_RoleMountChangeWarns pins the update-time
// warning when the resolved role mount changes under dependent roles:
// roles carry no mount of their own, so a connection-side mount change
// re-points every dependent role's next sync.
func TestVaultConnectionValidator_RoleMountChangeWarns(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	dependentRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "app-role", Namespace: "team-a"},
		Spec:       vaultv1alpha1.VaultRoleSpec{ConnectionRef: "c"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dependentRole).Build()
	v := &VaultConnectionValidator{client: c}

	oldConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault.example.com",
			Auth:    vaultv1alpha1.AuthConfig{Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r", AuthPath: "k8s-a"}},
		},
	}
	newConn := oldConn.DeepCopy()
	newConn.Spec.Auth.Kubernetes.AuthPath = "k8s-b"

	warnings, err := v.ValidateUpdate(context.Background(), oldConn, newConn)
	if err != nil {
		t.Fatalf("mount change must warn, not fail: %v", err)
	}
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "auth/k8s-a") || !strings.Contains(joined, "auth/k8s-b") {
		t.Fatalf("warning should name old and new mounts, got %v", warnings)
	}
	if !strings.Contains(joined, "1 dependent role(s)") {
		t.Errorf("warning should count dependents, got %v", warnings)
	}

	// Same mount → no warning; unrelated-connection roles don't count.
	warnings, err = v.ValidateUpdate(context.Background(), oldConn, oldConn.DeepCopy())
	if err != nil {
		t.Fatalf("no-op update should validate: %v", err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "re-points") {
			t.Errorf("unchanged mount should not warn about re-pointing: %v", w)
		}
	}
}
