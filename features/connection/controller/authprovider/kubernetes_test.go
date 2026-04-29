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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

func TestKubernetesProvider_Applies(t *testing.T) {
	p := NewKubernetesProvider(&fakeTokenProvider{})
	if !p.Applies(vaultv1alpha1.AuthConfig{Kubernetes: &vaultv1alpha1.KubernetesAuth{}}) {
		t.Error("expected Applies true when Kubernetes config set")
	}
	if p.Applies(vaultv1alpha1.AuthConfig{}) {
		t.Error("expected Applies false when Kubernetes config nil")
	}
}

func TestKubernetesProvider_UsesConfiguredPath(t *testing.T) {
	tp := &fakeTokenProvider{token: "sa-jwt-token"}
	p := NewKubernetesProvider(tp)
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{
					Role:          "operator-role",
					AuthPath:      "k8s-prod",
					TokenDuration: metav1.Duration{},
				},
			},
		},
	}

	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.k8sAuth.role != "operator-role" || vc.k8sAuth.mountPath != "k8s-prod" || vc.k8sAuth.jwt != "sa-jwt-token" {
		t.Errorf("unexpected auth args: %+v", vc.k8sAuth)
	}
}

func TestKubernetesProvider_DefaultsAuthPath(t *testing.T) {
	tp := &fakeTokenProvider{token: "jwt"}
	p := NewKubernetesProvider(tp)
	vc := &fakeAuthenticator{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"},
			},
		},
	}

	if err := p.Authenticate(context.Background(), vc, conn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.k8sAuth.mountPath != "kubernetes" {
		t.Errorf("expected default mountPath 'kubernetes', got %q", vc.k8sAuth.mountPath)
	}
}

func TestKubernetesProvider_RequiresTokenProvider(t *testing.T) {
	p := NewKubernetesProvider(nil)
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"}},
		},
	}
	err := p.Authenticate(context.Background(), &fakeAuthenticator{}, conn)
	if err == nil || !strings.Contains(err.Error(), "token provider not configured") {
		t.Errorf("expected token-provider error, got %v", err)
	}
}

func TestKubernetesProvider_WrapsTokenError(t *testing.T) {
	p := NewKubernetesProvider(&fakeTokenProvider{err: errors.New("boom")})
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"}},
		},
	}
	err := p.Authenticate(context.Background(), &fakeAuthenticator{}, conn)
	if err == nil || !strings.Contains(err.Error(), "failed to get service account token") {
		t.Errorf("expected wrapped error, got %v", err)
	}
}
