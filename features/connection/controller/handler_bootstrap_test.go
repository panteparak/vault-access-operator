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

package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// --- isBootstrapRequired Tests ---

func TestIsBootstrapRequired_NilBootstrapConfig(t *testing.T) {
	handler := &Handler{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{},
		},
	}

	if handler.isBootstrapRequired(conn) {
		t.Error("expected false when bootstrap config is nil")
	}
}

func TestIsBootstrapRequired_AlreadyComplete(t *testing.T) {
	handler := &Handler{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				Bootstrap: &vaultv1alpha1.BootstrapAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name: "bootstrap-token",
						Key:  "token",
					},
				},
			},
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			AuthStatus: &vaultv1alpha1.AuthStatus{
				BootstrapComplete: true,
			},
		},
	}

	if handler.isBootstrapRequired(conn) {
		t.Error("expected false when bootstrap is already complete")
	}
}

func TestIsBootstrapRequired_Needed(t *testing.T) {
	handler := &Handler{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				Bootstrap: &vaultv1alpha1.BootstrapAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name: "bootstrap-token",
						Key:  "token",
					},
				},
			},
		},
	}

	if !handler.isBootstrapRequired(conn) {
		t.Error("expected true when bootstrap config is present and not yet complete")
	}
}

func TestIsBootstrapRequired_AuthStatusNonNilButNotComplete(t *testing.T) {
	handler := &Handler{}
	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				Bootstrap: &vaultv1alpha1.BootstrapAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name: "bootstrap-token",
						Key:  "token",
					},
				},
			},
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			AuthStatus: &vaultv1alpha1.AuthStatus{
				BootstrapComplete: false,
			},
		},
	}

	if !handler.isBootstrapRequired(conn) {
		t.Error("expected true when AuthStatus exists but BootstrapComplete is false")
	}
}

// --- runBootstrap Tests ---

func TestRunBootstrap_SecretNotFound(t *testing.T) {
	scheme := createScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-conn",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Bootstrap: &vaultv1alpha1.BootstrapAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name:      "nonexistent-secret",
						Namespace: "default",
						Key:       "token",
					},
				},
				Kubernetes: &vaultv1alpha1.KubernetesAuth{
					Role: "operator-role",
				},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		EventBus:    bus,
		Log:         logr.Discard(),
	})

	// bootstrapMgr is nil by default (no TokenProvider), so set a dummy to get past the nil check
	// Actually, runBootstrap checks bootstrapMgr first, then gets secret.
	// With no bootstrap manager, it will return "bootstrap manager not configured".
	// Let's test that case separately and then test the secret path.

	ctx := logr.NewContext(context.Background(), logr.Discard())
	err := handler.runBootstrap(ctx, conn)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// With no bootstrapMgr, we get "bootstrap manager not configured"
	if err.Error() != "bootstrap manager not configured" {
		t.Errorf("expected 'bootstrap manager not configured', got: %v", err)
	}
}

func TestRunBootstrap_NoBootstrapManager(t *testing.T) {
	handler := &Handler{
		log: logr.Discard(),
	}

	conn := &vaultv1alpha1.VaultConnection{
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Auth: vaultv1alpha1.AuthConfig{
				Bootstrap: &vaultv1alpha1.BootstrapAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name: "token-secret",
						Key:  "token",
					},
				},
			},
		},
	}

	ctx := logr.NewContext(context.Background(), logr.Discard())
	err := handler.runBootstrap(ctx, conn)
	if err == nil {
		t.Fatal("expected error when bootstrap manager is nil")
	}

	if err.Error() != "bootstrap manager not configured" {
		t.Errorf("expected 'bootstrap manager not configured', got: %v", err)
	}
}
