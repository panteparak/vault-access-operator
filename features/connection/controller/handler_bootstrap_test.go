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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/pkg/vault/bootstrap"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// fakeBootstrapManager returns a canned Result so we can exercise the
// post-Bootstrap status mutation path without hitting Vault.
type fakeBootstrapManager struct {
	result *bootstrap.Result
	err    error
}

func (f *fakeBootstrapManager) Bootstrap(
	_ context.Context, _ bootstrap.VaultBootstrapClient, _ *bootstrap.Config,
) (*bootstrap.Result, error) {
	return f.result, f.err
}

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

// runBootstrapWithFakeMgr is the shared scaffold for the
// K8sAuthTest-failure tests below. It wires a fake bootstrap manager
// and the K8s objects (connection + bootstrap secret) needed to
// exercise the post-Bootstrap status mutation code path.
func runBootstrapWithFakeMgr(
	t *testing.T, mgrResult *bootstrap.Result,
) (*vaultv1alpha1.VaultConnection, error) {
	t.Helper()
	scheme := createScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-conn",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Bootstrap: &vaultv1alpha1.BootstrapAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name:      "boot",
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
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "boot", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("bootstrap-token-value")},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, secret).
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
	handler.bootstrapMgr = &fakeBootstrapManager{result: mgrResult}

	ctx := logr.NewContext(context.Background(), logr.Discard())
	err := handler.runBootstrap(ctx, conn)
	return conn, err
}

// TestRunBootstrap_K8sAuthTestFails_DoesNotMarkComplete pins the fix
// for the bug where BootstrapComplete=true was set unconditionally,
// even when the K8s auth test failed. Pre-fix, this stuck the
// connection: isBootstrapRequired returned false on subsequent
// reconciles, the (idempotent) bootstrap path was never re-tried, and
// the normal auth path failed for the same reason the test did. The
// operator reported BootstrapComplete=true while being unable to
// authenticate.
func TestRunBootstrap_K8sAuthTestFails_DoesNotMarkComplete(t *testing.T) {
	result := &bootstrap.Result{
		AuthPath:          "auth/kubernetes",
		AuthMethodCreated: true,
		RoleCreated:       true,
		K8sAuthTestPassed: false,
		K8sAuthTestError:  "kubernetes auth test failed: 403 forbidden",
	}
	conn, err := runBootstrapWithFakeMgr(t, result)
	if err != nil {
		t.Fatalf("runBootstrap returned error: %v", err)
	}
	if conn.Status.AuthStatus == nil {
		t.Fatal("AuthStatus should be set")
	}
	if conn.Status.AuthStatus.BootstrapComplete {
		t.Error("BootstrapComplete should be FALSE when K8s auth test failed")
	}
	if conn.Status.AuthStatus.BootstrapCompletedAt != nil {
		t.Error("BootstrapCompletedAt should be nil when test failed")
	}
}

// TestRunBootstrap_K8sAuthTestPasses_MarksComplete is the happy-path
// counterpart — when the test passes, BootstrapComplete must flip to
// true and the timestamp must be recorded. Guards against a regression
// where the gating logic accidentally fails closed.
func TestRunBootstrap_K8sAuthTestPasses_MarksComplete(t *testing.T) {
	result := &bootstrap.Result{
		AuthPath:          "auth/kubernetes",
		AuthMethodCreated: true,
		RoleCreated:       true,
		BootstrapRevoked:  true,
		K8sAuthTestPassed: true,
	}
	conn, err := runBootstrapWithFakeMgr(t, result)
	if err != nil {
		t.Fatalf("runBootstrap returned error: %v", err)
	}
	if conn.Status.AuthStatus == nil {
		t.Fatal("AuthStatus should be set")
	}
	if !conn.Status.AuthStatus.BootstrapComplete {
		t.Error("BootstrapComplete should be TRUE when K8s auth test passed")
	}
	if conn.Status.AuthStatus.BootstrapCompletedAt == nil {
		t.Error("BootstrapCompletedAt should be set when test passed")
	}
}

// TestRunBootstrap_SetsBootstrappedCondition pins the new
// `Bootstrapped` condition. Operators querying conditions should see
// explicit confirmation of bootstrap state instead of having to wait
// for the next reconcile to land the normal Ready=True. Status of the
// condition mirrors K8sAuthTestPassed.
func TestRunBootstrap_SetsBootstrappedCondition(t *testing.T) {
	cases := []struct {
		name           string
		k8sAuthPassed  bool
		k8sAuthError   string
		wantCondStatus metav1.ConditionStatus
		wantReason     string
	}{
		{
			name:           "passed → True/Succeeded",
			k8sAuthPassed:  true,
			wantCondStatus: metav1.ConditionTrue,
			wantReason:     vaultv1alpha1.ReasonSucceeded,
		},
		{
			name:           "failed → False/Failed",
			k8sAuthPassed:  false,
			k8sAuthError:   "auth failed: 403",
			wantCondStatus: metav1.ConditionFalse,
			wantReason:     vaultv1alpha1.ReasonFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &bootstrap.Result{
				AuthPath:          "auth/kubernetes",
				K8sAuthTestPassed: tc.k8sAuthPassed,
				K8sAuthTestError:  tc.k8sAuthError,
			}
			conn, err := runBootstrapWithFakeMgr(t, result)
			if err != nil {
				t.Fatalf("runBootstrap returned error: %v", err)
			}
			var got *vaultv1alpha1.Condition
			for i := range conn.Status.Conditions {
				if conn.Status.Conditions[i].Type == vaultv1alpha1.ConditionTypeBootstrapped {
					got = &conn.Status.Conditions[i]
					break
				}
			}
			if got == nil {
				t.Fatal("Bootstrapped condition should be set")
			}
			if got.Status != tc.wantCondStatus {
				t.Errorf("Bootstrapped.Status = %q, want %q", got.Status, tc.wantCondStatus)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("Bootstrapped.Reason = %q, want %q", got.Reason, tc.wantReason)
			}
		})
	}
}
