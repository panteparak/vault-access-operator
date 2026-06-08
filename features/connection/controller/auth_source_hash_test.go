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

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// TestComputeAuthSourceHash_TokenContentChangesHash pins the e2e-flake fix:
// when the user (or test) rotates the token bytes inside the referenced
// Secret, the auth-source hash MUST change so the connection reconciler
// evicts the cached client. Without this, getOrRenewClient happily reuses
// the cached client with the now-revoked token, and downstream policy/role
// controllers fail with 403 permission denied.
func TestComputeAuthSourceHash_TokenContentChangesHash(t *testing.T) {
	scheme := createScheme()
	secretV1 := newTokenSecret(tokenSecretOpts{token: "s.token-v1"})
	secretV2 := newTokenSecret(tokenSecretOpts{token: "s.token-v2"})
	conn := newVaultConnection(vaultConnectionOpts{address: "http://vault:8200"})

	ctx := context.Background()

	// Hash with the v1 token in the cluster
	k8sClient := newClientBuilderWithConnectionRefIndex(scheme).WithObjects(secretV1).Build()
	h := &Handler{client: k8sClient, log: logr.Discard()}
	hashV1, err := h.computeAuthSourceHash(ctx, conn)
	if err != nil {
		t.Fatalf("hash v1: unexpected error: %v", err)
	}

	// Swap to the v2 token (same Secret name + key, different value)
	k8sClient = newClientBuilderWithConnectionRefIndex(scheme).WithObjects(secretV2).Build()
	h.client = k8sClient
	hashV2, err := h.computeAuthSourceHash(ctx, conn)
	if err != nil {
		t.Fatalf("hash v2: unexpected error: %v", err)
	}

	if hashV1 == hashV2 {
		t.Fatalf("expected different hashes after token rotation, got identical %q", hashV1)
	}
}

// TestComputeAuthSourceHash_StableForSameInput ensures the hash function is
// deterministic. Two consecutive calls with the same Secret content must
// return the same hash — otherwise getOrRenewClient would evict on every
// reconcile and defeat the cache entirely.
func TestComputeAuthSourceHash_StableForSameInput(t *testing.T) {
	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{token: "s.stable-token"})
	conn := newVaultConnection(vaultConnectionOpts{address: "http://vault:8200"})

	k8sClient := newClientBuilderWithConnectionRefIndex(scheme).WithObjects(secret).Build()
	h := &Handler{client: k8sClient, log: logr.Discard()}

	ctx := context.Background()
	first, err := h.computeAuthSourceHash(ctx, conn)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := h.computeAuthSourceHash(ctx, conn)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if first != second {
		t.Errorf("hash not deterministic: first=%q second=%q", first, second)
	}
}

// TestComputeAuthSourceHash_AddressIsPartOfFingerprint guarantees that
// pointing the same connection at a different Vault server forces re-auth
// — otherwise a stale cached client would silently keep targeting the old
// address.
func TestComputeAuthSourceHash_AddressIsPartOfFingerprint(t *testing.T) {
	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	connA := newVaultConnection(vaultConnectionOpts{address: "http://vault-a:8200"})
	connB := newVaultConnection(vaultConnectionOpts{address: "http://vault-b:8200"})

	k8sClient := newClientBuilderWithConnectionRefIndex(scheme).WithObjects(secret).Build()
	h := &Handler{client: k8sClient, log: logr.Discard()}

	ctx := context.Background()
	hashA, err := h.computeAuthSourceHash(ctx, connA)
	if err != nil {
		t.Fatalf("hash A: %v", err)
	}
	hashB, err := h.computeAuthSourceHash(ctx, connB)
	if err != nil {
		t.Fatalf("hash B: %v", err)
	}
	if hashA == hashB {
		t.Errorf("expected different hashes for different addresses, both = %q", hashA)
	}
}

// TestComputeAuthSourceHash_AuthMethodDistinguished ensures the method
// itself participates in the hash. If two configs differed only by which
// auth method they chose (token vs kubernetes), they MUST hash differently
// so a CR mutation that swaps the method forces re-auth.
func TestComputeAuthSourceHash_AuthMethodDistinguished(t *testing.T) {
	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	tokenConn := newVaultConnection(vaultConnectionOpts{address: "http://vault:8200"})
	k8sConn := newKubernetesAuthConnection("http://vault:8200")

	k8sClient := newClientBuilderWithConnectionRefIndex(scheme).WithObjects(secret).Build()
	h := &Handler{client: k8sClient, log: logr.Discard()}

	ctx := context.Background()
	tokenHash, err := h.computeAuthSourceHash(ctx, tokenConn)
	if err != nil {
		t.Fatalf("token hash: %v", err)
	}
	k8sHash, err := h.computeAuthSourceHash(ctx, k8sConn)
	if err != nil {
		t.Fatalf("k8s hash: %v", err)
	}
	if tokenHash == k8sHash {
		t.Errorf("expected different hashes for different auth methods, both = %q", tokenHash)
	}
}

// TestComputeAuthSourceHash_KubernetesAuthPathDefaultNormalized pins the
// AuthPath default-normalization: a CR with the field unset must hash the
// same as one with the explicit default. Otherwise admins who rewrite the
// CR to make the default explicit (a no-op from Vault's perspective) would
// cause a spurious re-auth + cache flush.
func TestComputeAuthSourceHash_KubernetesAuthPathDefaultNormalized(t *testing.T) {
	scheme := createScheme()

	implicit := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Generation: 1},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r"},
			},
		},
	}
	explicit := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Generation: 1},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "r", AuthPath: defaultKubernetesAuthPath},
			},
		},
	}

	k8sClient := newClientBuilderWithConnectionRefIndex(scheme).Build()
	h := &Handler{client: k8sClient, log: logr.Discard()}

	ctx := context.Background()
	hImpl, err := h.computeAuthSourceHash(ctx, implicit)
	if err != nil {
		t.Fatalf("implicit: %v", err)
	}
	hExpl, err := h.computeAuthSourceHash(ctx, explicit)
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if hImpl != hExpl {
		t.Errorf("default-normalized hashes should match: implicit=%q explicit=%q", hImpl, hExpl)
	}
}

// TestComputeAuthSourceHash_MissingSecretIsError verifies that a hash
// computation fails when the referenced Secret doesn't exist. The caller
// (getOrRenewClient) must NOT silently fall back to the cached client — if
// the source can't be read, the cached state is suspect and the next
// authentication will fail anyway.
func TestComputeAuthSourceHash_MissingSecretIsError(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://vault:8200"})

	// Empty client — no Secret present
	k8sClient := newClientBuilderWithConnectionRefIndex(scheme).Build()
	h := &Handler{client: k8sClient, log: logr.Discard()}

	if _, err := h.computeAuthSourceHash(context.Background(), conn); err == nil {
		t.Fatal("expected error when referenced Secret is missing, got nil")
	}
}

// TestComputeAuthSourceHash_NoAuthMethodIsError covers the malformed-CR
// path. The webhook should reject this at admission, but the helper has to
// fail closed for any CR that slipped through (webhook bypassed, prior CR
// from before validation was added, etc.).
func TestComputeAuthSourceHash_NoAuthMethodIsError(t *testing.T) {
	scheme := createScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Generation: 1},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://vault:8200",
			// Auth left empty
		},
	}
	k8sClient := newClientBuilderWithConnectionRefIndex(scheme).Build()
	h := &Handler{client: k8sClient, log: logr.Discard()}

	if _, err := h.computeAuthSourceHash(context.Background(), conn); err == nil {
		t.Fatal("expected error when no auth method is configured")
	}
}

// Silence unused-import warnings if a future edit removes the only user
// of corev1 in this file (newTokenSecret is the current user via tests).
var _ = corev1.Secret{}
