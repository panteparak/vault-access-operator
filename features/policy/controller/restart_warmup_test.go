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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// Review finding 6 (#18): after an operator restart the client cache is
// empty until the VaultConnection reconciles, while the connection's
// status still says Active and healthy. Resolve returned "client not in
// cache", syncerror set Phase=Error (ConnectionNotReady), and the next sync,
// no longer Active, rewrote every object with identical content. A cache
// miss is now a warm-up: status is left alone, so the CR stays Active and
// the next sync takes the unchanged-resource path (no write).
func TestSyncPolicy_RestartWarmupKeepsActiveAndSkipsRewrite(t *testing.T) {
	state := newPolicyMockState()
	server := newPolicyMockServer(policyMockConfig{state: state})
	t.Cleanup(server.Close)

	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	k8sClient := fake.NewClientBuilder().WithScheme(newPolicyTestScheme()).
		WithObjects(conn, policy).WithStatusSubresource(conn, policy).Build()
	ctx := logr.NewContext(context.Background(), logr.Discard())
	vc := newPolicyCachedVaultClient(t, server.URL)
	key := types.NamespacedName{Namespace: policyTestNamespace, Name: policyTestName}
	fetch := func() *vaultv1alpha1.VaultPolicy {
		var p vaultv1alpha1.VaultPolicy
		if err := k8sClient.Get(ctx, key, &p); err != nil {
			t.Fatal(err)
		}
		return &p
	}

	cache := vault.NewClientCache()
	cache.Set(conn.Name, vc)
	h := NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	if err := h.SyncPolicy(ctx, domain.NewVaultPolicyAdapter(fetch())); err != nil {
		t.Fatalf("sync 1: %v", err)
	}
	before := fetch().Status
	writes := state.writes

	// Restart: a new handler with an empty cache; the connection's status
	// is unchanged (still Active and healthy).
	restarted := vault.NewClientCache()
	h = NewHandler(k8sClient, restarted, events.NewEventBus(logr.Discard()), logr.Discard())
	err := h.SyncPolicy(ctx, domain.NewVaultPolicyAdapter(fetch()))
	if !infraerrors.IsClientNotCached(err) {
		t.Errorf("warm-up sync: want a client-not-cached error, got %v", err)
	}
	if got := fetch().Status; got.Phase != vaultv1alpha1.PhaseActive || got.RetryCount != before.RetryCount {
		t.Errorf("warm-up sync changed status: phase=%s retryCount=%d message=%q, want Active and untouched",
			got.Phase, got.RetryCount, got.Message)
	}

	// The connection reconciles and caches its client.
	restarted.Set(conn.Name, vc)
	if err := h.SyncPolicy(ctx, domain.NewVaultPolicyAdapter(fetch())); err != nil {
		t.Fatalf("sync after warm-up: %v", err)
	}
	if state.writes != writes {
		t.Errorf("policy rewritten after restart: %d writes, want 0", state.writes-writes)
	}
	if got := fetch().Status; got.Phase != vaultv1alpha1.PhaseActive || !got.LastSyncedAt.Equal(before.LastSyncedAt) {
		t.Errorf("after warm-up: phase=%s lastSyncedAt %v -> %v, want Active and unchanged",
			got.Phase, before.LastSyncedAt, got.LastSyncedAt)
	}
}
