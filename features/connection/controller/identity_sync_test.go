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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// TestSync_RefusedIdentityLeavesCachedClient pins #18 review finding 9: a
// refused spec.identity change must not reach the cached client, which syncs
// already past vaultclient.Resolve share and read SpecIdentity() from.
func TestSync_RefusedIdentityLeavesCachedClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/auth" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"kubernetes/": map[string]any{"type": "kubernetes"}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": false, "version": "1.21.4"})
	}))
	defer server.Close()

	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})
	conn.Spec.Identity = &vaultv1alpha1.ConnectionIdentity{Name: "proj"}
	k8s := newClientBuilderWithConnectionRefIndex(createScheme()).
		WithObjects(newTokenSecret(tokenSecretOpts{}), conn).WithStatusSubresource(conn).Build()
	cache := vault.NewClientCache()
	handler := NewHandler(HandlerConfig{
		Client: k8s, ClientCache: cache, EventBus: events.NewEventBus(logr.Discard()), Log: logr.Discard(),
	})
	ctx := context.Background()

	if err := handler.Sync(ctx, conn); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	cached, err := cache.Get(conn.Name)
	if err != nil || cached.SpecIdentity() != "proj" {
		t.Fatalf("after first sync: cached client identity = %q (err %v), want proj", cached.SpecIdentity(), err)
	}

	conn.Spec.Identity.Name = "kubernetes" // equals the server's auth mount: refused
	conn.Generation = 2
	if err := k8s.Update(ctx, conn); err != nil {
		t.Fatalf("update spec: %v", err)
	}
	if err := handler.Sync(ctx, conn); err == nil {
		t.Fatal("second sync: want the colliding identity refused, got nil")
	}
	cached, _ = cache.Get(conn.Name)
	if got := cached.SpecIdentity(); got != "proj" {
		t.Errorf("cached client identity = %q after a refused change, want proj (unchanged)", got)
	}
	if conn.Status.Phase != vaultv1alpha1.PhaseError {
		t.Errorf("phase = %s, want Error", conn.Status.Phase)
	}
}
