/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cleanup

import (
	"testing"

	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// TestClientCacheAdapter_WiresConcreteCacheToInterface pins IMPROVEMENTS §3.
// The cleanup controller depends on the local ClientCache interface whose
// Get method returns (VaultClient, error). The real cache at *vault.ClientCache
// returns (*vault.Client, error). Go does not implicitly adapt concrete
// return types into interface-returning signatures, so without this adapter
// `NewController(cleanup.ControllerConfig{ClientCache: connFeature.ClientCache})`
// fails to compile — and that's why §1 couldn't wire the controller in main.go
// without §3 landing first.
func TestClientCacheAdapter_WiresConcreteCacheToInterface(t *testing.T) {
	realCache := vault.NewClientCache()
	// Construct a known client and install it under a known name. The client
	// doesn't need to be authenticated — we only care that the adapter
	// surfaces the same instance when asked.
	c, err := vault.NewClient(vault.ClientConfig{Address: "http://localhost:8200"})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	realCache.Set("conn-a", c)

	adapter := NewClientCacheAdapter(realCache)

	// Hit: known name returns a VaultClient typed value (no cast error).
	gotAny, err := adapter.Get("conn-a")
	if err != nil {
		t.Fatalf("adapter.Get: unexpected err: %v", err)
	}
	if gotAny == nil {
		t.Fatal("adapter.Get returned nil VaultClient")
	}
	// The concrete type comes back as *vault.Client — assert we can access
	// one of the interface methods without panicking. We don't call it end-
	// to-end (that would need a real Vault); just prove the method binding
	// survives the adapter.
	if _, ok := gotAny.(*vault.Client); !ok {
		t.Errorf("adapter.Get returned %T, want *vault.Client", gotAny)
	}

	// Miss: unknown name surfaces the underlying cache's error.
	if _, err := adapter.Get("does-not-exist"); err == nil {
		t.Error("expected error for missing connection, got nil")
	}
}

// TestNewClientCacheAdapter_AssignableToClientCache ensures the adapter
// structurally satisfies the ClientCache interface. This is the test that
// would have caught §3 had it existed during the original build — a compile
// error here means `NewController` wiring in cmd/main.go will also fail.
func TestNewClientCacheAdapter_AssignableToClientCache(t *testing.T) {
	var _ ClientCache = NewClientCacheAdapter(vault.NewClientCache())
}
