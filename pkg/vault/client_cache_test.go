package vault

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func createTestClient(t *testing.T, address string) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{Address: address})
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}
	return client
}

func TestNewClientCache(t *testing.T) {
	cache := NewClientCache()
	if cache == nil {
		t.Fatal("NewClientCache() returned nil")
	}
	if cache.clients == nil {
		t.Error("NewClientCache() did not initialize clients map")
	}
	if cache.Size() != 0 {
		t.Errorf("NewClientCache() Size() = %d, want 0", cache.Size())
	}
}

func TestClientCacheSetAndGet(t *testing.T) {
	cache := NewClientCache()
	client := createTestClient(t, "http://localhost:8200")

	// Test Set
	cache.Set("conn1", client)

	// Verify connection name was set
	if client.ConnectionName() != "conn1" {
		t.Errorf("Set() did not set connection name, got %q, want %q", client.ConnectionName(), "conn1")
	}

	// Test Get
	retrieved, err := cache.Get("conn1")
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if retrieved != client {
		t.Error("Get() returned different client than what was set")
	}
}

func TestClientCacheGetNonExistent(t *testing.T) {
	cache := NewClientCache()

	_, err := cache.Get("nonexistent")
	if err == nil {
		t.Error("Get() expected error for non-existent connection, got nil")
	}
}

func TestClientCacheDelete(t *testing.T) {
	cache := NewClientCache()
	client := createTestClient(t, "http://localhost:8200")

	cache.Set("conn1", client)
	if !cache.Has("conn1") {
		t.Fatal("Has() = false after Set()")
	}

	cache.Delete("conn1")
	if cache.Has("conn1") {
		t.Error("Has() = true after Delete()")
	}

	// Delete non-existent should not panic
	cache.Delete("nonexistent")
}

func TestClientCacheHas(t *testing.T) {
	cache := NewClientCache()
	client := createTestClient(t, "http://localhost:8200")

	tests := []struct {
		name     string
		setup    func()
		connName string
		want     bool
	}{
		{
			name:     "empty cache",
			setup:    func() {},
			connName: "conn1",
			want:     false,
		},
		{
			name: "existing connection",
			setup: func() {
				cache.Set("conn1", client)
			},
			connName: "conn1",
			want:     true,
		},
		{
			name: "different connection",
			setup: func() {
				cache.Set("conn1", client)
			},
			connName: "conn2",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.Clear()
			tt.setup()
			if got := cache.Has(tt.connName); got != tt.want {
				t.Errorf("Has(%q) = %v, want %v", tt.connName, got, tt.want)
			}
		})
	}
}

func TestClientCacheList(t *testing.T) {
	cache := NewClientCache()

	// Empty cache
	list := cache.List()
	if len(list) != 0 {
		t.Errorf("List() returned %d items for empty cache, want 0", len(list))
	}

	// Add some clients
	cache.Set("conn1", createTestClient(t, "http://localhost:8201"))
	cache.Set("conn2", createTestClient(t, "http://localhost:8202"))
	cache.Set("conn3", createTestClient(t, "http://localhost:8203"))

	list = cache.List()
	if len(list) != 3 {
		t.Errorf("List() returned %d items, want 3", len(list))
	}

	// Verify all names are present
	names := make(map[string]bool)
	for _, name := range list {
		names[name] = true
	}

	for _, expected := range []string{"conn1", "conn2", "conn3"} {
		if !names[expected] {
			t.Errorf("List() missing %q", expected)
		}
	}
}

func TestClientCacheClear(t *testing.T) {
	cache := NewClientCache()

	cache.Set("conn1", createTestClient(t, "http://localhost:8201"))
	cache.Set("conn2", createTestClient(t, "http://localhost:8202"))

	if cache.Size() != 2 {
		t.Fatalf("Size() = %d before Clear(), want 2", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Size() = %d after Clear(), want 0", cache.Size())
	}
	if cache.Has("conn1") || cache.Has("conn2") {
		t.Error("Has() returned true after Clear()")
	}
}

func TestClientCacheSize(t *testing.T) {
	cache := NewClientCache()

	tests := []struct {
		name     string
		setup    func()
		wantSize int
	}{
		{
			name:     "empty cache",
			setup:    func() {},
			wantSize: 0,
		},
		{
			name: "one client",
			setup: func() {
				cache.Set("conn1", createTestClient(t, "http://localhost:8201"))
			},
			wantSize: 1,
		},
		{
			name: "multiple clients",
			setup: func() {
				cache.Set("conn1", createTestClient(t, "http://localhost:8201"))
				cache.Set("conn2", createTestClient(t, "http://localhost:8202"))
				cache.Set("conn3", createTestClient(t, "http://localhost:8203"))
			},
			wantSize: 3,
		},
		{
			name: "overwrite same key",
			setup: func() {
				cache.Set("conn1", createTestClient(t, "http://localhost:8201"))
				cache.Set("conn1", createTestClient(t, "http://localhost:8202"))
			},
			wantSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.Clear()
			tt.setup()
			if got := cache.Size(); got != tt.wantSize {
				t.Errorf("Size() = %d, want %d", got, tt.wantSize)
			}
		})
	}
}

func TestClientCacheGetOrCreate(t *testing.T) {
	cache := NewClientCache()

	// Test creating new client
	factoryCalled := false
	client, err := cache.GetOrCreate("conn1", func() (*Client, error) {
		factoryCalled = true
		return createTestClient(t, "http://localhost:8200"), nil
	})
	if err != nil {
		t.Errorf("GetOrCreate() error = %v", err)
	}
	if !factoryCalled {
		t.Error("GetOrCreate() did not call factory for new connection")
	}
	if client == nil {
		t.Fatal("GetOrCreate() returned nil client")
	}
	if client.ConnectionName() != "conn1" {
		t.Errorf("GetOrCreate() did not set connection name, got %q", client.ConnectionName())
	}

	// Test getting existing client (factory should not be called)
	factoryCalled = false
	retrieved, err := cache.GetOrCreate("conn1", func() (*Client, error) {
		factoryCalled = true
		return createTestClient(t, "http://localhost:8200"), nil
	})
	if err != nil {
		t.Errorf("GetOrCreate() error = %v", err)
	}
	if factoryCalled {
		t.Error("GetOrCreate() called factory for existing connection")
	}
	if retrieved != client {
		t.Error("GetOrCreate() returned different client for existing connection")
	}
}

func TestClientCacheGetOrCreateError(t *testing.T) {
	cache := NewClientCache()

	expectedErr := errors.New("factory error")
	_, err := cache.GetOrCreate("conn1", func() (*Client, error) {
		return nil, expectedErr
	})
	if err != expectedErr {
		t.Errorf("GetOrCreate() error = %v, want %v", err, expectedErr)
	}

	// Verify client was not added to cache
	if cache.Has("conn1") {
		t.Error("GetOrCreate() added client to cache despite factory error")
	}
}

func TestClientCacheConcurrentAccess(t *testing.T) {
	cache := NewClientCache()
	numGoroutines := 100
	numOperations := 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Start multiple goroutines performing concurrent operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				connName := "conn" + string(rune('0'+id%10))

				switch j % 5 {
				case 0:
					client := createTestClient(t, "http://localhost:8200")
					cache.Set(connName, client)
				case 1:
					_, _ = cache.Get(connName) // Ignore error, may not exist
				case 2:
					cache.Has(connName)
				case 3:
					cache.List()
				case 4:
					cache.Size()
				}
			}
		}(i)
	}

	wg.Wait()
	// Test passes if no race conditions or panics occurred
}

func TestClientCacheConcurrentGetOrCreate(t *testing.T) {
	cache := NewClientCache()
	numGoroutines := 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	var factoryCallCount atomic.Int32
	var clients []*Client
	var clientsMu sync.Mutex

	// All goroutines try to get or create the same connection
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			client, err := cache.GetOrCreate("shared-conn", func() (*Client, error) {
				factoryCallCount.Add(1)
				return createTestClient(t, "http://localhost:8200"), nil
			})
			if err != nil {
				t.Errorf("GetOrCreate() error = %v", err)
				return
			}

			clientsMu.Lock()
			clients = append(clients, client)
			clientsMu.Unlock()
		}()
	}

	wg.Wait()

	// Factory should only be called once
	if count := factoryCallCount.Load(); count != 1 {
		t.Errorf("Factory was called %d times, expected exactly 1", count)
	}

	// All goroutines should have received the same client
	if len(clients) != numGoroutines {
		t.Fatalf("Expected %d clients, got %d", numGoroutines, len(clients))
	}

	firstClient := clients[0]
	for i, c := range clients {
		if c != firstClient {
			t.Errorf("Client at index %d is different from first client", i)
		}
	}
}

func TestClientCacheConcurrentSetAndDelete(t *testing.T) {
	cache := NewClientCache()
	numGoroutines := 50
	numOperations := 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Half goroutines setting
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				connName := "conn" + string(rune('0'+j%10))
				cache.Set(connName, createTestClient(t, "http://localhost:8200"))
			}
		}()
	}

	// Half goroutines deleting
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				connName := "conn" + string(rune('0'+j%10))
				cache.Delete(connName)
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions or panics occurred
}

func TestClientCacheConcurrentClear(t *testing.T) {
	cache := NewClientCache()
	numGoroutines := 20
	numOperations := 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Half goroutines setting
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				cache.Set("conn", createTestClient(t, "http://localhost:8200"))
			}
		}()
	}

	// Half goroutines clearing
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				cache.Clear()
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions or panics occurred
}

// --- Cache edge cases (Gap 11) ---

func TestCache_GetAfterDelete(t *testing.T) {
	cache := NewClientCache()
	client := createTestClient(t, "http://localhost:8200")

	cache.Set("conn", client)

	// Delete the entry
	cache.Delete("conn")

	// Get should fail after delete
	_, err := cache.Get("conn")
	if err == nil {
		t.Error("expected error after deleting entry from cache")
	}
}

func TestCache_EvictionOnAddressChange(t *testing.T) {
	cache := NewClientCache()

	// Set client with old address
	oldClient := createTestClient(t, "http://old-vault:8200")
	cache.Set("conn", oldClient)

	// Overwrite with new address client
	newClient := createTestClient(t, "http://new-vault:8200")
	cache.Set("conn", newClient)

	// Get should return the new client
	got, err := cache.Get("conn")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != newClient {
		t.Error("expected new client after address change")
	}
	if got == oldClient {
		t.Error("old client should have been replaced")
	}
}

func TestCache_ConcurrentSetAndGet(t *testing.T) {
	cache := NewClientCache()
	client := createTestClient(t, "http://localhost:8200")
	cache.Set("conn", client)

	numGoroutines := 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errs := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				// Even goroutines: Get
				got, err := cache.Get("conn")
				if err != nil {
					errs <- err
					return
				}
				if got == nil {
					errs <- fmt.Errorf("got nil client")
				}
			} else {
				// Odd goroutines: Set (same key)
				cache.Set("conn", client)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent operation failed: %v", err)
	}
}

func BenchmarkClientCacheSet(b *testing.B) {
	cache := NewClientCache()
	client, _ := NewClient(ClientConfig{Address: "http://localhost:8200"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set("conn", client)
	}
}

func BenchmarkClientCacheGet(b *testing.B) {
	cache := NewClientCache()
	client, _ := NewClient(ClientConfig{Address: "http://localhost:8200"})
	cache.Set("conn", client)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Get("conn")
	}
}

func BenchmarkClientCacheGetOrCreate(b *testing.B) {
	cache := NewClientCache()
	factory := func() (*Client, error) {
		return NewClient(ClientConfig{Address: "http://localhost:8200"})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.GetOrCreate("conn", factory)
	}
}

func BenchmarkClientCacheConcurrent(b *testing.B) {
	cache := NewClientCache()
	client, _ := NewClient(ClientConfig{Address: "http://localhost:8200"})

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			connName := "conn" + string(rune('0'+i%10))
			switch i % 4 {
			case 0:
				cache.Set(connName, client)
			case 1:
				_, _ = cache.Get(connName)
			case 2:
				cache.Has(connName)
			case 3:
				cache.Size()
			}
			i++
		}
	})
}
