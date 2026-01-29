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

package events

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

func TestNewEventBus(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	if bus == nil {
		t.Fatal("expected bus to be non-nil")
		return
	}

	if bus.handlers == nil {
		t.Error("expected handlers map to be initialized")
	}
}

func TestSubscribe(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error {
		return nil
	})

	count := bus.HandlerCount(ConnectionReadyType)
	if count != 1 {
		t.Errorf("expected 1 handler, got %d", count)
	}
}

func TestSubscribe_MultipleHandlers(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error { return nil })
	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error { return nil })
	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error { return nil })

	count := bus.HandlerCount(ConnectionReadyType)
	if count != 3 {
		t.Errorf("expected 3 handlers, got %d", count)
	}
}

func TestPublish_ConnectionReady(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	var received ConnectionReady
	Subscribe[ConnectionReady](bus, func(_ context.Context, e ConnectionReady) error {
		received = e
		return nil
	})

	event := NewConnectionReady("my-conn", "https://vault:8200", "1.15.0")
	err := bus.Publish(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if received.ConnectionName != "my-conn" {
		t.Errorf("expected ConnectionName 'my-conn', got %q", received.ConnectionName)
	}

	if received.VaultAddress != "https://vault:8200" {
		t.Errorf("expected VaultAddress 'https://vault:8200', got %q", received.VaultAddress)
	}
}

func TestPublish_PolicyDeleted(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	var received PolicyDeleted
	Subscribe[PolicyDeleted](bus, func(_ context.Context, e PolicyDeleted) error {
		received = e
		return nil
	})

	resource := ResourceInfo{
		Name:           "my-policy",
		Namespace:      "default",
		ClusterScoped:  false,
		ConnectionName: "vault-conn",
	}
	event := NewPolicyDeleted("default-my-policy", resource)
	err := bus.Publish(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if received.PolicyName != "default-my-policy" {
		t.Errorf("expected PolicyName 'default-my-policy', got %q", received.PolicyName)
	}

	if received.Resource.Namespace != "default" {
		t.Errorf("expected Resource.Namespace 'default', got %q", received.Resource.Namespace)
	}
}

func TestPublish_RoleCreated(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	var received RoleCreated
	Subscribe[RoleCreated](bus, func(_ context.Context, e RoleCreated) error {
		received = e
		return nil
	})

	resource := ResourceInfo{
		Name:           "my-role",
		Namespace:      "default",
		ClusterScoped:  false,
		ConnectionName: "vault-conn",
	}
	event := NewRoleCreated(
		"default-my-role",
		"auth/kubernetes",
		resource,
		[]string{"policy1", "policy2"},
		[]string{"sa1", "sa2"},
	)
	err := bus.Publish(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if received.RoleName != "default-my-role" {
		t.Errorf("expected RoleName 'default-my-role', got %q", received.RoleName)
	}

	if len(received.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(received.Policies))
	}

	if len(received.BoundServiceAccounts) != 2 {
		t.Errorf("expected 2 service accounts, got %d", len(received.BoundServiceAccounts))
	}
}

func TestPublish_NoHandlers(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	event := NewConnectionReady("my-conn", "https://vault:8200", "")
	err := bus.Publish(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error for no handlers: %v", err)
	}
}

func TestPublish_HandlerError(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	expectedErr := errors.New("handler failed")
	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error {
		return expectedErr
	})

	event := NewConnectionReady("my-conn", "https://vault:8200", "")
	err := bus.Publish(context.Background(), event)

	// Should return the last error
	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestPublish_MultipleHandlers_ContinuesOnError(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	var callCount int32
	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error {
		atomic.AddInt32(&callCount, 1)
		return errors.New("first handler failed")
	})

	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error {
		atomic.AddInt32(&callCount, 1)
		return nil
	})

	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error {
		atomic.AddInt32(&callCount, 1)
		return errors.New("third handler failed")
	})

	event := NewConnectionReady("my-conn", "https://vault:8200", "")
	_ = bus.Publish(context.Background(), event)

	// All handlers should be called despite errors
	if atomic.LoadInt32(&callCount) != 3 {
		t.Errorf("expected 3 handler calls, got %d", callCount)
	}
}

func TestUnsubscribe(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error { return nil })
	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error { return nil })

	if bus.HandlerCount(ConnectionReadyType) != 2 {
		t.Fatalf("expected 2 handlers before unsubscribe")
	}

	bus.Unsubscribe(ConnectionReadyType)

	if bus.HandlerCount(ConnectionReadyType) != 0 {
		t.Errorf("expected 0 handlers after unsubscribe, got %d", bus.HandlerCount(ConnectionReadyType))
	}
}

func TestEventTypes(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error { return nil })
	Subscribe[PolicyDeleted](bus, func(_ context.Context, _ PolicyDeleted) error { return nil })
	Subscribe[RoleCreated](bus, func(_ context.Context, _ RoleCreated) error { return nil })

	types := bus.EventTypes()
	if len(types) != 3 {
		t.Errorf("expected 3 event types, got %d", len(types))
	}

	// Verify all expected types are present
	typeMap := make(map[string]bool)
	for _, et := range types {
		typeMap[et] = true
	}

	expectedTypes := []string{ConnectionReadyType, PolicyDeletedType, RoleCreatedType}
	for _, expected := range expectedTypes {
		if !typeMap[expected] {
			t.Errorf("missing event type: %s", expected)
		}
	}
}

func TestPublishAsync(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	var wg sync.WaitGroup
	wg.Add(1)

	var received ConnectionReady
	Subscribe[ConnectionReady](bus, func(_ context.Context, e ConnectionReady) error {
		received = e
		wg.Done()
		return nil
	})

	event := NewConnectionReady("async-conn", "https://vault:8200", "")
	bus.PublishAsync(context.Background(), event)

	// Wait for async handler with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if received.ConnectionName != "async-conn" {
			t.Errorf("expected ConnectionName 'async-conn', got %q", received.ConnectionName)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for async event")
	}
}

func TestEventBus_ThreadSafety(t *testing.T) {
	bus := NewEventBus(logr.Discard())

	var wg sync.WaitGroup
	var callCount int32

	// Subscribe concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error {
				atomic.AddInt32(&callCount, 1)
				return nil
			})
		}()
	}

	wg.Wait()

	// Verify all subscriptions were registered
	if bus.HandlerCount(ConnectionReadyType) != 10 {
		t.Errorf("expected 10 handlers, got %d", bus.HandlerCount(ConnectionReadyType))
	}

	// Publish concurrently
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			event := NewConnectionReady("conn", "https://vault:8200", "")
			_ = bus.Publish(context.Background(), event)
		}()
	}

	wg.Wait()

	// Each publish should call all 10 handlers, so 5 publishes = 50 calls
	if atomic.LoadInt32(&callCount) != 50 {
		t.Errorf("expected 50 handler calls, got %d", callCount)
	}
}

func TestBaseEvent(t *testing.T) {
	event := NewBaseEvent("test.event")

	if event.Type() != "test.event" {
		t.Errorf("expected type 'test.event', got %q", event.Type())
	}

	if time.Since(event.Timestamp()) > time.Second {
		t.Error("expected timestamp to be recent")
	}
}

func TestResourceInfo(t *testing.T) {
	info := ResourceInfo{
		Name:           "my-resource",
		Namespace:      "default",
		ClusterScoped:  false,
		ConnectionName: "vault-conn",
	}

	if info.Name != "my-resource" {
		t.Errorf("expected Name 'my-resource', got %q", info.Name)
	}

	if info.ClusterScoped {
		t.Error("expected ClusterScoped to be false")
	}
}

// Benchmark for Publish with multiple handlers.
func BenchmarkPublish(b *testing.B) {
	bus := NewEventBus(logr.Discard())

	for i := 0; i < 10; i++ {
		Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error {
			return nil
		})
	}

	event := NewConnectionReady("bench-conn", "https://vault:8200", "1.15.0")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bus.Publish(ctx, event)
	}
}

// Benchmark for Subscribe.
func BenchmarkSubscribe(b *testing.B) {
	bus := NewEventBus(logr.Discard())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Subscribe[ConnectionReady](bus, func(_ context.Context, _ ConnectionReady) error {
			return nil
		})
	}
}
