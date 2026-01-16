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
	"fmt"
	"sync"

	"github.com/go-logr/logr"
)

// Handler is a function that processes events of type T.
// Handlers should be idempotent and handle errors gracefully.
type Handler[T Event] func(ctx context.Context, event T) error

// handlerWrapper wraps a typed handler for storage in the bus.
type handlerWrapper struct {
	eventType string
	handler   interface{}
}

// EventBus manages event publication and subscription for inter-feature communication.
// It is thread-safe and supports multiple handlers per event type.
type EventBus struct {
	mu       sync.RWMutex
	handlers map[string][]handlerWrapper
	logger   logr.Logger
}

// NewEventBus creates a new event bus with the given logger.
func NewEventBus(logger logr.Logger) *EventBus {
	return &EventBus{
		handlers: make(map[string][]handlerWrapper),
		logger:   logger,
	}
}

// Subscribe registers a handler for events of type T.
// The handler will be called whenever an event of that type is published.
// Multiple handlers can be registered for the same event type.
func Subscribe[T Event](bus *EventBus, handler Handler[T]) {
	var zero T
	eventType := zero.Type()

	bus.mu.Lock()
	defer bus.mu.Unlock()

	wrapper := handlerWrapper{
		eventType: eventType,
		handler:   handler,
	}

	bus.handlers[eventType] = append(bus.handlers[eventType], wrapper)
	bus.logger.V(1).Info("handler subscribed", "eventType", eventType)
}

// Unsubscribe removes all handlers for a specific event type.
// This is useful for cleanup during shutdown.
func (b *EventBus) Unsubscribe(eventType string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.handlers, eventType)
	b.logger.V(1).Info("handlers unsubscribed", "eventType", eventType)
}

// Publish sends an event to all subscribed handlers.
// Handlers are called sequentially. If a handler returns an error,
// it is logged but does not prevent other handlers from being called.
// This ensures that one failing handler doesn't break the event flow.
func (b *EventBus) Publish(ctx context.Context, event Event) error {
	b.mu.RLock()
	handlers := b.handlers[event.Type()]
	b.mu.RUnlock()

	if len(handlers) == 0 {
		b.logger.V(2).Info("no handlers for event", "type", event.Type())
		return nil
	}

	b.logger.V(1).Info("publishing event",
		"type", event.Type(),
		"timestamp", event.Timestamp(),
		"handlerCount", len(handlers),
	)

	var lastErr error
	for i, wrapper := range handlers {
		if err := b.invokeHandler(ctx, wrapper.handler, event); err != nil {
			b.logger.Error(err, "handler failed",
				"type", event.Type(),
				"handlerIndex", i,
			)
			lastErr = err
			// Continue to other handlers - don't fail on single handler error
		}
	}

	return lastErr
}

// PublishAsync sends an event to all subscribed handlers asynchronously.
// It returns immediately and handlers are invoked in a goroutine.
// Use this when you don't need to wait for handlers to complete.
func (b *EventBus) PublishAsync(ctx context.Context, event Event) {
	go func() {
		_ = b.Publish(ctx, event)
	}()
}

// invokeHandler calls the appropriate typed handler based on the event type.
// This uses type assertions to convert from interface{} to the correct handler type.
func (b *EventBus) invokeHandler(ctx context.Context, handler interface{}, event Event) error {
	// Use type switch to handle each event type
	switch e := event.(type) {
	// Connection events
	case ConnectionReady:
		if h, ok := handler.(Handler[ConnectionReady]); ok {
			return h(ctx, e)
		}
	case ConnectionDisconnected:
		if h, ok := handler.(Handler[ConnectionDisconnected]); ok {
			return h(ctx, e)
		}
	case ConnectionHealthChanged:
		if h, ok := handler.(Handler[ConnectionHealthChanged]); ok {
			return h(ctx, e)
		}

	// Policy events
	case PolicyCreated:
		if h, ok := handler.(Handler[PolicyCreated]); ok {
			return h(ctx, e)
		}
	case PolicyUpdated:
		if h, ok := handler.(Handler[PolicyUpdated]); ok {
			return h(ctx, e)
		}
	case PolicyDeleted:
		if h, ok := handler.(Handler[PolicyDeleted]); ok {
			return h(ctx, e)
		}

	// Role events
	case RoleCreated:
		if h, ok := handler.(Handler[RoleCreated]); ok {
			return h(ctx, e)
		}
	case RoleUpdated:
		if h, ok := handler.(Handler[RoleUpdated]); ok {
			return h(ctx, e)
		}
	case RoleDeleted:
		if h, ok := handler.(Handler[RoleDeleted]); ok {
			return h(ctx, e)
		}

	default:
		return fmt.Errorf("unknown event type: %T", event)
	}

	return fmt.Errorf("handler type mismatch for event: %s", event.Type())
}

// HandlerCount returns the number of handlers registered for a specific event type.
// This is useful for testing and debugging.
func (b *EventBus) HandlerCount(eventType string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.handlers[eventType])
}

// EventTypes returns all event types that have registered handlers.
// This is useful for debugging and monitoring.
func (b *EventBus) EventTypes() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	types := make([]string, 0, len(b.handlers))
	for eventType := range b.handlers {
		types = append(types, eventType)
	}
	return types
}
