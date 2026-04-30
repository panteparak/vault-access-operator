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
	"time"

	"github.com/go-logr/logr"
)

// Handler is a function that processes events of type T.
// Handlers should be idempotent and handle errors gracefully.
type Handler[T Event] func(ctx context.Context, event T) error

// handlerFunc is a type-erased handler that accepts any Event.
// The type assertion is captured at Subscribe time via a closure,
// so the dispatch path is O(1) with no type switch.
type handlerFunc func(ctx context.Context, event Event) error

// EventBus manages event publication and subscription for inter-feature communication.
// It is thread-safe and supports multiple handlers per event type.
type EventBus struct {
	mu       sync.RWMutex
	handlers map[string][]handlerFunc
	logger   logr.Logger
}

// NewEventBus creates a new event bus with the given logger.
func NewEventBus(logger logr.Logger) *EventBus {
	return &EventBus{
		handlers: make(map[string][]handlerFunc),
		logger:   logger,
	}
}

// Subscribe registers a handler for events of type T.
// The handler will be called whenever an event of that type is published.
// Multiple handlers can be registered for the same event type.
//
// The type assertion is captured in a closure at subscribe time, eliminating
// the need for an exhaustive type switch in the dispatch path. Adding new
// event types requires no changes to the bus implementation.
func Subscribe[T Event](bus *EventBus, handler Handler[T]) {
	var zero T
	eventType := zero.Type()

	// Capture the type assertion in a closure — the handler is called
	// with the concrete type already asserted, so dispatch is a direct
	// function call with no runtime type switch.
	wrapped := func(ctx context.Context, event Event) error {
		return handler(ctx, event.(T))
	}

	bus.mu.Lock()
	defer bus.mu.Unlock()

	bus.handlers[eventType] = append(bus.handlers[eventType], wrapped)
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
	for i, handler := range handlers {
		if err := b.safeInvoke(ctx, handler, event, i); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// safeInvoke calls a handler with panic recovery so one bad handler
// doesn't crash the operator. Remaining handlers continue executing.
func (b *EventBus) safeInvoke(ctx context.Context, handler handlerFunc, event Event, index int) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("handler panicked: %v", r)
			b.logger.Error(err, "handler panic recovered",
				"type", event.Type(),
				"handlerIndex", index,
			)
		}
	}()

	if err = handler(ctx, event); err != nil {
		b.logger.Error(err, "handler failed",
			"type", event.Type(),
			"handlerIndex", index,
		)
	}
	return err
}

// PublishAsync sends an event to all subscribed handlers asynchronously.
// It returns immediately and handlers are invoked in a goroutine.
// Use this when you don't need to wait for handlers to complete.
//
// IMPORTANT: handlers run on a NEW background context derived from the
// caller's ctx logger only — NOT the caller's request-scoped ctx.
// Without this decoupling, controller-runtime cancels the reconcile
// ctx as soon as Reconcile returns, which can cancel handlers
// mid-execution (e.g., a metric emission or downstream HTTP call). The
// logger is preserved so request-scoped log fields (reconcileID, etc.)
// stay attached to handler logs.
//
// Caller-provided cancellation is honored only via the timeout below
// — handlers should be quick. Add a hard 10s deadline as a safety net
// against runaway handlers leaking goroutines indefinitely.
func (b *EventBus) PublishAsync(ctx context.Context, event Event) {
	// Preserve the logger but drop all other ctx values (deadlines,
	// cancellation). Handlers get a fresh background ctx with a 10s
	// deadline.
	parentLog, _ := logr.FromContext(ctx)
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if parentLog.GetSink() != nil {
			bgCtx = logr.NewContext(bgCtx, parentLog)
		}
		_ = b.Publish(bgCtx, event)
	}()
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
