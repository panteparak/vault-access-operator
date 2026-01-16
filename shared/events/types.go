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

// Package events provides an event bus for inter-feature communication in the
// Feature-Driven Design (FDD) architecture. Features publish domain events when
// significant actions occur, and other features can subscribe to react without
// direct coupling.
package events

import "time"

// Event is the base interface for all domain events.
// Each event type must implement this interface to be publishable.
type Event interface {
	// Type returns the unique event type identifier (e.g., "connection.ready")
	Type() string
	// Timestamp returns when the event occurred
	Timestamp() time.Time
}

// BaseEvent provides common fields for all domain events.
// Embed this in concrete event types to get default implementations.
type BaseEvent struct {
	EventType  string
	OccurredAt time.Time
}

// Type returns the event type identifier.
func (e BaseEvent) Type() string {
	return e.EventType
}

// Timestamp returns when the event occurred.
func (e BaseEvent) Timestamp() time.Time {
	return e.OccurredAt
}

// NewBaseEvent creates a BaseEvent with the given type and current timestamp.
func NewBaseEvent(eventType string) BaseEvent {
	return BaseEvent{
		EventType:  eventType,
		OccurredAt: time.Now(),
	}
}

// ResourceInfo contains common metadata about the K8s resource that triggered the event.
type ResourceInfo struct {
	// Name is the Kubernetes resource name
	Name string
	// Namespace is the Kubernetes namespace (empty for cluster-scoped resources)
	Namespace string
	// ClusterScoped indicates if this is a cluster-scoped resource
	ClusterScoped bool
	// ConnectionName is the VaultConnection used for this resource
	ConnectionName string
}
