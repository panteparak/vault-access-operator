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

// Connection event type constants.
const (
	ConnectionReadyType         = "connection.ready"
	ConnectionDisconnectedType  = "connection.disconnected"
	ConnectionHealthChangedType = "connection.health_changed"
)

// ConnectionReady is published when a VaultConnection becomes ready.
// Other features can subscribe to know when they can start syncing to Vault.
type ConnectionReady struct {
	BaseEvent
	// ConnectionName is the name of the VaultConnection resource
	ConnectionName string
	// VaultAddress is the Vault server address
	VaultAddress string
	// VaultVersion is the version of the Vault server (if available)
	VaultVersion string
}

// Type returns the event type identifier.
func (e ConnectionReady) Type() string {
	return ConnectionReadyType
}

// NewConnectionReady creates a ConnectionReady event.
func NewConnectionReady(connectionName, vaultAddress, vaultVersion string) ConnectionReady {
	return ConnectionReady{
		BaseEvent:      NewBaseEvent(ConnectionReadyType),
		ConnectionName: connectionName,
		VaultAddress:   vaultAddress,
		VaultVersion:   vaultVersion,
	}
}

// ConnectionDisconnected is published when a VaultConnection is removed or becomes unavailable.
// Other features should stop using this connection and handle graceful degradation.
type ConnectionDisconnected struct {
	BaseEvent
	// ConnectionName is the name of the VaultConnection resource
	ConnectionName string
	// Reason describes why the connection was disconnected
	Reason string
}

// Type returns the event type identifier.
func (e ConnectionDisconnected) Type() string {
	return ConnectionDisconnectedType
}

// NewConnectionDisconnected creates a ConnectionDisconnected event.
func NewConnectionDisconnected(connectionName, reason string) ConnectionDisconnected {
	return ConnectionDisconnected{
		BaseEvent:      NewBaseEvent(ConnectionDisconnectedType),
		ConnectionName: connectionName,
		Reason:         reason,
	}
}

// ConnectionHealthChanged is published when a connection's health status changes.
// This is useful for monitoring and alerting on connection issues.
type ConnectionHealthChanged struct {
	BaseEvent
	// ConnectionName is the name of the VaultConnection resource
	ConnectionName string
	// Healthy indicates the new health status
	Healthy bool
	// Reason describes why the health changed
	Reason string
}

// Type returns the event type identifier.
func (e ConnectionHealthChanged) Type() string {
	return ConnectionHealthChangedType
}

// NewConnectionHealthChanged creates a ConnectionHealthChanged event.
func NewConnectionHealthChanged(connectionName string, healthy bool, reason string) ConnectionHealthChanged {
	return ConnectionHealthChanged{
		BaseEvent:      NewBaseEvent(ConnectionHealthChangedType),
		ConnectionName: connectionName,
		Healthy:        healthy,
		Reason:         reason,
	}
}
