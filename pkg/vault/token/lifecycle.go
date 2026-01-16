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

package token

import "context"

// LifecycleController manages Vault token lifecycle with proactive renewal.
// It implements manager.Runnable to run as a background controller.
//
// # Behavior
//
// The controller tracks token expiration for each registered connection.
// When a token reaches the renewal threshold (e.g., 75% of TTL consumed),
// it proactively renews the token. If renewal fails, it falls back to
// full re-authentication.
//
// # Thread Safety
//
// All methods are thread-safe and can be called concurrently.
//
// # Events
//
// The controller publishes TokenRenewed events on successful renewal,
// allowing other features to react to token changes.
//
// # Usage
//
//	controller := NewLifecycleController(provider, eventBus, log)
//	mgr.Add(controller) // Starts background loop
//
//	// Register a connection
//	controller.Register("my-connection", config, func(name string, result *AuthResult) {
//	    // Handle token refresh - update cached client
//	})
//
//	// Initial authentication
//	result, err := controller.Authenticate(ctx, "my-connection")
//
//	// Later, when connection is deleted
//	controller.Unregister("my-connection")
type LifecycleController interface {
	// Start begins the background renewal loop.
	// Implements manager.Runnable interface.
	// Returns when ctx is cancelled.
	Start(ctx context.Context) error

	// Register adds a connection for lifecycle management.
	// The onRefresh callback is called when the token is renewed.
	// Registration is idempotent - calling with the same name updates the config.
	Register(connectionName string, config *LifecycleConfig, onRefresh TokenRefreshCallback) error

	// Unregister removes a connection from lifecycle management.
	// Should be called during connection cleanup.
	// Safe to call multiple times or with non-existent names.
	Unregister(connectionName string)

	// Authenticate performs initial authentication for a connection.
	// Returns the AuthResult containing the Vault token.
	// The connection must be registered before calling Authenticate.
	Authenticate(ctx context.Context, connectionName string) (*AuthResult, error)

	// GetStatus returns the current token status for a connection.
	// Returns nil if the connection is not registered.
	GetStatus(connectionName string) *TokenStatus
}

// VaultAuthenticator is the interface for Vault authentication operations.
// This allows for mocking in tests and decouples from the concrete Vault client.
type VaultAuthenticator interface {
	// AuthenticateKubernetes authenticates to Vault using a Kubernetes JWT.
	// Returns the Vault client token and metadata.
	AuthenticateKubernetes(ctx context.Context, jwt, role, mountPath string) (*AuthResult, error)

	// RenewSelf renews the current Vault token.
	// Returns the new TTL after renewal.
	RenewSelf(ctx context.Context) (*AuthResult, error)
}
