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

// TokenReviewerController manages the token_reviewer_jwt in Vault's Kubernetes
// auth configuration. It automatically rotates the JWT before expiration.
//
// # What is token_reviewer_jwt?
//
// Vault's Kubernetes auth method needs a JWT to verify service account tokens
// presented during authentication. This JWT must have TokenReview permissions
// in Kubernetes. If it expires, ALL Kubernetes authentication to Vault fails.
//
// # Behavior
//
// The controller generates a new token_reviewer_jwt using the TokenRequest API
// and updates Vault's auth configuration. It does this proactively before the
// current JWT expires.
//
// # Thread Safety
//
// All methods are thread-safe.
//
// # Usage
//
//	controller := NewTokenReviewerController(provider, log)
//	mgr.Add(controller) // Starts background loop
//
//	// Register a connection for token reviewer management
//	controller.Register("my-connection", &ReviewerConfig{
//	    ServiceAccount: ServiceAccountRef{Namespace: "kube-system", Name: "vault-reviewer"},
//	    Duration:       24 * time.Hour,
//	    RefreshInterval: 12 * time.Hour,
//	    VaultAuthPath:  "kubernetes",
//	})
//
//	// Immediate refresh (e.g., during bootstrap)
//	controller.Refresh(ctx, "my-connection")
type TokenReviewerController interface {
	// Start begins the background refresh loop.
	// Returns when ctx is cancelled.
	Start(ctx context.Context) error

	// Register adds a connection for token reviewer management.
	// The VaultClient must be set before calling Refresh.
	Register(connectionName string, config *ReviewerConfig) error

	// SetVaultClient sets the Vault client for a connection.
	// Called after the connection is authenticated.
	SetVaultClient(connectionName string, client VaultAuthConfigUpdater)

	// Unregister removes a connection.
	// Safe to call multiple times or with non-existent names.
	Unregister(connectionName string)

	// Refresh immediately refreshes the token_reviewer_jwt for a connection.
	// Called during bootstrap and can be called manually if needed.
	Refresh(ctx context.Context, connectionName string) error

	// GetStatus returns the current token reviewer status.
	// Returns nil if the connection is not registered.
	GetStatus(connectionName string) *TokenReviewerStatus
}

// VaultAuthConfigUpdater is the interface for updating Vault auth config.
// Implemented by vault.Client.
type VaultAuthConfigUpdater interface {
	// UpdateKubernetesAuthConfig updates the token_reviewer_jwt in Vault.
	UpdateKubernetesAuthConfig(ctx context.Context, mountPath, tokenReviewerJWT string) error
}
