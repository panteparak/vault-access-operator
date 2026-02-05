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

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// reviewerControllerImpl implements TokenReviewerController.
type reviewerControllerImpl struct {
	provider TokenProvider
	eventBus EventPublisher
	log      logr.Logger

	mu          sync.RWMutex
	connections map[string]*reviewerState

	// checkInterval is how often the background loop checks for refreshes.
	checkInterval time.Duration
}

// reviewerState tracks the state of token reviewer management for a connection.
type reviewerState struct {
	config      *ReviewerConfig
	vaultClient VaultAuthConfigUpdater
	status      *TokenReviewerStatus
}

// NewTokenReviewerController creates a new TokenReviewerController.
func NewTokenReviewerController(
	provider TokenProvider,
	eventBus EventPublisher,
	log logr.Logger,
) TokenReviewerController {
	return &reviewerControllerImpl{
		provider:      provider,
		eventBus:      eventBus,
		log:           log.WithName("reviewer-controller"),
		connections:   make(map[string]*reviewerState),
		checkInterval: 60 * time.Second, // Check every minute
	}
}

// Start begins the background refresh loop.
func (c *reviewerControllerImpl) Start(ctx context.Context) error {
	c.log.Info("starting token reviewer controller")

	ticker := time.NewTicker(c.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.log.Info("token reviewer controller stopped")
			return nil
		case <-ticker.C:
			c.checkRefreshes(ctx)
		}
	}
}

// Register adds a connection for token reviewer management.
func (c *reviewerControllerImpl) Register(connectionName string, config *ReviewerConfig) error {
	if connectionName == "" {
		return fmt.Errorf("connection name is required")
	}
	if config == nil {
		return fmt.Errorf("config is required")
	}

	// Apply defaults
	config = config.WithDefaults()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.connections[connectionName] = &reviewerState{
		config: config,
		status: &TokenReviewerStatus{
			ConnectionName: connectionName,
			Enabled:        true,
		},
	}

	c.log.Info("registered connection for token reviewer management",
		"connection", connectionName,
		"authPath", config.VaultAuthPath,
		"duration", config.Duration,
		"refreshInterval", config.RefreshInterval,
	)

	return nil
}

// SetVaultClient sets the Vault client for a connection.
func (c *reviewerControllerImpl) SetVaultClient(connectionName string, client VaultAuthConfigUpdater) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if state, ok := c.connections[connectionName]; ok {
		state.vaultClient = client
		c.log.V(1).Info("set vault client for connection", "connection", connectionName)
	}
}

// Unregister removes a connection.
func (c *reviewerControllerImpl) Unregister(connectionName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.connections[connectionName]; exists {
		delete(c.connections, connectionName)
		c.log.Info("unregistered connection from token reviewer management",
			"connection", connectionName,
		)
	}
}

// Refresh immediately refreshes the token_reviewer_jwt for a connection.
func (c *reviewerControllerImpl) Refresh(ctx context.Context, connectionName string) error {
	c.mu.RLock()
	state, exists := c.connections[connectionName]
	if !exists {
		c.mu.RUnlock()
		return fmt.Errorf("connection %s not registered", connectionName)
	}
	if state.vaultClient == nil {
		c.mu.RUnlock()
		return fmt.Errorf("vault client not set for connection %s", connectionName)
	}
	config := state.config
	vaultClient := state.vaultClient
	c.mu.RUnlock()

	c.log.Info("refreshing token_reviewer_jwt", "connection", connectionName)

	// Get new token_reviewer_jwt
	// NOTE: Do NOT set Audiences here. The token_reviewer_jwt is used by Vault
	// as bearer auth to call the Kubernetes TokenReview API. It must have the
	// API server's default audience (not "vault") to be accepted.
	tokenInfo, err := c.provider.GetToken(ctx, GetTokenOptions{
		ServiceAccount: config.ServiceAccount,
		Duration:       config.Duration,
	})
	if err != nil {
		return c.handleRefreshFailure(connectionName, fmt.Errorf("failed to get token: %w", err))
	}

	// Update Vault auth config
	if err := vaultClient.UpdateKubernetesAuthConfig(ctx, config.VaultAuthPath, tokenInfo.Token); err != nil {
		return c.handleRefreshFailure(connectionName, fmt.Errorf("failed to update vault config: %w", err))
	}

	// Update status
	c.mu.Lock()
	if s, ok := c.connections[connectionName]; ok {
		s.status.LastRefresh = time.Now()
		s.status.ExpirationTime = tokenInfo.ExpirationTime
		s.status.NextRefresh = time.Now().Add(config.RefreshInterval)
		s.status.Error = ""
	}
	c.mu.Unlock()

	c.log.Info("refreshed token_reviewer_jwt",
		"connection", connectionName,
		"expiresAt", tokenInfo.ExpirationTime,
		"nextRefresh", time.Now().Add(config.RefreshInterval),
	)

	return nil
}

// GetStatus returns the current token reviewer status.
func (c *reviewerControllerImpl) GetStatus(connectionName string) *TokenReviewerStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if state, exists := c.connections[connectionName]; exists {
		// Return a copy to avoid race conditions
		status := *state.status
		return &status
	}
	return nil
}

// checkRefreshes checks all connections and refreshes token_reviewer_jwt as needed.
func (c *reviewerControllerImpl) checkRefreshes(ctx context.Context) {
	c.mu.RLock()
	// Get a snapshot of connections that need refresh
	var toRefresh []string
	for name, state := range c.connections {
		if state.vaultClient != nil && !state.status.NextRefresh.IsZero() && time.Now().After(state.status.NextRefresh) {
			toRefresh = append(toRefresh, name)
		}
	}
	c.mu.RUnlock()

	// Refresh each connection (outside the lock)
	for _, name := range toRefresh {
		if err := c.Refresh(ctx, name); err != nil {
			c.log.Error(err, "failed to refresh token_reviewer_jwt", "connection", name)
		}
	}
}

// handleRefreshFailure updates state on refresh failure.
func (c *reviewerControllerImpl) handleRefreshFailure(connectionName string, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if state, ok := c.connections[connectionName]; ok {
		state.status.Error = err.Error()
		// Schedule retry in 1 minute
		state.status.NextRefresh = time.Now().Add(1 * time.Minute)
	}

	return err
}

// Ensure reviewerControllerImpl implements TokenReviewerController.
var _ TokenReviewerController = (*reviewerControllerImpl)(nil)
