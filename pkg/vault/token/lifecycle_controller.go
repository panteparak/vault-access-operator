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

// lifecycleControllerImpl implements LifecycleController.
type lifecycleControllerImpl struct {
	provider      TokenProvider
	authenticator VaultAuthenticator
	eventBus      EventPublisher
	log           logr.Logger

	mu          sync.RWMutex
	connections map[string]*connectionState

	// checkInterval is how often the background loop checks for renewals.
	checkInterval time.Duration
}

// connectionState tracks the state of a managed connection.
type connectionState struct {
	config     *LifecycleConfig
	onRefresh  TokenRefreshCallback
	status     *TokenStatus
	lastResult *AuthResult
}

// EventPublisher is the interface for publishing events.
// This decouples from the concrete event bus implementation.
type EventPublisher interface {
	Publish(ctx context.Context, event interface{}) error
}

// NewLifecycleController creates a new LifecycleController.
func NewLifecycleController(
	provider TokenProvider,
	authenticator VaultAuthenticator,
	eventBus EventPublisher,
	log logr.Logger,
) LifecycleController {
	return &lifecycleControllerImpl{
		provider:      provider,
		authenticator: authenticator,
		eventBus:      eventBus,
		log:           log.WithName("lifecycle-controller"),
		connections:   make(map[string]*connectionState),
		checkInterval: 30 * time.Second, // Check every 30 seconds
	}
}

// Start begins the background renewal loop.
func (c *lifecycleControllerImpl) Start(ctx context.Context) error {
	c.log.Info("starting lifecycle controller")

	ticker := time.NewTicker(c.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.log.Info("lifecycle controller stopped")
			return nil
		case <-ticker.C:
			c.checkRenewals(ctx)
		}
	}
}

// Register adds a connection for lifecycle management.
func (c *lifecycleControllerImpl) Register(
	connectionName string,
	config *LifecycleConfig,
	onRefresh TokenRefreshCallback,
) error {
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

	c.connections[connectionName] = &connectionState{
		config:    config,
		onRefresh: onRefresh,
		status: &TokenStatus{
			ConnectionName: connectionName,
			Authenticated:  false,
		},
	}

	c.log.Info("registered connection for lifecycle management",
		"connection", connectionName,
		"role", config.VaultRole,
		"authPath", config.VaultAuthPath,
	)

	return nil
}

// Unregister removes a connection from lifecycle management.
func (c *lifecycleControllerImpl) Unregister(connectionName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.connections[connectionName]; exists {
		delete(c.connections, connectionName)
		c.log.Info("unregistered connection from lifecycle management",
			"connection", connectionName,
		)
	}
}

// Authenticate performs initial authentication for a connection.
func (c *lifecycleControllerImpl) Authenticate(
	ctx context.Context,
	connectionName string,
) (*AuthResult, error) {
	c.mu.RLock()
	state, exists := c.connections[connectionName]
	c.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connection %s not registered", connectionName)
	}

	// Get service account token
	tokenInfo, err := c.provider.GetToken(ctx, GetTokenOptions{
		ServiceAccount: state.config.ServiceAccount,
		Duration:       state.config.TokenDuration,
		Audiences:      state.config.Audiences,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get service account token: %w", err)
	}

	// Authenticate to Vault
	result, err := c.authenticator.AuthenticateKubernetes(
		ctx,
		tokenInfo.Token,
		state.config.VaultRole,
		state.config.VaultAuthPath,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate to Vault: %w", err)
	}

	// Update state
	c.mu.Lock()
	if s, ok := c.connections[connectionName]; ok {
		s.lastResult = result
		s.status.Authenticated = true
		s.status.ExpirationTime = result.ExpirationTime
		s.status.LastRenewal = time.Now()
		s.status.RenewalCount = 0
		s.status.NextRenewal = c.calculateNextRenewal(result.ExpirationTime, state.config.RenewalThreshold)
		s.status.Error = ""
	}
	c.mu.Unlock()

	c.log.Info("authenticated connection",
		"connection", connectionName,
		"expiresAt", result.ExpirationTime,
		"renewable", result.Renewable,
	)

	return result, nil
}

// GetStatus returns the current token status for a connection.
func (c *lifecycleControllerImpl) GetStatus(connectionName string) *TokenStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if state, exists := c.connections[connectionName]; exists {
		// Return a copy to avoid race conditions
		status := *state.status
		return &status
	}
	return nil
}

// checkRenewals checks all connections and renews tokens as needed.
func (c *lifecycleControllerImpl) checkRenewals(ctx context.Context) {
	c.mu.RLock()
	// Get a snapshot of connections that need renewal
	var toRenew []string
	for name, state := range c.connections {
		if state.status.Authenticated && time.Now().After(state.status.NextRenewal) {
			toRenew = append(toRenew, name)
		}
	}
	c.mu.RUnlock()

	// Renew each connection (outside the lock)
	for _, name := range toRenew {
		if err := c.renewConnection(ctx, name); err != nil {
			c.log.Error(err, "failed to renew token", "connection", name)
		}
	}
}

// renewConnection attempts to renew a single connection's token.
func (c *lifecycleControllerImpl) renewConnection(ctx context.Context, connectionName string) error {
	c.mu.RLock()
	state, exists := c.connections[connectionName]
	if !exists {
		c.mu.RUnlock()
		return nil // Connection was removed
	}
	config := state.config
	c.mu.RUnlock()

	c.log.Info("renewing token",
		"connection", connectionName,
		"strategy", config.RenewalStrategy,
	)

	var result *AuthResult
	var err error
	var method string

	// Check renewal strategy
	shouldTryRenew := config.RenewalStrategy != RenewalStrategyReauth

	// Try renewal first (if strategy allows)
	if shouldTryRenew {
		result, err = c.authenticator.RenewSelf(ctx)
		if err == nil {
			method = "renew"
		} else {
			c.log.Info("renewal failed, attempting re-authentication",
				"connection", connectionName,
				"error", err,
			)
		}
	}

	// Re-authenticate if renewal wasn't attempted or failed
	if result == nil {
		// Get new service account token
		tokenInfo, tokenErr := c.provider.GetToken(ctx, GetTokenOptions{
			ServiceAccount: config.ServiceAccount,
			Duration:       config.TokenDuration,
			Audiences:      config.Audiences,
		})
		if tokenErr != nil {
			return c.handleRenewalFailure(connectionName, tokenErr)
		}

		// Re-authenticate to Vault
		result, err = c.authenticator.AuthenticateKubernetes(
			ctx,
			tokenInfo.Token,
			config.VaultRole,
			config.VaultAuthPath,
		)
		if err != nil {
			return c.handleRenewalFailure(connectionName, err)
		}
		if shouldTryRenew {
			method = "re-authenticate" // Fallback from failed renewal
		} else {
			method = "re-authenticate (reauth strategy)"
		}
	}

	// Update state and notify
	c.mu.Lock()
	if s, ok := c.connections[connectionName]; ok {
		s.lastResult = result
		s.status.ExpirationTime = result.ExpirationTime
		s.status.LastRenewal = time.Now()
		s.status.RenewalCount++
		s.status.NextRenewal = c.calculateNextRenewal(result.ExpirationTime, config.RenewalThreshold)
		s.status.Error = ""

		// Call refresh callback (outside lock would be better, but keeping simple)
		if s.onRefresh != nil {
			s.onRefresh(connectionName, result)
		}
	}
	c.mu.Unlock()

	c.log.Info("token renewed",
		"connection", connectionName,
		"method", method,
		"expiresAt", result.ExpirationTime,
	)

	return nil
}

// handleRenewalFailure updates state on renewal failure.
func (c *lifecycleControllerImpl) handleRenewalFailure(connectionName string, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if state, ok := c.connections[connectionName]; ok {
		state.status.Error = err.Error()
		// Schedule retry
		state.status.NextRenewal = time.Now().Add(state.config.RetryInterval)
	}

	return fmt.Errorf("renewal failed: %w", err)
}

// calculateNextRenewal calculates when to next attempt renewal.
func (c *lifecycleControllerImpl) calculateNextRenewal(expiration time.Time, threshold float64) time.Time {
	ttl := time.Until(expiration)
	renewAfter := time.Duration(float64(ttl) * threshold)
	return time.Now().Add(renewAfter)
}

// Ensure lifecycleControllerImpl implements LifecycleController.
var _ LifecycleController = (*lifecycleControllerImpl)(nil)
