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

package vault

import (
	"context"
	"fmt"
	"time"
)

// IsAuthenticated returns whether the client has been authenticated
func (c *Client) IsAuthenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authenticated
}

// SetAuthenticated marks the client as authenticated
func (c *Client) SetAuthenticated(auth bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authenticated = auth
}

// TokenExpiration returns when the current Vault token expires.
// Returns zero time if not set (e.g., static token auth).
func (c *Client) TokenExpiration() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tokenExpiration
}

// TokenTTL returns the original TTL of the current Vault token.
// Returns zero if not set (e.g., static token auth).
func (c *Client) TokenTTL() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tokenTTL
}

// SetTokenExpiration sets when the token expires.
func (c *Client) SetTokenExpiration(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokenExpiration = t
}

// SetTokenTTL sets the token's original TTL.
func (c *Client) SetTokenTTL(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokenTTL = d
}

// TokenAccessor returns the accessor of the current Vault token.
// Accessors identify tokens without exposing them, useful for audit
// correlation and out-of-band revocation.
func (c *Client) TokenAccessor() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tokenAccessor
}

// RenewSelf renews the current Vault token in place.
// Updates tokenExpiration and tokenTTL with the new values from Vault.
func (c *Client) RenewSelf(ctx context.Context) error {
	secret, err := c.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("token renewal failed: %w", err)
	}
	if secret != nil && secret.Auth != nil && secret.Auth.LeaseDuration > 0 {
		ttl := time.Duration(secret.Auth.LeaseDuration) * time.Second
		c.mu.Lock()
		c.tokenTTL = ttl
		c.tokenExpiration = time.Now().Add(ttl)
		c.mu.Unlock()
	}
	return nil
}
