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

import "time"

// Default values for token lifecycle management.
// These are internal defaults not exposed in the CRD.
const (
	// DefaultTokenDuration is the default service account token lifetime.
	DefaultTokenDuration = 1 * time.Hour

	// DefaultRenewalThreshold is the fraction of TTL at which to renew.
	// At 0.75, renewal occurs when 75% of the TTL has elapsed.
	DefaultRenewalThreshold = 0.75

	// DefaultMaxRetries is the max renewal attempts before re-authentication.
	DefaultMaxRetries = 3

	// DefaultRetryInterval is the delay between retry attempts.
	DefaultRetryInterval = 10 * time.Second

	// DefaultReviewerDuration is how long each token_reviewer_jwt is valid.
	DefaultReviewerDuration = 24 * time.Hour

	// DefaultReviewerRefreshInterval is how often to refresh token_reviewer_jwt.
	DefaultReviewerRefreshInterval = 12 * time.Hour

	// DefaultAudience is the standard audience for Vault authentication.
	DefaultAudience = "vault"
)

// TokenInfo contains the acquired token and its metadata.
// This is the output of TokenProvider.GetToken.
type TokenInfo struct {
	// Token is the JWT token string to use for Vault authentication.
	Token string

	// ExpirationTime is when the token expires. Used by LifecycleController
	// to schedule proactive renewal.
	ExpirationTime time.Time

	// IssuedAt is when the token was issued.
	IssuedAt time.Time

	// Audiences are the audiences the token is valid for.
	Audiences []string
}

// GetTokenOptions configures token acquisition.
type GetTokenOptions struct {
	// ServiceAccount identifies the service account to get a token for.
	ServiceAccount ServiceAccountRef

	// Duration is the requested token lifetime (for TokenRequest API).
	Duration time.Duration

	// Audiences are the intended audiences for the token.
	Audiences []string
}

// ServiceAccountRef identifies a Kubernetes service account.
type ServiceAccountRef struct {
	// Namespace is the service account's namespace.
	Namespace string

	// Name is the service account's name.
	Name string
}

// AuthResult contains the result of Vault authentication.
type AuthResult struct {
	// ClientToken is the Vault client token.
	ClientToken string

	// TokenTTL is the token's time-to-live.
	TokenTTL time.Duration

	// Renewable indicates if the token can be renewed.
	Renewable bool

	// ExpirationTime is when the token expires.
	ExpirationTime time.Time

	// Policies are the policies attached to the token.
	Policies []string
}

// TokenStatus represents the current status of a managed token.
type TokenStatus struct {
	// ConnectionName is the name of the VaultConnection.
	ConnectionName string

	// Authenticated indicates if the connection is authenticated.
	Authenticated bool

	// ExpirationTime is when the current token expires.
	ExpirationTime time.Time

	// LastRenewal is when the token was last renewed.
	LastRenewal time.Time

	// RenewalCount is the number of times the token has been renewed.
	RenewalCount int

	// NextRenewal is when the next renewal is scheduled.
	NextRenewal time.Time

	// Error contains any error from the last renewal attempt.
	Error string
}

// TokenReviewerStatus represents the status of token_reviewer_jwt management.
type TokenReviewerStatus struct {
	// ConnectionName is the name of the VaultConnection.
	ConnectionName string

	// Enabled indicates if token reviewer rotation is enabled.
	Enabled bool

	// LastRefresh is when the token_reviewer_jwt was last refreshed.
	LastRefresh time.Time

	// NextRefresh is when the next refresh is scheduled.
	NextRefresh time.Time

	// ExpirationTime is when the current token_reviewer_jwt expires.
	ExpirationTime time.Time

	// Error contains any error from the last refresh attempt.
	Error string
}

// LifecycleConfig configures lifecycle management for a connection.
type LifecycleConfig struct {
	// VaultAddress is the Vault server address.
	VaultAddress string

	// VaultRole is the Vault role to authenticate as.
	VaultRole string

	// VaultAuthPath is the Vault auth mount path (e.g., "kubernetes").
	VaultAuthPath string

	// ServiceAccount is the service account to get tokens for.
	ServiceAccount ServiceAccountRef

	// TokenDuration is the requested token lifetime.
	TokenDuration time.Duration

	// Audiences for the token.
	Audiences []string

	// RenewalThreshold is the fraction of TTL at which to renew (0.0-1.0).
	RenewalThreshold float64

	// MaxRetries is the max renewal attempts before re-authentication.
	MaxRetries int

	// RetryInterval is the delay between retry attempts.
	RetryInterval time.Duration

	// TLSConfig contains TLS settings for Vault connection.
	TLSConfig *TLSConfig
}

// TLSConfig contains TLS settings for Vault connection.
type TLSConfig struct {
	// CACert is the CA certificate for Vault.
	CACert string

	// SkipVerify skips TLS verification (not recommended for production).
	SkipVerify bool
}

// ReviewerConfig configures token reviewer management for a connection.
type ReviewerConfig struct {
	// ServiceAccount is the service account for token review.
	// Must have TokenReview permissions in Kubernetes.
	ServiceAccount ServiceAccountRef

	// Duration is how long the token_reviewer_jwt should be valid.
	Duration time.Duration

	// RefreshInterval is how often to refresh (should be < Duration).
	RefreshInterval time.Duration

	// VaultAuthPath is the Vault auth mount path to update.
	VaultAuthPath string
}

// TokenRefreshCallback is called when a token is successfully renewed.
// The callback receives the connection name and new authentication result.
type TokenRefreshCallback func(connectionName string, result *AuthResult)

// WithDefaults returns a copy of LifecycleConfig with default values applied.
func (c *LifecycleConfig) WithDefaults() *LifecycleConfig {
	cfg := *c
	if cfg.TokenDuration == 0 {
		cfg.TokenDuration = DefaultTokenDuration
	}
	if cfg.RenewalThreshold == 0 {
		cfg.RenewalThreshold = DefaultRenewalThreshold
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = DefaultRetryInterval
	}
	if len(cfg.Audiences) == 0 {
		cfg.Audiences = []string{DefaultAudience}
	}
	if cfg.VaultAuthPath == "" {
		cfg.VaultAuthPath = "kubernetes"
	}
	return &cfg
}

// WithDefaults returns a copy of ReviewerConfig with default values applied.
func (c *ReviewerConfig) WithDefaults() *ReviewerConfig {
	cfg := *c
	if cfg.Duration == 0 {
		cfg.Duration = DefaultReviewerDuration
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = DefaultReviewerRefreshInterval
	}
	if cfg.VaultAuthPath == "" {
		cfg.VaultAuthPath = "kubernetes"
	}
	return &cfg
}
