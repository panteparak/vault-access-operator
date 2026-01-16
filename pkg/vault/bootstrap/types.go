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

package bootstrap

import (
	"time"

	"github.com/panteparak/vault-access-operator/pkg/vault/token"
)

// Default values for bootstrap configuration.
const (
	// DefaultAuthMethodName is the default name for the Kubernetes auth method.
	DefaultAuthMethodName = "kubernetes"

	// DefaultTokenReviewerDuration is how long the initial token_reviewer_jwt is valid.
	DefaultTokenReviewerDuration = 24 * time.Hour
)

// Config contains all configuration for the bootstrap process.
type Config struct {
	// BootstrapToken is the Vault token for initial authentication.
	BootstrapToken string

	// AuthMethodName is the name for the auth method (default: "kubernetes").
	// Use a custom name to avoid conflicts with existing auth methods.
	AuthMethodName string

	// OperatorRole is the Vault role to create for the operator.
	OperatorRole string

	// OperatorPolicy is the Vault policy to attach to the operator role.
	OperatorPolicy string

	// OperatorServiceAccount is the operator's service account.
	OperatorServiceAccount token.ServiceAccountRef

	// KubernetesConfig optionally overrides auto-discovered cluster details.
	KubernetesConfig *KubernetesClusterConfig

	// AutoRevoke controls whether to revoke the bootstrap token after setup.
	AutoRevoke bool

	// TokenReviewerServiceAccount is the service account for token review.
	// If not set, uses the operator's service account.
	TokenReviewerServiceAccount *token.ServiceAccountRef

	// TokenReviewerDuration is how long the initial token_reviewer_jwt is valid.
	TokenReviewerDuration time.Duration

	// VaultAddress is the Vault server address.
	VaultAddress string

	// TLSConfig contains TLS settings for Vault connection.
	TLSConfig *token.TLSConfig
}

// Result contains the results of a successful bootstrap.
type Result struct {
	// AuthPath is the Vault auth path (e.g., "auth/kubernetes").
	AuthPath string

	// AuthMethodCreated indicates if the auth method was created (vs already existed).
	AuthMethodCreated bool

	// RoleCreated indicates if the operator role was created.
	RoleCreated bool

	// BootstrapRevoked indicates if the bootstrap token was revoked.
	BootstrapRevoked bool

	// K8sAuthTestPassed indicates if K8s auth was tested successfully.
	K8sAuthTestPassed bool

	// TokenReviewerExpiration is when the token_reviewer_jwt expires.
	TokenReviewerExpiration time.Time
}

// KubernetesClusterConfig overrides auto-discovered cluster details.
type KubernetesClusterConfig struct {
	// Host is the Kubernetes API server URL.
	Host string

	// CACert is the CA certificate for the Kubernetes API.
	CACert string
}

// WithDefaults returns a copy of Config with default values applied.
func (c *Config) WithDefaults() *Config {
	cfg := *c
	if cfg.AuthMethodName == "" {
		cfg.AuthMethodName = DefaultAuthMethodName
	}
	if cfg.TokenReviewerDuration == 0 {
		cfg.TokenReviewerDuration = DefaultTokenReviewerDuration
	}
	if cfg.TokenReviewerServiceAccount == nil {
		cfg.TokenReviewerServiceAccount = &cfg.OperatorServiceAccount
	}
	return &cfg
}
