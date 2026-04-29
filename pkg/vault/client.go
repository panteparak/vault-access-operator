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

// Package vault provides a thin wrapper around the HashiCorp Vault Go SDK
// with operator-specific metadata (authentication state, token TTL,
// connection identity). Methods are organized by concern across multiple
// files on the same *Client type:
//
//   - client.go       — construction, TLS, connection identity
//   - token_state.go  — authenticated flag, token expiration/TTL/accessor, RenewSelf
//   - health.go       — IsHealthy, GetVersion
//   - auth_methods.go — all Authenticate* methods
//   - policy_ops.go   — policy CRUD against sys/policies/acl
//   - role_ops.go     — Kubernetes auth role CRUD
//   - bootstrap_ops.go— auth mount management + token revocation (bootstrap-only)
package vault

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

// DefaultKubernetesAuthPath is the default path for Kubernetes auth in Vault
const DefaultKubernetesAuthPath = "auth/kubernetes"

// Client wraps the Vault API client with additional metadata.
// Mutable metadata fields are protected by mu for concurrent access
// from reconciler goroutines and the token renewal background loop.
type Client struct {
	*api.Client
	mu              sync.RWMutex
	connectionName  string
	authenticated   bool
	tokenExpiration time.Time
	tokenTTL        time.Duration
	tokenAccessor   string
}

// ClientConfig holds configuration for creating a Vault client
type ClientConfig struct {
	Address   string
	TLSConfig *TLSConfig
	Timeout   time.Duration
}

// TLSConfig holds TLS configuration for Vault client
type TLSConfig struct {
	CACert     string
	SkipVerify bool
}

// NewClient creates a new Vault client with the given configuration
func NewClient(cfg ClientConfig) (*Client, error) {
	config := api.DefaultConfig()
	config.Address = cfg.Address

	if cfg.Timeout > 0 {
		config.Timeout = cfg.Timeout
	}

	if cfg.TLSConfig != nil {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.TLSConfig.SkipVerify,
		}

		if cfg.TLSConfig.CACert != "" {
			if err := config.ConfigureTLS(&api.TLSConfig{
				CACert:   cfg.TLSConfig.CACert,
				Insecure: cfg.TLSConfig.SkipVerify,
			}); err != nil {
				return nil, fmt.Errorf("failed to configure TLS: %w", err)
			}
		} else if cfg.TLSConfig.SkipVerify {
			config.HttpClient.Transport = &http.Transport{
				TLSClientConfig: tlsConfig,
			}
		}
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	return &Client{
		Client: client,
	}, nil
}

// SetConnectionName sets the connection name for this client
func (c *Client) SetConnectionName(name string) {
	c.connectionName = name
}

// ConnectionName returns the connection name for this client
func (c *Client) ConnectionName() string {
	return c.connectionName
}
