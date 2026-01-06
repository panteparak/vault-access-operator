package vault

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/vault/api"
)

// Client wraps the Vault API client with additional metadata
type Client struct {
	*api.Client
	connectionName string
	authenticated  bool
}

// ClientConfig holds configuration for creating a Vault client
type ClientConfig struct {
	Address    string
	TLSConfig  *TLSConfig
	Timeout    time.Duration
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
			// Set CA cert using the API's TLS configuration
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

// IsAuthenticated returns whether the client has been authenticated
func (c *Client) IsAuthenticated() bool {
	return c.authenticated
}

// SetAuthenticated marks the client as authenticated
func (c *Client) SetAuthenticated(auth bool) {
	c.authenticated = auth
}

// IsHealthy checks if Vault is healthy and the client can connect
func (c *Client) IsHealthy(ctx context.Context) (bool, error) {
	health, err := c.Sys().HealthWithContext(ctx)
	if err != nil {
		return false, fmt.Errorf("vault health check failed: %w", err)
	}

	// Vault is healthy if initialized and unsealed
	return health.Initialized && !health.Sealed, nil
}

// GetVersion returns the Vault server version
func (c *Client) GetVersion(ctx context.Context) (string, error) {
	health, err := c.Sys().HealthWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get vault version: %w", err)
	}
	return health.Version, nil
}

// AuthenticateKubernetes authenticates using the Kubernetes auth method
func (c *Client) AuthenticateKubernetes(ctx context.Context, role, mountPath, tokenPath string) error {
	if mountPath == "" {
		mountPath = "kubernetes"
	}
	if tokenPath == "" {
		tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	jwt, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("failed to read service account token: %w", err)
	}

	path := fmt.Sprintf("auth/%s/login", mountPath)
	secret, err := c.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"role": role,
		"jwt":  string(jwt),
	})
	if err != nil {
		return fmt.Errorf("kubernetes auth failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("kubernetes auth returned no token")
	}

	c.SetToken(secret.Auth.ClientToken)
	c.authenticated = true
	return nil
}

// AuthenticateToken authenticates using a static token
func (c *Client) AuthenticateToken(token string) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}
	c.SetToken(token)
	c.authenticated = true
	return nil
}

// AuthenticateAppRole authenticates using the AppRole auth method
func (c *Client) AuthenticateAppRole(ctx context.Context, roleID, secretID, mountPath string) error {
	if mountPath == "" {
		mountPath = "approle"
	}

	path := fmt.Sprintf("auth/%s/login", mountPath)
	secret, err := c.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return fmt.Errorf("approle auth failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("approle auth returned no token")
	}

	c.SetToken(secret.Auth.ClientToken)
	c.authenticated = true
	return nil
}

// WritePolicy writes a policy to Vault
func (c *Client) WritePolicy(ctx context.Context, name, hcl string) error {
	return c.Sys().PutPolicyWithContext(ctx, name, hcl)
}

// ReadPolicy reads a policy from Vault
func (c *Client) ReadPolicy(ctx context.Context, name string) (string, error) {
	return c.Sys().GetPolicyWithContext(ctx, name)
}

// DeletePolicy deletes a policy from Vault
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	return c.Sys().DeletePolicyWithContext(ctx, name)
}

// PolicyExists checks if a policy exists in Vault
func (c *Client) PolicyExists(ctx context.Context, name string) (bool, error) {
	policies, err := c.Sys().ListPoliciesWithContext(ctx)
	if err != nil {
		return false, err
	}
	for _, p := range policies {
		if p == name {
			return true, nil
		}
	}
	return false, nil
}

// WriteKubernetesAuthRole writes a Kubernetes auth role to Vault
func (c *Client) WriteKubernetesAuthRole(ctx context.Context, authPath, roleName string, data map[string]interface{}) error {
	if authPath == "" {
		authPath = "auth/kubernetes"
	}
	path := fmt.Sprintf("%s/role/%s", authPath, roleName)
	_, err := c.Logical().WriteWithContext(ctx, path, data)
	return err
}

// ReadKubernetesAuthRole reads a Kubernetes auth role from Vault
func (c *Client) ReadKubernetesAuthRole(ctx context.Context, authPath, roleName string) (map[string]interface{}, error) {
	if authPath == "" {
		authPath = "auth/kubernetes"
	}
	path := fmt.Sprintf("%s/role/%s", authPath, roleName)
	secret, err := c.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, nil
	}
	return secret.Data, nil
}

// DeleteKubernetesAuthRole deletes a Kubernetes auth role from Vault
func (c *Client) DeleteKubernetesAuthRole(ctx context.Context, authPath, roleName string) error {
	if authPath == "" {
		authPath = "auth/kubernetes"
	}
	path := fmt.Sprintf("%s/role/%s", authPath, roleName)
	_, err := c.Logical().DeleteWithContext(ctx, path)
	return err
}

// KubernetesAuthRoleExists checks if a Kubernetes auth role exists
func (c *Client) KubernetesAuthRoleExists(ctx context.Context, authPath, roleName string) (bool, error) {
	data, err := c.ReadKubernetesAuthRole(ctx, authPath, roleName)
	if err != nil {
		return false, err
	}
	return data != nil, nil
}
