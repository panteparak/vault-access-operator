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

// Package utils provides test utilities including a typed Vault API client
// that replaces kubectl exec Vault CLI calls in E2E tests. Using the Vault
// Go SDK instead of subprocess calls eliminates ~500ms per-call overhead and
// provides compile-time safety with typed responses.
package utils

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"
)

const (
	// DefaultTestVaultAddr is the default address for the Vault dev server
	// when port-forwarded from the k3d cluster.
	DefaultTestVaultAddr = "http://localhost:8200"

	// DefaultTestVaultToken is the root token for the Vault dev server.
	DefaultTestVaultToken = "root" //nolint:gosec
)

var (
	testVaultClient     *TestVaultClient
	testVaultClientOnce sync.Once
	testVaultClientErr  error
)

// TestVaultClient wraps the Vault API client for E2E tests.
// It provides high-level methods that replace RunVaultCommand() calls.
type TestVaultClient struct {
	client *vaultapi.Client
}

// GetTestVaultClient returns a singleton Vault API client for E2E tests.
// The address defaults to VAULT_ADDR env var or http://localhost:8200.
// The token defaults to VAULT_TOKEN env var or "root".
func GetTestVaultClient() (*TestVaultClient, error) {
	testVaultClientOnce.Do(func() {
		testVaultClient, testVaultClientErr = NewTestVaultClient("", "")
	})
	return testVaultClient, testVaultClientErr
}

// NewTestVaultClient creates a new Vault API client with the given address
// and token. Empty values fall back to environment variables, then defaults.
func NewTestVaultClient(address, token string) (*TestVaultClient, error) {
	if address == "" {
		address = os.Getenv("VAULT_ADDR")
	}
	if address == "" {
		address = DefaultTestVaultAddr
	}

	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		token = DefaultTestVaultToken
	}

	config := vaultapi.DefaultConfig()
	config.Address = address

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}
	client.SetToken(token)

	return &TestVaultClient{client: client}, nil
}

// Client returns the underlying vault/api.Client for advanced operations.
func (c *TestVaultClient) Client() *vaultapi.Client {
	return c.client
}

// =============================================================================
// Health / Status
// =============================================================================

// Health returns true if Vault is initialized and unsealed.
func (c *TestVaultClient) Health(ctx context.Context) (bool, error) {
	health, err := c.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return false, fmt.Errorf("vault health check failed: %w", err)
	}
	return health.Initialized && !health.Sealed, nil
}

// =============================================================================
// Policy operations
// =============================================================================

// WritePolicy creates or updates a Vault policy with the given HCL rules.
func (c *TestVaultClient) WritePolicy(
	ctx context.Context, name, hcl string,
) error {
	if err := c.client.Sys().PutPolicyWithContext(ctx, name, hcl); err != nil {
		return fmt.Errorf("failed to write policy %q: %w", name, err)
	}
	return nil
}

// ReadPolicy returns the HCL content of a Vault policy.
func (c *TestVaultClient) ReadPolicy(
	ctx context.Context, name string,
) (string, error) {
	policy, err := c.client.Sys().GetPolicyWithContext(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to read policy %q: %w", name, err)
	}
	return policy, nil
}

// DeletePolicy removes a policy from Vault.
func (c *TestVaultClient) DeletePolicy(
	ctx context.Context, name string,
) error {
	if err := c.client.Sys().DeletePolicyWithContext(ctx, name); err != nil {
		return fmt.Errorf("failed to delete policy %q: %w", name, err)
	}
	return nil
}

// ListPolicies returns all policy names in Vault.
func (c *TestVaultClient) ListPolicies(
	ctx context.Context,
) ([]string, error) {
	policies, err := c.client.Sys().ListPoliciesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	return policies, nil
}

// PolicyExists checks if a policy exists in Vault.
func (c *TestVaultClient) PolicyExists(
	ctx context.Context, name string,
) (bool, error) {
	policies, err := c.ListPolicies(ctx)
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

// =============================================================================
// Auth method management
// =============================================================================

// EnableAuth enables an auth method at the given path.
// If path is empty, the method type is used as the path.
// Returns nil if the auth method is already enabled.
func (c *TestVaultClient) EnableAuth(
	ctx context.Context, path, methodType string,
) error {
	if path == "" {
		path = methodType
	}
	// Vault paths for auth enable need trailing slash removed
	path = strings.TrimSuffix(path, "/")

	err := c.client.Sys().EnableAuthWithOptionsWithContext(
		ctx, path,
		&vaultapi.EnableAuthOptions{Type: methodType},
	)
	if err != nil {
		// "already in use" means auth method is already enabled — not an error
		if strings.Contains(err.Error(), "already in use") ||
			strings.Contains(err.Error(), "path is already in use") {
			return nil
		}
		return fmt.Errorf("failed to enable auth %q at %q: %w", methodType, path, err)
	}
	return nil
}

// DisableAuth disables an auth method at the given path.
func (c *TestVaultClient) DisableAuth(ctx context.Context, path string) error {
	path = strings.TrimSuffix(path, "/")
	if err := c.client.Sys().DisableAuthWithContext(ctx, path+"/"); err != nil {
		return fmt.Errorf("failed to disable auth at %q: %w", path, err)
	}
	return nil
}

// =============================================================================
// Auth configuration and roles
// =============================================================================

// WriteAuthConfig writes configuration to an auth method.
// path is the full path, e.g., "auth/kubernetes/config".
func (c *TestVaultClient) WriteAuthConfig(
	ctx context.Context, path string, data map[string]interface{},
) error {
	_, err := c.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return fmt.Errorf("failed to write auth config at %q: %w", path, err)
	}
	return nil
}

// WriteKubernetesAuthConfig is a convenience method for configuring K8s auth.
func (c *TestVaultClient) WriteKubernetesAuthConfig(
	ctx context.Context, authPath, k8sHost, reviewerJWT, caCert string,
) error {
	return c.WriteAuthConfig(ctx, fmt.Sprintf("auth/%s/config", authPath), map[string]interface{}{
		"kubernetes_host":    k8sHost,
		"token_reviewer_jwt": reviewerJWT,
		"kubernetes_ca_cert": caCert,
	})
}

// WriteAuthRole creates or updates an auth role.
// authPath is the mount path (e.g., "kubernetes"), roleName is the role name.
func (c *TestVaultClient) WriteAuthRole(
	ctx context.Context, authPath, roleName string,
	data map[string]interface{},
) error {
	path := fmt.Sprintf("auth/%s/role/%s", authPath, roleName)
	_, err := c.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return fmt.Errorf("failed to write role %q at %q: %w", roleName, path, err)
	}
	return nil
}

// ReadAuthRole reads an auth role's configuration.
func (c *TestVaultClient) ReadAuthRole(
	ctx context.Context, authPath, roleName string,
) (map[string]interface{}, error) {
	path := fmt.Sprintf("auth/%s/role/%s", authPath, roleName)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read role at %q: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no data at %q", path)
	}
	return secret.Data, nil
}

// DeleteAuthRole deletes an auth role.
func (c *TestVaultClient) DeleteAuthRole(
	ctx context.Context, authPath, roleName string,
) error {
	path := fmt.Sprintf("auth/%s/role/%s", authPath, roleName)
	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete role at %q: %w", path, err)
	}
	return nil
}

// RoleExists checks if an auth role exists.
func (c *TestVaultClient) RoleExists(
	ctx context.Context, authPath, roleName string,
) (bool, error) {
	path := fmt.Sprintf("auth/%s/role/%s", authPath, roleName)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		// "no handler for route" or similar means the auth method doesn't exist
		if strings.Contains(err.Error(), "no handler for route") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check role at %q: %w", path, err)
	}
	return secret != nil && secret.Data != nil, nil
}

// =============================================================================
// Token operations
// =============================================================================

// CreateToken creates a new Vault token with the given policies and TTL.
// Returns the token string.
func (c *TestVaultClient) CreateToken(
	ctx context.Context, policies []string, ttl string,
) (string, error) {
	secret, err := c.client.Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{
		Policies: policies,
		TTL:      ttl,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create token: %w", err)
	}
	return secret.Auth.ClientToken, nil
}

// RevokeToken revokes a specific token.
func (c *TestVaultClient) RevokeToken(ctx context.Context, token string) error {
	if err := c.client.Auth().Token().RevokeTreeWithContext(ctx, token); err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	return nil
}

// TokenLookupSelf looks up the current token's info.
func (c *TestVaultClient) TokenLookupSelf(
	ctx context.Context,
) (map[string]interface{}, error) {
	secret, err := c.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup self token: %w", err)
	}
	return secret.Data, nil
}

// TokenLookupSelfWithToken looks up a specific token's info by
// temporarily switching the client token.
func (c *TestVaultClient) TokenLookupSelfWithToken(
	ctx context.Context, token string,
) (map[string]interface{}, error) {
	// Save and restore the original token
	original := c.client.Token()
	c.client.SetToken(token)
	defer c.client.SetToken(original)

	return c.TokenLookupSelf(ctx)
}

// =============================================================================
// Login operations
// =============================================================================

// LoginKubernetes authenticates to Vault using Kubernetes auth.
// Returns the Vault client token on success.
func (c *TestVaultClient) LoginKubernetes(
	ctx context.Context, authPath, role, jwt string,
) (string, error) {
	path := fmt.Sprintf("auth/%s/login", authPath)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"role": role,
		"jwt":  jwt,
	})
	if err != nil {
		return "", fmt.Errorf("kubernetes login failed at %q: %w", path, err)
	}
	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("kubernetes login returned no auth data")
	}
	return secret.Auth.ClientToken, nil
}

// LoginJWT authenticates to Vault using JWT auth.
func (c *TestVaultClient) LoginJWT(
	ctx context.Context, authPath, role, jwt string,
) (string, error) {
	path := fmt.Sprintf("auth/%s/login", authPath)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"role": role,
		"jwt":  jwt,
	})
	if err != nil {
		return "", fmt.Errorf("JWT login failed at %q: %w", path, err)
	}
	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("JWT login returned no auth data")
	}
	return secret.Auth.ClientToken, nil
}

// LoginAppRole authenticates to Vault using AppRole auth.
func (c *TestVaultClient) LoginAppRole(
	ctx context.Context, authPath, roleID, secretID string,
) (string, error) {
	path := fmt.Sprintf("auth/%s/login", authPath)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return "", fmt.Errorf("AppRole login failed at %q: %w", path, err)
	}
	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("AppRole login returned no auth data")
	}
	return secret.Auth.ClientToken, nil
}

// =============================================================================
// AppRole helpers
// =============================================================================

// GetAppRoleRoleID reads the role_id for an AppRole role.
func (c *TestVaultClient) GetAppRoleRoleID(
	ctx context.Context, authPath, roleName string,
) (string, error) {
	path := fmt.Sprintf("auth/%s/role/%s/role-id", authPath, roleName)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to read role-id at %q: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no role-id data at %q", path)
	}
	roleID, ok := secret.Data["role_id"].(string)
	if !ok {
		return "", fmt.Errorf("role_id is not a string at %q", path)
	}
	return roleID, nil
}

// GenerateAppRoleSecretID generates a new secret_id for an AppRole role.
func (c *TestVaultClient) GenerateAppRoleSecretID(
	ctx context.Context, authPath, roleName string,
) (string, error) {
	path := fmt.Sprintf("auth/%s/role/%s/secret-id", authPath, roleName)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate secret-id at %q: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no secret-id data at %q", path)
	}
	secretID, ok := secret.Data["secret_id"].(string)
	if !ok {
		return "", fmt.Errorf("secret_id is not a string at %q", path)
	}
	return secretID, nil
}

// =============================================================================
// Generic read/write
// =============================================================================

// Write writes data to a Vault path and returns the response data.
func (c *TestVaultClient) Write(
	ctx context.Context, path string, data map[string]interface{},
) (*vaultapi.Secret, error) {
	secret, err := c.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("failed to write to %q: %w", path, err)
	}
	return secret, nil
}

// Read reads data from a Vault path.
func (c *TestVaultClient) Read(
	ctx context.Context, path string,
) (*vaultapi.Secret, error) {
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read from %q: %w", path, err)
	}
	return secret, nil
}

// Delete deletes data at a Vault path.
func (c *TestVaultClient) Delete(
	ctx context.Context, path string,
) error {
	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete %q: %w", path, err)
	}
	return nil
}

// =============================================================================
// Secrets engine management
// =============================================================================

// EnableSecretsEngine enables a secrets engine at the given path.
// Returns nil if already enabled.
func (c *TestVaultClient) EnableSecretsEngine(
	ctx context.Context, engineType, path string,
) error {
	err := c.client.Sys().MountWithContext(ctx, path, &vaultapi.MountInput{
		Type: engineType,
	})
	if err != nil {
		if strings.Contains(err.Error(), "already in use") ||
			strings.Contains(err.Error(), "path is already in use") {
			return nil
		}
		return fmt.Errorf(
			"failed to enable %q engine at %q: %w", engineType, path, err,
		)
	}
	return nil
}
