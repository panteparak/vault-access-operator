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

	"github.com/hashicorp/vault/api"
)

// The methods in this file satisfy bootstrap.VaultBootstrapClient and are
// primarily used during the one-time bootstrap flow. They are also reused
// by the connection cleanup path (DisableAuth, RevokeSelf) when the user
// opts into auth-mount cleanup.

// EnableAuth enables an auth method at the given path.
// This is used during bootstrap to enable the Kubernetes auth method.
func (c *Client) EnableAuth(ctx context.Context, path, methodType string) error {
	return c.Sys().EnableAuthWithOptionsWithContext(ctx, path, &api.EnableAuthOptions{
		Type: methodType,
	})
}

// IsAuthEnabled checks if an auth method is enabled at the given path.
func (c *Client) IsAuthEnabled(ctx context.Context, path string) (bool, error) {
	auths, err := c.Sys().ListAuthWithContext(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to list auth methods: %w", err)
	}
	pathWithSlash := path + "/"
	_, exists := auths[pathWithSlash]
	return exists, nil
}

// WriteKubernetesAuthConfig writes the Kubernetes auth configuration.
// This configures the kubernetes_host, kubernetes_ca_cert, and token_reviewer_jwt.
func (c *Client) WriteKubernetesAuthConfig(ctx context.Context, mountPath string, config map[string]interface{}) error {
	path := fmt.Sprintf("auth/%s/config", mountPath)
	_, err := c.Logical().WriteWithContext(ctx, path, config)
	if err != nil {
		return fmt.Errorf("failed to write kubernetes auth config: %w", err)
	}
	return nil
}

// UpdateKubernetesAuthConfig updates only the token_reviewer_jwt in the
// Kubernetes auth configuration. Vault's config endpoint performs a
// merge-update, so this preserves kubernetes_host and kubernetes_ca_cert.
// Implements token.VaultAuthConfigUpdater.
func (c *Client) UpdateKubernetesAuthConfig(ctx context.Context, mountPath, tokenReviewerJWT string) error {
	return c.WriteKubernetesAuthConfig(ctx, mountPath, map[string]interface{}{
		"token_reviewer_jwt": tokenReviewerJWT,
	})
}

// DisableAuth disables an auth method at the given path.
// WARNING: This revokes ALL tokens issued through this auth mount.
func (c *Client) DisableAuth(ctx context.Context, path string) error {
	return c.Sys().DisableAuthWithContext(ctx, path)
}

// WriteKubernetesRole creates or updates a Kubernetes auth role.
// This is used during bootstrap to create the operator's role.
func (c *Client) WriteKubernetesRole(
	ctx context.Context, mountPath, roleName string, config map[string]interface{},
) error {
	path := fmt.Sprintf("auth/%s/role/%s", mountPath, roleName)
	_, err := c.Logical().WriteWithContext(ctx, path, config)
	if err != nil {
		return fmt.Errorf("failed to write kubernetes role: %w", err)
	}
	return nil
}

// RevokeToken revokes the specified token.
func (c *Client) RevokeToken(ctx context.Context, token string) error {
	return c.Auth().Token().RevokeTreeWithContext(ctx, token)
}

// RevokeSelf revokes the current token.
// This is typically called after bootstrap to revoke the bootstrap token.
func (c *Client) RevokeSelf(ctx context.Context) error {
	return c.Auth().Token().RevokeSelfWithContext(ctx, "")
}
