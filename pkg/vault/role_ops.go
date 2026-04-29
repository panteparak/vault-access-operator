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
)

// ListKubernetesAuthRoles returns all role names under the Kubernetes auth mount
func (c *Client) ListKubernetesAuthRoles(ctx context.Context, authPath string) ([]string, error) {
	if authPath == "" {
		authPath = DefaultKubernetesAuthPath
	}
	path := fmt.Sprintf("%s/role", authPath)
	secret, err := c.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles at %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, nil
	}

	roles := make([]string, 0, len(keys))
	for _, key := range keys {
		if s, ok := key.(string); ok {
			roles = append(roles, s)
		}
	}
	return roles, nil
}

// WriteKubernetesAuthRole writes a Kubernetes auth role to Vault
func (c *Client) WriteKubernetesAuthRole(
	ctx context.Context, authPath, roleName string, data map[string]interface{},
) error {
	if authPath == "" {
		authPath = DefaultKubernetesAuthPath
	}
	path := fmt.Sprintf("%s/role/%s", authPath, roleName)
	_, err := c.Logical().WriteWithContext(ctx, path, data)
	return err
}

// ReadKubernetesAuthRole reads a Kubernetes auth role from Vault
func (c *Client) ReadKubernetesAuthRole(
	ctx context.Context, authPath, roleName string,
) (map[string]interface{}, error) {
	if authPath == "" {
		authPath = DefaultKubernetesAuthPath
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
		authPath = DefaultKubernetesAuthPath
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
