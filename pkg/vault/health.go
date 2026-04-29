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

// IsHealthy checks if Vault is healthy and the client can connect
func (c *Client) IsHealthy(ctx context.Context) (bool, error) {
	health, err := c.Sys().HealthWithContext(ctx)
	if err != nil {
		return false, fmt.Errorf("vault health check failed: %w", err)
	}
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
