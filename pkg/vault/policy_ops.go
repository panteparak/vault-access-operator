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

import "context"

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

// ListPolicies returns all policy names in Vault
func (c *Client) ListPolicies(ctx context.Context) ([]string, error) {
	return c.Sys().ListPoliciesWithContext(ctx)
}
