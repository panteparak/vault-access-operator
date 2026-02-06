package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const (
	// ManagedBasePath is the base path in Vault for storing managed resource metadata
	ManagedBasePath = "secret/data/vault-access-operator/managed"

	// ManagedPoliciesPath stores metadata about managed policies
	ManagedPoliciesPath = ManagedBasePath + "/policies"

	// ManagedRolesPath stores metadata about managed roles
	ManagedRolesPath = ManagedBasePath + "/roles"
)

// ManagedResource represents metadata about a managed Vault resource
type ManagedResource struct {
	// K8sResource is the Kubernetes resource reference (namespace/name or just name for cluster-scoped)
	K8sResource string `json:"k8sResource"`

	// ManagedAt is when this resource was first managed
	ManagedAt time.Time `json:"managedAt"`

	// LastUpdated is when this resource was last updated
	LastUpdated time.Time `json:"lastUpdated"`
}

// markManaged is the shared implementation for MarkPolicyManaged / MarkRoleManaged.
func (c *Client) markManaged(ctx context.Context, basePath, resourceName, k8sResource, resourceType string) error {
	path := fmt.Sprintf("%s/%s", basePath, resourceName)

	now := time.Now()
	metadata := ManagedResource{
		K8sResource: k8sResource,
		ManagedAt:   now,
		LastUpdated: now,
	}

	// Check if already managed to preserve ManagedAt
	existing, _ := c.getManaged(ctx, basePath, resourceName, resourceType)
	if existing != nil {
		metadata.ManagedAt = existing.ManagedAt
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal managed metadata: %w", err)
	}

	_, err = c.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"data": map[string]interface{}{
			"metadata": string(data),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to mark %s as managed: %w", resourceType, err)
	}

	return nil
}

// getManaged is the shared implementation for getPolicyManaged / getRoleManaged.
func (c *Client) getManaged(
	ctx context.Context, basePath, resourceName, resourceType string,
) (*ManagedResource, error) {
	path := fmt.Sprintf("%s/%s", basePath, resourceName)

	secret, err := c.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read managed %s metadata: %w", resourceType, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, nil
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	metadataStr, ok := data["metadata"].(string)
	if !ok {
		return nil, nil
	}

	var metadata ManagedResource
	if err := json.Unmarshal([]byte(metadataStr), &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal managed metadata: %w", err)
	}

	return &metadata, nil
}

// removeManaged is the shared implementation for RemovePolicyManaged / RemoveRoleManaged.
func (c *Client) removeManaged(ctx context.Context, basePath, resourceName, resourceType string) error {
	path := fmt.Sprintf("%s/%s", basePath, resourceName)

	_, err := c.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to remove %s managed marker: %w", resourceType, err)
	}

	return nil
}

// MarkPolicyManaged marks a Vault policy as managed by the operator
func (c *Client) MarkPolicyManaged(ctx context.Context, policyName, k8sResource string) error {
	return c.markManaged(ctx, ManagedPoliciesPath, policyName, k8sResource, "policy")
}

// IsPolicyManaged checks if a policy is managed by the operator
func (c *Client) IsPolicyManaged(ctx context.Context, policyName string) (bool, error) {
	metadata, err := c.getManaged(ctx, ManagedPoliciesPath, policyName, "policy")
	if err != nil {
		return false, err
	}
	return metadata != nil, nil
}

// GetPolicyManagedBy returns the K8s resource that manages this policy
func (c *Client) GetPolicyManagedBy(ctx context.Context, policyName string) (string, error) {
	metadata, err := c.getManaged(ctx, ManagedPoliciesPath, policyName, "policy")
	if err != nil {
		return "", err
	}
	if metadata == nil {
		return "", nil
	}
	return metadata.K8sResource, nil
}

// RemovePolicyManaged removes the managed marker for a policy
func (c *Client) RemovePolicyManaged(ctx context.Context, policyName string) error {
	return c.removeManaged(ctx, ManagedPoliciesPath, policyName, "policy")
}

// MarkRoleManaged marks a Vault role as managed by the operator
func (c *Client) MarkRoleManaged(ctx context.Context, roleName, k8sResource string) error {
	return c.markManaged(ctx, ManagedRolesPath, roleName, k8sResource, "role")
}

// IsRoleManaged checks if a role is managed by the operator
func (c *Client) IsRoleManaged(ctx context.Context, roleName string) (bool, error) {
	metadata, err := c.getManaged(ctx, ManagedRolesPath, roleName, "role")
	if err != nil {
		return false, err
	}
	return metadata != nil, nil
}

// GetRoleManagedBy returns the K8s resource that manages this role
func (c *Client) GetRoleManagedBy(ctx context.Context, roleName string) (string, error) {
	metadata, err := c.getManaged(ctx, ManagedRolesPath, roleName, "role")
	if err != nil {
		return "", err
	}
	if metadata == nil {
		return "", nil
	}
	return metadata.K8sResource, nil
}

// RemoveRoleManaged removes the managed marker for a role
func (c *Client) RemoveRoleManaged(ctx context.Context, roleName string) error {
	return c.removeManaged(ctx, ManagedRolesPath, roleName, "role")
}
