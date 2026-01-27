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

package utils

import (
	"context"
	"fmt"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// Default auth method paths
const (
	DefaultJWTAuthPath  = "jwt"
	DefaultOIDCAuthPath = "oidc"
)

// VaultAuthHelper provides utilities for configuring Vault auth methods in tests.
type VaultAuthHelper struct {
	client *vault.Client
}

// NewVaultAuthHelper creates a new VaultAuthHelper with the given Vault client.
func NewVaultAuthHelper(client *vault.Client) *VaultAuthHelper {
	return &VaultAuthHelper{client: client}
}

// NewVaultAuthHelperFromAddress creates a VaultAuthHelper by connecting to a Vault server.
func NewVaultAuthHelperFromAddress(address, token string) (*VaultAuthHelper, error) {
	config := vault.DefaultConfig()
	config.Address = address

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	client.SetToken(token)
	return &VaultAuthHelper{client: client}, nil
}

// JWTAuthConfig contains configuration for JWT auth method
type JWTAuthConfig struct {
	// Path is the mount path for the auth method (default: "jwt")
	Path string
	// BoundIssuer validates the iss claim
	BoundIssuer string
	// JWTValidationPubKeys is a list of PEM-encoded public keys
	JWTValidationPubKeys []string
	// JWKSURL for fetching public keys dynamically
	JWKSURL string
	// DefaultRole is the default role to use
	DefaultRole string
}

// JWTRoleConfig contains configuration for a JWT role
type JWTRoleConfig struct {
	// Name is the role name
	Name string
	// RoleType is "jwt" or "oidc"
	RoleType string
	// BoundAudiences restricts the "aud" claim
	BoundAudiences []string
	// BoundSubject restricts the "sub" claim
	BoundSubject string
	// BoundClaims is a map of claim restrictions
	BoundClaims map[string]interface{}
	// UserClaim is the claim to use as the Vault username
	UserClaim string
	// GroupsClaim is the claim containing group membership
	GroupsClaim string
	// TokenPolicies are the policies to attach to the token
	TokenPolicies []string
	// TokenTTL is the default token TTL
	TokenTTL string
	// TokenMaxTTL is the maximum token TTL
	TokenMaxTTL string
}

// OIDCAuthConfig contains configuration for OIDC auth method
type OIDCAuthConfig struct {
	// Path is the mount path for the auth method (default: "oidc")
	Path string
	// OIDCDiscoveryURL is the OIDC provider URL
	OIDCDiscoveryURL string
	// OIDCDiscoveryCAPEM is the CA certificate for the discovery URL
	OIDCDiscoveryCAPEM string
	// OIDCClientID is the OAuth client ID
	OIDCClientID string
	// OIDCClientSecret is the OAuth client secret
	OIDCClientSecret string
	// DefaultRole is the default role to use
	DefaultRole string
}

// OIDCRoleConfig contains configuration for an OIDC role
type OIDCRoleConfig struct {
	// Name is the role name
	Name string
	// AllowedRedirectURIs for OIDC callback
	AllowedRedirectURIs []string
	// BoundAudiences restricts the "aud" claim
	BoundAudiences []string
	// BoundClaims is a map of claim restrictions
	BoundClaims map[string]interface{}
	// UserClaim is the claim to use as the Vault username
	UserClaim string
	// GroupsClaim is the claim containing group membership
	GroupsClaim string
	// TokenPolicies are the policies to attach to the token
	TokenPolicies []string
	// TokenTTL is the default token TTL
	TokenTTL string
	// TokenMaxTTL is the maximum token TTL
	TokenMaxTTL string
}

// EnableJWTAuth enables the JWT auth method at the specified path.
func (h *VaultAuthHelper) EnableJWTAuth(ctx context.Context, path string) error {
	if path == "" {
		path = DefaultJWTAuthPath
	}

	// Check if already enabled
	mounts, err := h.client.Sys().ListAuthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to list auth mounts: %w", err)
	}

	mountPath := path + "/"
	if _, ok := mounts[mountPath]; ok {
		// Already enabled
		return nil
	}

	options := &vault.MountInput{
		Type:        "jwt",
		Description: "JWT auth for testing",
	}

	if err := h.client.Sys().EnableAuthWithOptionsWithContext(ctx, path, options); err != nil {
		return fmt.Errorf("failed to enable JWT auth: %w", err)
	}

	return nil
}

// ConfigureJWTAuth configures the JWT auth method.
func (h *VaultAuthHelper) ConfigureJWTAuth(ctx context.Context, config JWTAuthConfig) error {
	path := config.Path
	if path == "" {
		path = DefaultJWTAuthPath
	}

	data := map[string]interface{}{}

	if config.BoundIssuer != "" {
		data["bound_issuer"] = config.BoundIssuer
	}
	if len(config.JWTValidationPubKeys) > 0 {
		data["jwt_validation_pubkeys"] = strings.Join(config.JWTValidationPubKeys, ",")
	}
	if config.JWKSURL != "" {
		data["jwks_url"] = config.JWKSURL
	}
	if config.DefaultRole != "" {
		data["default_role"] = config.DefaultRole
	}

	_, err := h.client.Logical().WriteWithContext(ctx, fmt.Sprintf("auth/%s/config", path), data)
	if err != nil {
		return fmt.Errorf("failed to configure JWT auth: %w", err)
	}

	return nil
}

// CreateJWTRole creates a JWT role.
func (h *VaultAuthHelper) CreateJWTRole(ctx context.Context, path string, config JWTRoleConfig) error {
	if path == "" {
		path = DefaultJWTAuthPath
	}

	data := map[string]interface{}{
		"role_type":  config.RoleType,
		"user_claim": config.UserClaim,
	}

	if config.RoleType == "" {
		data["role_type"] = "jwt"
	}
	if config.UserClaim == "" {
		data["user_claim"] = "sub"
	}

	if len(config.BoundAudiences) > 0 {
		data["bound_audiences"] = config.BoundAudiences
	}
	if config.BoundSubject != "" {
		data["bound_subject"] = config.BoundSubject
	}
	if config.BoundClaims != nil {
		data["bound_claims"] = config.BoundClaims
	}
	if config.GroupsClaim != "" {
		data["groups_claim"] = config.GroupsClaim
	}
	if len(config.TokenPolicies) > 0 {
		data["token_policies"] = config.TokenPolicies
	}
	if config.TokenTTL != "" {
		data["token_ttl"] = config.TokenTTL
	}
	if config.TokenMaxTTL != "" {
		data["token_max_ttl"] = config.TokenMaxTTL
	}

	_, err := h.client.Logical().WriteWithContext(ctx, fmt.Sprintf("auth/%s/role/%s", path, config.Name), data)
	if err != nil {
		return fmt.Errorf("failed to create JWT role: %w", err)
	}

	return nil
}

// DeleteJWTRole deletes a JWT role.
func (h *VaultAuthHelper) DeleteJWTRole(ctx context.Context, path, roleName string) error {
	if path == "" {
		path = DefaultJWTAuthPath
	}

	_, err := h.client.Logical().DeleteWithContext(ctx, fmt.Sprintf("auth/%s/role/%s", path, roleName))
	if err != nil {
		return fmt.Errorf("failed to delete JWT role: %w", err)
	}

	return nil
}

// EnableOIDCAuth enables the OIDC auth method at the specified path.
func (h *VaultAuthHelper) EnableOIDCAuth(ctx context.Context, path string) error {
	if path == "" {
		path = DefaultOIDCAuthPath
	}

	// Check if already enabled
	mounts, err := h.client.Sys().ListAuthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to list auth mounts: %w", err)
	}

	mountPath := path + "/"
	if _, ok := mounts[mountPath]; ok {
		return nil
	}

	options := &vault.MountInput{
		Type:        "oidc",
		Description: "OIDC auth for testing",
	}

	if err := h.client.Sys().EnableAuthWithOptionsWithContext(ctx, path, options); err != nil {
		return fmt.Errorf("failed to enable OIDC auth: %w", err)
	}

	return nil
}

// ConfigureOIDCAuth configures the OIDC auth method.
func (h *VaultAuthHelper) ConfigureOIDCAuth(ctx context.Context, config OIDCAuthConfig) error {
	path := config.Path
	if path == "" {
		path = DefaultOIDCAuthPath
	}

	data := map[string]interface{}{}

	if config.OIDCDiscoveryURL != "" {
		data["oidc_discovery_url"] = config.OIDCDiscoveryURL
	}
	if config.OIDCDiscoveryCAPEM != "" {
		data["oidc_discovery_ca_pem"] = config.OIDCDiscoveryCAPEM
	}
	if config.OIDCClientID != "" {
		data["oidc_client_id"] = config.OIDCClientID
	}
	if config.OIDCClientSecret != "" {
		data["oidc_client_secret"] = config.OIDCClientSecret
	}
	if config.DefaultRole != "" {
		data["default_role"] = config.DefaultRole
	}

	_, err := h.client.Logical().WriteWithContext(ctx, fmt.Sprintf("auth/%s/config", path), data)
	if err != nil {
		return fmt.Errorf("failed to configure OIDC auth: %w", err)
	}

	return nil
}

// CreateOIDCRole creates an OIDC role.
func (h *VaultAuthHelper) CreateOIDCRole(ctx context.Context, path string, config OIDCRoleConfig) error {
	if path == "" {
		path = DefaultOIDCAuthPath
	}

	data := map[string]interface{}{
		"user_claim": config.UserClaim,
	}

	if config.UserClaim == "" {
		data["user_claim"] = "sub"
	}

	if len(config.AllowedRedirectURIs) > 0 {
		data["allowed_redirect_uris"] = config.AllowedRedirectURIs
	}
	if len(config.BoundAudiences) > 0 {
		data["bound_audiences"] = config.BoundAudiences
	}
	if config.BoundClaims != nil {
		data["bound_claims"] = config.BoundClaims
	}
	if config.GroupsClaim != "" {
		data["groups_claim"] = config.GroupsClaim
	}
	if len(config.TokenPolicies) > 0 {
		data["token_policies"] = config.TokenPolicies
	}
	if config.TokenTTL != "" {
		data["token_ttl"] = config.TokenTTL
	}
	if config.TokenMaxTTL != "" {
		data["token_max_ttl"] = config.TokenMaxTTL
	}

	_, err := h.client.Logical().WriteWithContext(ctx, fmt.Sprintf("auth/%s/role/%s", path, config.Name), data)
	if err != nil {
		return fmt.Errorf("failed to create OIDC role: %w", err)
	}

	return nil
}

// DeleteOIDCRole deletes an OIDC role.
func (h *VaultAuthHelper) DeleteOIDCRole(ctx context.Context, path, roleName string) error {
	if path == "" {
		path = DefaultOIDCAuthPath
	}

	_, err := h.client.Logical().DeleteWithContext(ctx, fmt.Sprintf("auth/%s/role/%s", path, roleName))
	if err != nil {
		return fmt.Errorf("failed to delete OIDC role: %w", err)
	}

	return nil
}

// DisableAuth disables an auth method at the specified path.
func (h *VaultAuthHelper) DisableAuth(ctx context.Context, path string) error {
	if err := h.client.Sys().DisableAuthWithContext(ctx, path); err != nil {
		// Ignore "not found" errors
		if !strings.Contains(err.Error(), "no matching mount") {
			return fmt.Errorf("failed to disable auth: %w", err)
		}
	}
	return nil
}

// LoginWithJWT performs a JWT login and returns the auth response.
func (h *VaultAuthHelper) LoginWithJWT(ctx context.Context, path, role, jwt string) (*vault.Secret, error) {
	if path == "" {
		path = DefaultJWTAuthPath
	}

	data := map[string]interface{}{
		"role": role,
		"jwt":  jwt,
	}

	return h.client.Logical().WriteWithContext(ctx, fmt.Sprintf("auth/%s/login", path), data)
}

// CreateTestPolicy creates a simple test policy in Vault.
func (h *VaultAuthHelper) CreateTestPolicy(ctx context.Context, name, hcl string) error {
	if err := h.client.Sys().PutPolicyWithContext(ctx, name, hcl); err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}
	return nil
}

// DeletePolicy deletes a policy from Vault.
func (h *VaultAuthHelper) DeletePolicy(ctx context.Context, name string) error {
	if err := h.client.Sys().DeletePolicyWithContext(ctx, name); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}
	return nil
}

// Client returns the underlying Vault client.
func (h *VaultAuthHelper) Client() *vault.Client {
	return h.client
}
