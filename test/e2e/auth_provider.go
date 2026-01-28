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

package e2e

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/onsi/ginkgo/v2"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// AuthProvider abstracts different Vault authentication methods for testing.
// This allows the same test cases to run against different auth backends.
type AuthProvider interface {
	// Name returns the human-readable name of the auth method
	Name() string

	// Setup configures the auth method in Vault. Returns skip reason if not available.
	Setup() (skipReason string, err error)

	// GetToken retrieves an authentication token for the given service account
	GetToken(namespace, serviceAccount string) (string, error)

	// Login authenticates to Vault and returns a Vault token
	Login(role, token string) (vaultToken string, err error)

	// CreateRole creates a Vault role for the given service account
	CreateRole(roleName, namespace, serviceAccount string, policies []string) error

	// DeleteRole removes a Vault role
	DeleteRole(roleName string) error

	// Cleanup removes all resources created by Setup
	Cleanup() error

	// AuthPath returns the Vault auth path (e.g., "auth/kubernetes", "auth/jwt")
	AuthPath() string
}

// TokenAuthProvider uses direct Vault token authentication.
// This is the simplest auth method - just use an existing token.
type TokenAuthProvider struct {
	token string
}

func NewTokenAuthProvider(token string) *TokenAuthProvider {
	return &TokenAuthProvider{token: token}
}

func (p *TokenAuthProvider) Name() string {
	return "token"
}

func (p *TokenAuthProvider) Setup() (string, error) {
	// Token auth is always available
	return "", nil
}

func (p *TokenAuthProvider) GetToken(_, _ string) (string, error) {
	return p.token, nil
}

func (p *TokenAuthProvider) Login(_, _ string) (string, error) {
	return p.token, nil
}

func (p *TokenAuthProvider) CreateRole(_, _, _ string, _ []string) error {
	// Token auth doesn't use roles
	return nil
}

func (p *TokenAuthProvider) DeleteRole(_ string) error {
	return nil
}

func (p *TokenAuthProvider) Cleanup() error {
	return nil
}

func (p *TokenAuthProvider) AuthPath() string {
	return "auth/token"
}

// KubernetesAuthProvider uses Vault's Kubernetes auth method.
type KubernetesAuthProvider struct {
	authPath string
}

func NewKubernetesAuthProvider() *KubernetesAuthProvider {
	return &KubernetesAuthProvider{
		authPath: "auth/kubernetes",
	}
}

func (p *KubernetesAuthProvider) Name() string {
	return "kubernetes"
}

func (p *KubernetesAuthProvider) Setup() (string, error) {
	ginkgo.By("enabling Kubernetes auth method")
	_, err := utils.RunVaultCommand("auth", "enable", "kubernetes")
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return "", fmt.Errorf("failed to enable kubernetes auth: %w", err)
	}

	ginkgo.By("configuring Kubernetes auth")
	_, err = utils.RunVaultCommand("write", "auth/kubernetes/config",
		"kubernetes_host=https://kubernetes.default.svc.cluster.local:443",
	)
	if err != nil {
		return "", fmt.Errorf("failed to configure kubernetes auth: %w", err)
	}

	return "", nil
}

func (p *KubernetesAuthProvider) GetToken(namespace, serviceAccount string) (string, error) {
	return utils.GetServiceAccountToken(namespace, serviceAccount)
}

func (p *KubernetesAuthProvider) Login(role, token string) (string, error) {
	output, err := utils.RunVaultCommand("write", "-format=json",
		"auth/kubernetes/login",
		"role="+role,
		"jwt="+token,
	)
	if err != nil {
		return "", err
	}

	var resp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		return "", err
	}
	return resp.Auth.ClientToken, nil
}

func (p *KubernetesAuthProvider) CreateRole(
	roleName, namespace, serviceAccount string, policies []string,
) error {
	args := []string{
		"write", fmt.Sprintf("auth/kubernetes/role/%s", roleName),
		fmt.Sprintf("bound_service_account_names=%s", serviceAccount),
		fmt.Sprintf("bound_service_account_namespaces=%s", namespace),
		fmt.Sprintf("policies=%s", strings.Join(policies, ",")),
		"ttl=1h",
	}
	_, err := utils.RunVaultCommand(args...)
	return err
}

func (p *KubernetesAuthProvider) DeleteRole(roleName string) error {
	_, err := utils.RunVaultCommand("delete", fmt.Sprintf("auth/kubernetes/role/%s", roleName))
	return err
}

func (p *KubernetesAuthProvider) Cleanup() error {
	// Don't disable kubernetes auth - other tests may use it
	return nil
}

func (p *KubernetesAuthProvider) AuthPath() string {
	return p.authPath
}

// JWTAuthProvider uses Vault's JWT auth method with Kubernetes JWKS.
// This approach uses JWKS directly instead of OIDC discovery, making it
// work reliably in k3d/kind environments where Vault can't reach the
// Kubernetes API server's OIDC endpoint.
type JWTAuthProvider struct {
	authPath string
	issuer   string
}

func NewJWTAuthProvider() *JWTAuthProvider {
	return &JWTAuthProvider{
		authPath: "auth/jwt",
	}
}

func (p *JWTAuthProvider) Name() string {
	return "jwt"
}

func (p *JWTAuthProvider) Setup() (string, error) {
	ginkgo.By("enabling JWT auth method")
	_, err := utils.RunVaultCommand("auth", "enable", "jwt")
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return "", fmt.Errorf("failed to enable jwt auth: %w", err)
	}

	// Get OIDC configuration to find the issuer
	ginkgo.By("getting Kubernetes OIDC configuration")
	cmd := exec.Command("kubectl", "get", "--raw", "/.well-known/openid-configuration")
	output, err := utils.Run(cmd)
	if err != nil {
		return "Kubernetes OIDC discovery not available", nil
	}

	var oidcConfig struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal([]byte(output), &oidcConfig); err != nil {
		return fmt.Sprintf("failed to parse OIDC config: %v", err), nil
	}
	p.issuer = oidcConfig.Issuer

	// Get JWKS directly from Kubernetes API (this works locally, no network call from Vault)
	ginkgo.By("fetching JWKS from Kubernetes API")
	cmd = exec.Command("kubectl", "get", "--raw", "/openid/v1/jwks")
	jwksOutput, err := utils.Run(cmd)
	if err != nil {
		return "failed to get JWKS from Kubernetes", nil
	}

	// Configure JWT auth with JWKS directly (bypasses OIDC discovery)
	ginkgo.By("configuring JWT auth with JWKS (bypassing OIDC discovery)")
	_, err = utils.RunVaultCommand("write", "auth/jwt/config",
		fmt.Sprintf("jwt_validation_pubkeys=%s", jwksOutput),
		fmt.Sprintf("bound_issuer=%s", p.issuer),
	)
	if err != nil {
		// Fall back to trying OIDC discovery
		ginkgo.By("JWKS config failed, trying OIDC discovery")
		_, err = utils.RunVaultCommand("write", "auth/jwt/config",
			fmt.Sprintf("oidc_discovery_url=%s", p.issuer),
			fmt.Sprintf("bound_issuer=%s", p.issuer),
		)
		if err != nil {
			if strings.Contains(err.Error(), "error checking oidc discovery URL") ||
				strings.Contains(err.Error(), "fetching keys") ||
				strings.Contains(err.Error(), "connection refused") ||
				strings.Contains(err.Error(), "no such host") {
				return fmt.Sprintf("Vault cannot reach OIDC/JWKS endpoint (%s)", p.issuer), nil
			}
			return "", fmt.Errorf("failed to configure JWT auth: %w", err)
		}
	}

	return "", nil
}

func (p *JWTAuthProvider) GetToken(namespace, serviceAccount string) (string, error) {
	return utils.GetServiceAccountToken(namespace, serviceAccount)
}

func (p *JWTAuthProvider) Login(role, token string) (string, error) {
	output, err := utils.VaultLoginWithJWT(p.authPath, role, token)
	if err != nil {
		return "", err
	}

	var resp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		return "", fmt.Errorf("failed to parse JWT login response: %w", err)
	}
	return resp.Auth.ClientToken, nil
}

func (p *JWTAuthProvider) CreateRole(
	roleName, namespace, serviceAccount string, policies []string,
) error {
	args := []string{
		"write", fmt.Sprintf("auth/jwt/role/%s", roleName),
		"role_type=jwt",
		"bound_audiences=https://kubernetes.default.svc.cluster.local",
		fmt.Sprintf("bound_subject=system:serviceaccount:%s:%s", namespace, serviceAccount),
		"user_claim=sub",
		fmt.Sprintf("policies=%s", strings.Join(policies, ",")),
		"ttl=1h",
	}
	_, err := utils.RunVaultCommand(args...)
	return err
}

func (p *JWTAuthProvider) DeleteRole(roleName string) error {
	_, err := utils.RunVaultCommand("delete", fmt.Sprintf("auth/jwt/role/%s", roleName))
	return err
}

func (p *JWTAuthProvider) Cleanup() error {
	// Don't disable jwt auth - other tests may use it
	return nil
}

func (p *JWTAuthProvider) AuthPath() string {
	return p.authPath
}

// GetAvailableAuthProviders returns all auth providers that are available
// in the current environment. Providers that can't be set up are skipped.
func GetAvailableAuthProviders() []AuthProvider {
	providers := []AuthProvider{
		NewKubernetesAuthProvider(),
		NewJWTAuthProvider(),
	}

	var available []AuthProvider
	for _, p := range providers {
		skipReason, err := p.Setup()
		if err != nil {
			fmt.Fprintf(ginkgo.GinkgoWriter, "Auth provider %s setup failed: %v\n", p.Name(), err)
			continue
		}
		if skipReason != "" {
			fmt.Fprintf(ginkgo.GinkgoWriter, "Auth provider %s skipped: %s\n", p.Name(), skipReason)
			continue
		}
		available = append(available, p)
	}

	return available
}
