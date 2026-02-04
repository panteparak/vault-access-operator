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
	"net/http"
	"os/exec"
	"strings"

	"github.com/onsi/ginkgo/v2"

	"github.com/panteparak/vault-access-operator/test/utils"
)

const (
	// vaultAuthSA is the ServiceAccount in the vault namespace with TokenReview permissions.
	// Created by test/e2e/fixtures/vault.yaml along with the ClusterRoleBinding.
	vaultAuthSA        = "vault-auth"
	vaultAuthNamespace = "vault"
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

	// Get a token for the vault-auth ServiceAccount (has TokenReview permissions)
	ginkgo.By("getting token_reviewer_jwt from vault-auth service account")
	reviewerJWT, err := utils.GetServiceAccountToken(vaultAuthNamespace, vaultAuthSA)
	if err != nil {
		return "", fmt.Errorf("failed to get vault-auth SA token: %w", err)
	}
	reviewerJWT = strings.TrimSpace(reviewerJWT)

	// Get Kubernetes CA certificate from the vault pod's mounted SA
	ginkgo.By("getting Kubernetes CA certificate")
	cmd := exec.Command("kubectl", "exec", "-n", vaultAuthNamespace, "vault-0", "--",
		"cat", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	caCert, err := utils.Run(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to get Kubernetes CA cert: %w", err)
	}

	ginkgo.By("configuring Kubernetes auth with token reviewer and CA cert")
	_, err = utils.RunVaultCommand("write", "auth/kubernetes/config",
		"kubernetes_host=https://kubernetes.default.svc.cluster.local:443",
		fmt.Sprintf("token_reviewer_jwt=%s", reviewerJWT),
		fmt.Sprintf("kubernetes_ca_cert=%s", strings.TrimSpace(caCert)),
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

// AppRoleAuthProvider uses Vault's AppRole auth method.
// AppRole uses role_id + secret_id pairs instead of Kubernetes service account tokens.
// The provider maps the AuthProvider interface onto AppRole semantics:
// GetToken() generates a secret_id, Login() combines stored role_id with the secret_id.
type AppRoleAuthProvider struct {
	authPath     string
	roleIDs      map[string]string // roleName -> role_id
	lastRoleName string            // tracks the last created role for GetToken()
}

func NewAppRoleAuthProvider() *AppRoleAuthProvider {
	return &AppRoleAuthProvider{
		authPath: "auth/approle",
		roleIDs:  make(map[string]string),
	}
}

func (p *AppRoleAuthProvider) Name() string {
	return "approle"
}

func (p *AppRoleAuthProvider) Setup() (string, error) {
	ginkgo.By("enabling AppRole auth method")
	_, err := utils.RunVaultCommand("auth", "enable", "approle")
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return "", fmt.Errorf("failed to enable approle auth: %w", err)
	}
	return "", nil
}

func (p *AppRoleAuthProvider) GetToken(_, _ string) (string, error) {
	// AppRole doesn't use K8s service accounts — generate a secret_id instead
	if p.lastRoleName == "" {
		return "", fmt.Errorf("no AppRole role has been created yet; call CreateRole first")
	}
	output, err := utils.GenerateAppRoleSecretID(p.authPath, p.lastRoleName)
	if err != nil {
		return "", fmt.Errorf("failed to generate secret_id: %w", err)
	}

	var resp struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		return "", fmt.Errorf("failed to parse secret_id response: %w", err)
	}
	return resp.Data.SecretID, nil
}

func (p *AppRoleAuthProvider) Login(role, secretID string) (string, error) {
	roleID, ok := p.roleIDs[role]
	if !ok {
		return "", fmt.Errorf("no role_id found for role %q; call CreateRole first", role)
	}

	output, err := utils.VaultLoginWithAppRole(p.authPath, roleID, secretID)
	if err != nil {
		return "", err
	}

	var resp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		return "", fmt.Errorf("failed to parse AppRole login response: %w", err)
	}
	return resp.Auth.ClientToken, nil
}

func (p *AppRoleAuthProvider) CreateRole(
	roleName, _, _ string, policies []string,
) error {
	// Create the AppRole role (ignores namespace/serviceAccount — AppRole doesn't use them)
	args := []string{
		"write", fmt.Sprintf("%s/role/%s", p.authPath, roleName),
		fmt.Sprintf("policies=%s", strings.Join(policies, ",")),
		"token_ttl=1h",
	}
	_, err := utils.RunVaultCommand(args...)
	if err != nil {
		return fmt.Errorf("failed to create AppRole role: %w", err)
	}

	// Read and store the role_id
	output, err := utils.GetAppRoleRoleID(p.authPath, roleName)
	if err != nil {
		return fmt.Errorf("failed to read role_id: %w", err)
	}

	var resp struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		return fmt.Errorf("failed to parse role_id response: %w", err)
	}
	p.roleIDs[roleName] = resp.Data.RoleID
	p.lastRoleName = roleName

	return nil
}

func (p *AppRoleAuthProvider) DeleteRole(roleName string) error {
	delete(p.roleIDs, roleName)
	_, err := utils.RunVaultCommand("delete", fmt.Sprintf("%s/role/%s", p.authPath, roleName))
	return err
}

func (p *AppRoleAuthProvider) Cleanup() error {
	// Don't disable approle auth - other tests may use it
	return nil
}

func (p *AppRoleAuthProvider) AuthPath() string {
	return p.authPath
}

// OIDCAuthProvider uses Vault's JWT auth method mounted at the "oidc" path.
// Vault's native role_type="oidc" requires an interactive browser flow (unusable in CI).
// Instead, we mount a JWT auth engine at path "oidc" and validate K8s SA tokens against
// the cluster's built-in OIDC issuer. This mirrors real-world EKS/GKE/AKS behavior where
// the cloud provider supplies an OIDC issuer for service account tokens.
type OIDCAuthProvider struct {
	authPath string
	issuer   string
}

func NewOIDCAuthProvider() *OIDCAuthProvider {
	return &OIDCAuthProvider{
		authPath: "auth/oidc",
	}
}

func (p *OIDCAuthProvider) Name() string {
	return "oidc"
}

func (p *OIDCAuthProvider) Setup() (string, error) {
	ginkgo.By("enabling OIDC auth method (JWT engine at oidc path)")
	_, err := utils.RunVaultCommand("auth", "enable", "-path=oidc", "jwt")
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return "", fmt.Errorf("failed to enable oidc (jwt) auth: %w", err)
	}

	ginkgo.By("checking Dex OIDC provider availability")
	resp, err := http.Get(dexDiscoveryURL)
	if err != nil {
		return fmt.Sprintf("Dex not reachable at %s: %v", dexDiscoveryURL, err), nil
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("Dex discovery returned status %d", resp.StatusCode), nil
	}

	ginkgo.By("configuring OIDC auth with Dex OIDC discovery")
	_, err = utils.RunVaultCommand("write", "auth/oidc/config",
		fmt.Sprintf("oidc_discovery_url=%s", dexIssuer),
		fmt.Sprintf("bound_issuer=%s", dexIssuer),
	)
	if err != nil {
		return "", fmt.Errorf("failed to configure OIDC auth with Dex: %w", err)
	}

	p.issuer = dexIssuer
	return "", nil
}

func (p *OIDCAuthProvider) GetToken(_, _ string) (string, error) {
	return getDexToken(dexClientID, dexClientSecret)
}

func (p *OIDCAuthProvider) Login(role, token string) (string, error) {
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
		return "", fmt.Errorf("failed to parse OIDC login response: %w", err)
	}
	return resp.Auth.ClientToken, nil
}

func (p *OIDCAuthProvider) CreateRole(
	roleName, _, _ string, policies []string,
) error {
	args := []string{
		"write", fmt.Sprintf("auth/oidc/role/%s", roleName),
		"role_type=jwt",
		fmt.Sprintf("bound_audiences=%s", dexClientID),
		"user_claim=email",
		fmt.Sprintf("bound_claims=email=%s", dexTestEmail),
		fmt.Sprintf("policies=%s", strings.Join(policies, ",")),
		"ttl=1h",
	}
	_, err := utils.RunVaultCommand(args...)
	return err
}

func (p *OIDCAuthProvider) DeleteRole(roleName string) error {
	_, err := utils.RunVaultCommand("delete", fmt.Sprintf("auth/oidc/role/%s", roleName))
	return err
}

func (p *OIDCAuthProvider) Cleanup() error {
	// Don't disable oidc auth - other tests may use it
	return nil
}

func (p *OIDCAuthProvider) AuthPath() string {
	return p.authPath
}

// GetAvailableAuthProviders returns all auth providers that are available
// in the current environment. Providers that can't be set up are skipped.
func GetAvailableAuthProviders() []AuthProvider {
	providers := []AuthProvider{
		NewKubernetesAuthProvider(),
		NewJWTAuthProvider(),
		NewAppRoleAuthProvider(),
		NewOIDCAuthProvider(),
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
