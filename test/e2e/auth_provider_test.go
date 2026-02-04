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
	"context"
	"fmt"
	"net/http"
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
	ctx := context.Background()

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return "", fmt.Errorf("failed to get vault client: %w", err)
	}

	ginkgo.By("enabling Kubernetes auth method")
	err = vaultClient.EnableAuth(ctx, "kubernetes", "kubernetes")
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return "", fmt.Errorf("failed to enable kubernetes auth: %w", err)
	}

	ginkgo.By("getting token_reviewer_jwt from vault-auth service account")
	reviewerJWT, err := utils.CreateServiceAccountTokenClientGo(
		ctx, vaultAuthNamespace, vaultAuthSA,
	)
	if err != nil {
		return "", fmt.Errorf("failed to get vault-auth SA token: %w", err)
	}

	ginkgo.By("getting Kubernetes CA certificate")
	caCert, err := utils.GetKubernetesCA()
	if err != nil {
		return "", fmt.Errorf("failed to get Kubernetes CA cert: %w", err)
	}

	ginkgo.By("configuring Kubernetes auth with token reviewer and CA cert")
	err = vaultClient.WriteKubernetesAuthConfig(
		ctx, "kubernetes",
		"https://kubernetes.default.svc.cluster.local:443",
		strings.TrimSpace(reviewerJWT),
		strings.TrimSpace(caCert),
	)
	if err != nil {
		return "", fmt.Errorf("failed to configure kubernetes auth: %w", err)
	}

	return "", nil
}

func (p *KubernetesAuthProvider) GetToken(
	namespace, serviceAccount string,
) (string, error) {
	ctx := context.Background()
	return utils.CreateServiceAccountTokenClientGo(
		ctx, namespace, serviceAccount,
	)
}

func (p *KubernetesAuthProvider) Login(
	role, token string,
) (string, error) {
	ctx := context.Background()
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return "", err
	}
	return vaultClient.LoginKubernetes(
		ctx, "kubernetes", role, token,
	)
}

func (p *KubernetesAuthProvider) CreateRole(
	roleName, namespace, serviceAccount string,
	policies []string,
) error {
	ctx := context.Background()
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return err
	}
	return vaultClient.WriteAuthRole(
		ctx, "kubernetes", roleName,
		map[string]interface{}{
			"bound_service_account_names":      serviceAccount,
			"bound_service_account_namespaces": namespace,
			"policies":                         strings.Join(policies, ","),
			"ttl":                              "1h",
		},
	)
}

func (p *KubernetesAuthProvider) DeleteRole(
	roleName string,
) error {
	ctx := context.Background()
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return err
	}
	return vaultClient.DeleteAuthRole(
		ctx, "kubernetes", roleName,
	)
}

func (p *KubernetesAuthProvider) Cleanup() error {
	// Don't disable kubernetes auth - other tests may use it
	return nil
}

func (p *KubernetesAuthProvider) AuthPath() string {
	return p.authPath
}

// JWTAuthProvider uses Vault's JWT auth method with Kubernetes JWKS.
type JWTAuthProvider struct {
	authPath string
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
	ctx := context.Background()

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return "", fmt.Errorf("failed to get vault client: %w", err)
	}

	ginkgo.By("enabling JWT auth method")
	err = vaultClient.EnableAuth(ctx, "jwt", "jwt")
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return "", fmt.Errorf("failed to enable jwt auth: %w", err)
	}

	// Reuse the already-migrated configureJWTAuthAtPath from e2e_suite_test.go
	if err := configureJWTAuthAtPath("auth/jwt"); err != nil {
		if strings.Contains(err.Error(), "cannot reach") ||
			strings.Contains(err.Error(), "connection refused") {
			return fmt.Sprintf(
				"Vault cannot reach OIDC/JWKS endpoint: %v", err,
			), nil
		}
		return "", fmt.Errorf("failed to configure JWT auth: %w", err)
	}

	return "", nil
}

func (p *JWTAuthProvider) GetToken(
	namespace, serviceAccount string,
) (string, error) {
	ctx := context.Background()
	return utils.CreateServiceAccountTokenClientGo(
		ctx, namespace, serviceAccount,
	)
}

func (p *JWTAuthProvider) Login(
	role, token string,
) (string, error) {
	ctx := context.Background()
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return "", err
	}
	return vaultClient.LoginJWT(ctx, "jwt", role, token)
}

func (p *JWTAuthProvider) CreateRole(
	roleName, namespace, serviceAccount string,
	policies []string,
) error {
	ctx := context.Background()
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return err
	}
	return vaultClient.WriteAuthRole(
		ctx, "jwt", roleName,
		map[string]interface{}{
			"role_type":       "jwt",
			"bound_audiences": "https://kubernetes.default.svc.cluster.local",
			"bound_subject": fmt.Sprintf(
				"system:serviceaccount:%s:%s",
				namespace, serviceAccount,
			),
			"user_claim": "sub",
			"policies":   strings.Join(policies, ","),
			"ttl":        "1h",
		},
	)
}

func (p *JWTAuthProvider) DeleteRole(roleName string) error {
	ctx := context.Background()
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return err
	}
	return vaultClient.DeleteAuthRole(ctx, "jwt", roleName)
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
	ctx := context.Background()

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return "", fmt.Errorf("failed to get vault client: %w", err)
	}

	ginkgo.By("enabling AppRole auth method")
	err = vaultClient.EnableAuth(ctx, "approle", "approle")
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return "", fmt.Errorf("failed to enable approle auth: %w", err)
	}
	return "", nil
}

func (p *AppRoleAuthProvider) GetToken(
	_, _ string,
) (string, error) {
	ctx := context.Background()

	// AppRole doesn't use K8s service accounts - generate a secret_id instead
	if p.lastRoleName == "" {
		return "", fmt.Errorf(
			"no AppRole role created yet; call CreateRole first",
		)
	}

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return "", err
	}

	return vaultClient.GenerateAppRoleSecretID(
		ctx, "approle", p.lastRoleName,
	)
}

func (p *AppRoleAuthProvider) Login(
	role, secretID string,
) (string, error) {
	ctx := context.Background()

	roleID, ok := p.roleIDs[role]
	if !ok {
		return "", fmt.Errorf(
			"no role_id for role %q; call CreateRole first",
			role,
		)
	}

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return "", err
	}

	return vaultClient.LoginAppRole(
		ctx, "approle", roleID, secretID,
	)
}

func (p *AppRoleAuthProvider) CreateRole(
	roleName, _, _ string, policies []string,
) error {
	ctx := context.Background()

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return err
	}

	// Create the AppRole role (ignores namespace/serviceAccount)
	err = vaultClient.WriteAuthRole(
		ctx, "approle", roleName,
		map[string]interface{}{
			"policies":  strings.Join(policies, ","),
			"token_ttl": "1h",
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create AppRole role: %w", err)
	}

	// Read and store the role_id
	roleID, err := vaultClient.GetAppRoleRoleID(
		ctx, "approle", roleName,
	)
	if err != nil {
		return fmt.Errorf("failed to read role_id: %w", err)
	}
	p.roleIDs[roleName] = roleID
	p.lastRoleName = roleName

	return nil
}

func (p *AppRoleAuthProvider) DeleteRole(
	roleName string,
) error {
	ctx := context.Background()

	delete(p.roleIDs, roleName)

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return err
	}
	return vaultClient.DeleteAuthRole(
		ctx, "approle", roleName,
	)
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
// Instead, we mount a JWT auth engine at path "oidc" and validate Dex-issued tokens.
type OIDCAuthProvider struct {
	authPath string
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
	ctx := context.Background()

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return "", fmt.Errorf("failed to get vault client: %w", err)
	}

	ginkgo.By("enabling OIDC auth method (JWT engine at oidc path)")
	err = vaultClient.EnableAuth(ctx, "oidc", "jwt")
	if err != nil && !strings.Contains(err.Error(), "already in use") {
		return "", fmt.Errorf("failed to enable oidc (jwt) auth: %w", err)
	}

	ginkgo.By("checking Dex OIDC provider availability")
	resp, err := http.Get(dexDiscoveryURL) //nolint:gosec
	if err != nil {
		return fmt.Sprintf(
			"Dex not reachable at %s: %v",
			dexDiscoveryURL, err,
		), nil
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf(
			"Dex discovery returned status %d",
			resp.StatusCode,
		), nil
	}

	// Reuse the already-migrated configureOIDCAuth from e2e_suite_test.go
	if err := configureOIDCAuth(); err != nil {
		return "", fmt.Errorf(
			"failed to configure OIDC auth with Dex: %w", err,
		)
	}

	return "", nil
}

func (p *OIDCAuthProvider) GetToken(
	_, _ string,
) (string, error) {
	return getDexToken(dexClientID, dexClientSecret)
}

func (p *OIDCAuthProvider) Login(
	role, token string,
) (string, error) {
	ctx := context.Background()
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return "", err
	}
	return vaultClient.LoginJWT(ctx, "oidc", role, token)
}

func (p *OIDCAuthProvider) CreateRole(
	roleName, _, _ string, policies []string,
) error {
	ctx := context.Background()

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return err
	}

	return vaultClient.WriteAuthRole(
		ctx, "oidc", roleName,
		map[string]interface{}{
			"role_type":       "jwt",
			"bound_audiences": dexClientID,
			"user_claim":      "email",
			"bound_claims":    fmt.Sprintf("email=%s", dexTestEmail),
			"policies":        strings.Join(policies, ","),
			"ttl":             "1h",
		},
	)
}

func (p *OIDCAuthProvider) DeleteRole(
	roleName string,
) error {
	ctx := context.Background()
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return err
	}
	return vaultClient.DeleteAuthRole(
		ctx, "oidc", roleName,
	)
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
			fmt.Fprintf(
				ginkgo.GinkgoWriter,
				"Auth provider %s setup failed: %v\n",
				p.Name(), err,
			)
			continue
		}
		if skipReason != "" {
			fmt.Fprintf(
				ginkgo.GinkgoWriter,
				"Auth provider %s skipped: %s\n",
				p.Name(), skipReason,
			)
			continue
		}
		available = append(available, p)
	}

	return available
}
