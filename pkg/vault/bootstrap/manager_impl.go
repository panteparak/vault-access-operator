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

package bootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"github.com/panteparak/vault-access-operator/pkg/vault/token"
)

// managerImpl implements Manager.
type managerImpl struct {
	tokenProvider    token.TokenProvider
	clusterDiscovery K8sClusterDiscovery
	log              logr.Logger
}

// NewManager creates a new bootstrap Manager.
func NewManager(
	tokenProvider token.TokenProvider,
	clusterDiscovery K8sClusterDiscovery,
	log logr.Logger,
) Manager {
	return &managerImpl{
		tokenProvider:    tokenProvider,
		clusterDiscovery: clusterDiscovery,
		log:              log.WithName("bootstrap-manager"),
	}
}

// Bootstrap performs the full setup sequence.
func (m *managerImpl) Bootstrap(
	ctx context.Context,
	vaultClient VaultBootstrapClient,
	config *Config,
) (*Result, error) {
	m.log.Info("starting bootstrap process",
		"authMethodName", config.AuthMethodName,
		"operatorRole", config.OperatorRole,
	)

	// Apply defaults
	config = config.WithDefaults()

	result := &Result{
		AuthPath: "auth/" + config.AuthMethodName,
	}

	// Step 1: Enable Kubernetes auth method
	authMethodCreated, err := m.enableAuthMethod(ctx, vaultClient, config.AuthMethodName)
	if err != nil {
		return nil, fmt.Errorf("failed to enable auth method: %w", err)
	}
	result.AuthMethodCreated = authMethodCreated

	// Step 2: Get Kubernetes cluster configuration
	k8sConfig, err := m.getK8sConfig(ctx, config.KubernetesConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}

	// Step 3: Get token_reviewer_jwt
	// NOTE: Do NOT set Audiences here. The token_reviewer_jwt is used by Vault
	// as bearer auth to call the Kubernetes TokenReview API. It must have the
	// API server's default audience (not "vault") to be accepted.
	tokenInfo, err := m.tokenProvider.GetToken(ctx, token.GetTokenOptions{
		ServiceAccount: *config.TokenReviewerServiceAccount,
		Duration:       config.TokenReviewerDuration,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get token_reviewer_jwt: %w", err)
	}
	result.TokenReviewerExpiration = tokenInfo.ExpirationTime

	// Step 4: Configure Kubernetes auth
	if err := m.configureKubernetesAuth(ctx, vaultClient, config.AuthMethodName, k8sConfig, tokenInfo.Token); err != nil {
		return nil, fmt.Errorf("failed to configure kubernetes auth: %w", err)
	}

	// Step 5: Create operator role
	roleCreated, err := m.createOperatorRole(ctx, vaultClient, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create operator role: %w", err)
	}
	result.RoleCreated = roleCreated

	// Step 6: Test Kubernetes auth
	testPassed, err := m.testKubernetesAuth(ctx, vaultClient, config)
	if err != nil {
		m.log.Error(err, "kubernetes auth test failed")
		// Don't fail bootstrap, but record the failure
	}
	result.K8sAuthTestPassed = testPassed

	// Step 7: Revoke bootstrap token (if enabled)
	if config.AutoRevoke {
		if err := vaultClient.RevokeSelf(ctx); err != nil {
			m.log.Error(err, "failed to revoke bootstrap token")
			// Don't fail bootstrap for revocation failure
		} else {
			result.BootstrapRevoked = true
			m.log.Info("revoked bootstrap token")
		}
	}

	m.log.Info("bootstrap completed successfully",
		"authMethodCreated", result.AuthMethodCreated,
		"roleCreated", result.RoleCreated,
		"bootstrapRevoked", result.BootstrapRevoked,
		"k8sAuthTestPassed", result.K8sAuthTestPassed,
	)

	return result, nil
}

// enableAuthMethod enables the Kubernetes auth method if not already enabled.
func (m *managerImpl) enableAuthMethod(
	ctx context.Context,
	vaultClient VaultBootstrapClient,
	authMethodName string,
) (bool, error) {
	enabled, err := vaultClient.IsAuthEnabled(ctx, authMethodName)
	if err != nil {
		return false, fmt.Errorf("failed to check auth method: %w", err)
	}

	if enabled {
		m.log.Info("auth method already enabled", "path", authMethodName)
		return false, nil
	}

	m.log.Info("enabling auth method", "path", authMethodName)
	if err := vaultClient.EnableAuth(ctx, authMethodName, "kubernetes"); err != nil {
		return false, fmt.Errorf("failed to enable auth method: %w", err)
	}

	return true, nil
}

// getK8sConfig gets Kubernetes cluster configuration.
func (m *managerImpl) getK8sConfig(
	ctx context.Context,
	overrideConfig *KubernetesClusterConfig,
) (*KubernetesClusterConfig, error) {
	if overrideConfig != nil && overrideConfig.Host != "" && overrideConfig.CACert != "" {
		m.log.Info("using override kubernetes config")
		return overrideConfig, nil
	}

	m.log.Info("auto-discovering kubernetes cluster config")
	config, err := m.clusterDiscovery.GetClusterConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to auto-discover cluster config: %w", err)
	}

	// Merge with override if partial override provided
	if overrideConfig != nil {
		if overrideConfig.Host != "" {
			config.Host = overrideConfig.Host
		}
		if overrideConfig.CACert != "" {
			config.CACert = overrideConfig.CACert
		}
	}

	return config, nil
}

// configureKubernetesAuth configures the Kubernetes auth method.
func (m *managerImpl) configureKubernetesAuth(
	ctx context.Context,
	vaultClient VaultBootstrapClient,
	authMethodName string,
	k8sConfig *KubernetesClusterConfig,
	tokenReviewerJWT string,
) error {
	m.log.Info("configuring kubernetes auth",
		"host", k8sConfig.Host,
		"hasCACert", k8sConfig.CACert != "",
	)

	config := map[string]interface{}{
		"kubernetes_host":    k8sConfig.Host,
		"kubernetes_ca_cert": k8sConfig.CACert,
		"token_reviewer_jwt": tokenReviewerJWT,
	}

	return vaultClient.WriteKubernetesAuthConfig(ctx, authMethodName, config)
}

// createOperatorRole creates the Vault role for the operator.
func (m *managerImpl) createOperatorRole(
	ctx context.Context,
	vaultClient VaultBootstrapClient,
	config *Config,
) (bool, error) {
	m.log.Info("creating operator role",
		"role", config.OperatorRole,
		"serviceAccount", config.OperatorServiceAccount.Name,
		"namespace", config.OperatorServiceAccount.Namespace,
	)

	roleConfig := map[string]interface{}{
		"bound_service_account_names":      []string{config.OperatorServiceAccount.Name},
		"bound_service_account_namespaces": []string{config.OperatorServiceAccount.Namespace},
		"policies":                         []string{config.OperatorPolicy},
		"ttl":                              "1h",
	}

	if err := vaultClient.WriteKubernetesRole(ctx, config.AuthMethodName, config.OperatorRole, roleConfig); err != nil {
		return false, fmt.Errorf("failed to create role: %w", err)
	}

	return true, nil
}

// testKubernetesAuth tests that Kubernetes auth works.
func (m *managerImpl) testKubernetesAuth(
	ctx context.Context,
	vaultClient VaultBootstrapClient,
	config *Config,
) (bool, error) {
	m.log.Info("testing kubernetes auth")

	// Get a fresh token for testing
	tokenInfo, err := m.tokenProvider.GetToken(ctx, token.GetTokenOptions{
		ServiceAccount: config.OperatorServiceAccount,
		Duration:       10 * time.Minute, // Must be >= 10 minutes for k3s/some K8s distributions
		Audiences:      []string{token.DefaultAudience},
	})
	if err != nil {
		return false, fmt.Errorf("failed to get test token: %w", err)
	}

	// Try to authenticate
	err = vaultClient.AuthenticateKubernetesWithToken(
		ctx, config.OperatorRole, config.AuthMethodName, tokenInfo.Token)
	if err != nil {
		return false, fmt.Errorf("kubernetes auth test failed: %w", err)
	}

	m.log.Info("kubernetes auth test passed")
	return true, nil
}

// Ensure managerImpl implements Manager.
var _ Manager = (*managerImpl)(nil)
