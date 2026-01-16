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

package controller

import (
	"context"
	"fmt"
	"os"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/pkg/vault/bootstrap"
	"github.com/panteparak/vault-access-operator/pkg/vault/token"
	"github.com/panteparak/vault-access-operator/shared/controller/base"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// Default auth path constant.
const defaultKubernetesAuthPath = "kubernetes"

// OS functions for testability.
var (
	osLookupEnv = os.LookupEnv
	osReadFile  = os.ReadFile
)

// Handler implements base.FeatureHandler for VaultConnection resources.
// It handles the feature-specific sync and cleanup logic for Vault connections,
// including bootstrap, token lifecycle management, and token_reviewer_jwt rotation.
type Handler struct {
	client           client.Client
	clientCache      *vault.ClientCache
	eventBus         *events.EventBus
	lifecycleCtrl    token.LifecycleController
	reviewerCtrl     token.TokenReviewerController
	bootstrapMgr     bootstrap.Manager
	tokenProvider    token.TokenProvider
	clusterDiscovery bootstrap.K8sClusterDiscovery
	log              logr.Logger
}

// HandlerConfig contains configuration for creating a Handler.
type HandlerConfig struct {
	Client           client.Client
	ClientCache      *vault.ClientCache
	EventBus         *events.EventBus
	K8sClientset     kubernetes.Interface
	LifecycleCtrl    token.LifecycleController
	ReviewerCtrl     token.TokenReviewerController
	TokenProvider    token.TokenProvider
	ClusterDiscovery bootstrap.K8sClusterDiscovery
	Log              logr.Logger
}

// NewHandler creates a new connection Handler.
func NewHandler(cfg HandlerConfig) *Handler {
	h := &Handler{
		client:           cfg.Client,
		clientCache:      cfg.ClientCache,
		eventBus:         cfg.EventBus,
		lifecycleCtrl:    cfg.LifecycleCtrl,
		reviewerCtrl:     cfg.ReviewerCtrl,
		tokenProvider:    cfg.TokenProvider,
		clusterDiscovery: cfg.ClusterDiscovery,
		log:              cfg.Log,
	}

	// Create bootstrap manager if we have token provider
	if cfg.TokenProvider != nil && cfg.ClusterDiscovery != nil {
		h.bootstrapMgr = bootstrap.NewManager(cfg.TokenProvider, cfg.ClusterDiscovery, cfg.Log)
	}

	return h
}

// Sync synchronizes the VaultConnection with Vault.
// It handles three phases: bootstrap → transition → production.
func (h *Handler) Sync(ctx context.Context, conn *vaultv1alpha1.VaultConnection) error {
	log := logr.FromContextOrDiscard(ctx)

	// Set phase to Syncing if not already
	if conn.Status.Phase != vaultv1alpha1.PhaseSyncing && conn.Status.Phase != vaultv1alpha1.PhaseActive {
		conn.Status.Phase = vaultv1alpha1.PhaseSyncing
		if err := h.client.Status().Update(ctx, conn); err != nil {
			return fmt.Errorf("failed to update status to Syncing: %w", err)
		}
	}

	// Phase 1: Bootstrap if needed
	if h.isBootstrapRequired(conn) {
		log.Info("bootstrap required, running setup")
		return h.runBootstrap(ctx, conn)
	}

	// Phase 2: Normal auth (K8s, Token, or AppRole)
	vaultClient, err := h.buildAndAuthenticateClient(ctx, conn)
	if err != nil {
		return h.handleSyncError(ctx, conn, err)
	}

	// Store client in cache
	h.clientCache.Set(conn.Name, vaultClient)
	log.V(1).Info("stored client in cache", "connectionName", conn.Name)

	// Get Vault version
	version, err := vaultClient.GetVersion(ctx)
	if err != nil {
		return h.handleSyncError(ctx, conn, fmt.Errorf("failed to get Vault version: %w", err))
	}

	// Update AuthStatus for Kubernetes auth
	if conn.Spec.Auth.Kubernetes != nil {
		h.updateAuthStatus(conn)
	}

	// Update status to Active
	now := metav1.Now()
	conn.Status.Phase = vaultv1alpha1.PhaseActive
	conn.Status.VaultVersion = version
	conn.Status.LastHeartbeat = &now
	conn.Status.Message = ""
	h.setCondition(conn, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Connected to Vault")

	if err := h.client.Status().Update(ctx, conn); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	// Publish ConnectionReady event
	if h.eventBus != nil {
		h.eventBus.PublishAsync(ctx, events.NewConnectionReady(conn.Name, conn.Spec.Address, version))
	}

	log.Info("VaultConnection synced successfully", "version", version)
	return nil
}

// isBootstrapRequired checks if bootstrap is needed for this connection.
func (h *Handler) isBootstrapRequired(conn *vaultv1alpha1.VaultConnection) bool {
	// Bootstrap is required if:
	// 1. Bootstrap config is present
	// 2. Bootstrap has not completed yet
	if conn.Spec.Auth.Bootstrap == nil {
		return false
	}

	if conn.Status.AuthStatus != nil && conn.Status.AuthStatus.BootstrapComplete {
		return false
	}

	return true
}

// runBootstrap executes the bootstrap process.
func (h *Handler) runBootstrap(ctx context.Context, conn *vaultv1alpha1.VaultConnection) error {
	log := logr.FromContextOrDiscard(ctx)

	if h.bootstrapMgr == nil {
		return fmt.Errorf("bootstrap manager not configured")
	}

	// Get bootstrap token from secret
	bootstrapToken, err := h.getSecretData(ctx, &conn.Spec.Auth.Bootstrap.SecretRef)
	if err != nil {
		return h.handleSyncError(ctx, conn, fmt.Errorf("failed to get bootstrap token: %w", err))
	}

	// Build Vault client with bootstrap token
	vaultClient, err := h.buildVaultClient(ctx, conn)
	if err != nil {
		return h.handleSyncError(ctx, conn, fmt.Errorf("failed to create vault client: %w", err))
	}

	// Authenticate with bootstrap token
	if err := vaultClient.AuthenticateToken(bootstrapToken); err != nil {
		return h.handleSyncError(ctx, conn, fmt.Errorf("failed to authenticate with bootstrap token: %w", err))
	}

	// Prepare bootstrap config
	k8sAuth := conn.Spec.Auth.Kubernetes
	if k8sAuth == nil {
		return h.handleSyncError(ctx, conn, fmt.Errorf("kubernetes auth config required for bootstrap"))
	}

	authPath := k8sAuth.AuthPath
	if authPath == "" {
		authPath = defaultKubernetesAuthPath
	}

	autoRevoke := true
	if conn.Spec.Auth.Bootstrap.AutoRevoke != nil {
		autoRevoke = *conn.Spec.Auth.Bootstrap.AutoRevoke
	}

	saName := getOperatorServiceAccountName()
	saNamespace := getOperatorNamespace()

	bootstrapConfig := &bootstrap.Config{
		AuthMethodName: authPath,
		OperatorRole:   k8sAuth.Role,
		OperatorServiceAccount: token.ServiceAccountRef{
			Name:      saName,
			Namespace: saNamespace,
		},
		TokenReviewerServiceAccount: &token.ServiceAccountRef{
			Name:      saName,
			Namespace: saNamespace,
		},
		TokenReviewerDuration: token.DefaultReviewerDuration,
		AutoRevoke:            autoRevoke,
		OperatorPolicy:        "vault-access-operator",
	}

	// Run bootstrap
	result, err := h.bootstrapMgr.Bootstrap(ctx, vaultClient, bootstrapConfig)
	if err != nil {
		return h.handleSyncError(ctx, conn, fmt.Errorf("bootstrap failed: %w", err))
	}

	// Update status with bootstrap result
	now := metav1.Now()
	if conn.Status.AuthStatus == nil {
		conn.Status.AuthStatus = &vaultv1alpha1.AuthStatus{}
	}
	conn.Status.AuthStatus.BootstrapComplete = true
	conn.Status.AuthStatus.BootstrapCompletedAt = &now
	conn.Status.AuthStatus.AuthMethod = defaultKubernetesAuthPath

	if !result.TokenReviewerExpiration.IsZero() {
		expTime := metav1.NewTime(result.TokenReviewerExpiration)
		conn.Status.AuthStatus.TokenReviewerExpiration = &expTime
	}

	log.Info("bootstrap completed successfully",
		"authMethodCreated", result.AuthMethodCreated,
		"roleCreated", result.RoleCreated,
		"bootstrapRevoked", result.BootstrapRevoked,
	)

	// Publish bootstrap completed event
	if h.eventBus != nil {
		h.eventBus.PublishAsync(ctx, events.NewBootstrapCompleted(
			conn.Name,
			result.AuthPath,
			result.BootstrapRevoked,
			true, // transitioned to K8s auth
		))
	}

	// Continue with normal K8s auth flow
	return h.Sync(ctx, conn)
}

// buildVaultClient creates an unauthenticated Vault client.
func (h *Handler) buildVaultClient(ctx context.Context, conn *vaultv1alpha1.VaultConnection) (*vault.Client, error) {
	var tlsConfig *vault.TLSConfig
	if conn.Spec.TLS != nil {
		tlsConfig = &vault.TLSConfig{
			SkipVerify: conn.Spec.TLS.SkipVerify,
		}
		if conn.Spec.TLS.CASecretRef != nil {
			caCert, err := h.getSecretData(ctx, conn.Spec.TLS.CASecretRef)
			if err != nil {
				return nil, fmt.Errorf("failed to get CA certificate: %w", err)
			}
			tlsConfig.CACert = caCert
		}
	}

	return vault.NewClient(vault.ClientConfig{
		Address:   conn.Spec.Address,
		TLSConfig: tlsConfig,
	})
}

// updateAuthStatus updates the auth status for Kubernetes auth connections.
func (h *Handler) updateAuthStatus(conn *vaultv1alpha1.VaultConnection) {
	if conn.Status.AuthStatus == nil {
		conn.Status.AuthStatus = &vaultv1alpha1.AuthStatus{}
	}
	conn.Status.AuthStatus.AuthMethod = defaultKubernetesAuthPath

	// Check if token reviewer rotation is disabled and add warning
	k8sAuth := conn.Spec.Auth.Kubernetes
	if k8sAuth.TokenReviewerRotation != nil && !*k8sAuth.TokenReviewerRotation {
		h.setCondition(conn, "TokenReviewerRotationDisabled", metav1.ConditionTrue,
			"ManualManagement",
			"Warning: TokenReviewerRotation is disabled. "+
				"You must manually update token_reviewer_jwt in Vault before it expires.")
	}
}

// Cleanup removes the Vault client from the cache when the connection is deleted.
func (h *Handler) Cleanup(ctx context.Context, conn *vaultv1alpha1.VaultConnection) error {
	log := logr.FromContextOrDiscard(ctx)

	// Update phase to Deleting
	conn.Status.Phase = vaultv1alpha1.PhaseDeleting
	if err := h.client.Status().Update(ctx, conn); err != nil {
		log.V(1).Info("failed to update status to Deleting (ignoring)", "error", err)
	}

	// Unregister from lifecycle controllers
	if h.lifecycleCtrl != nil {
		h.lifecycleCtrl.Unregister(conn.Name)
		log.V(1).Info("unregistered from lifecycle controller", "connectionName", conn.Name)
	}

	if h.reviewerCtrl != nil {
		h.reviewerCtrl.Unregister(conn.Name)
		log.V(1).Info("unregistered from reviewer controller", "connectionName", conn.Name)
	}

	// Remove from cache
	h.clientCache.Delete(conn.Name)
	log.V(1).Info("removed client from cache", "connectionName", conn.Name)

	// Publish ConnectionDisconnected event
	if h.eventBus != nil {
		h.eventBus.PublishAsync(ctx, events.NewConnectionDisconnected(conn.Name, "resource deleted"))
	}

	log.Info("VaultConnection cleanup completed")
	return nil
}

// handleSyncError updates the status to error state and returns the error.
func (h *Handler) handleSyncError(ctx context.Context, conn *vaultv1alpha1.VaultConnection, err error) error {
	conn.Status.Phase = vaultv1alpha1.PhaseError
	conn.Status.Message = err.Error()
	h.setCondition(conn, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
		vaultv1alpha1.ReasonFailed, err.Error())

	if updateErr := h.client.Status().Update(ctx, conn); updateErr != nil {
		h.log.Error(updateErr, "failed to update error status")
	}

	return err
}

// buildAndAuthenticateClient creates and authenticates a Vault client.
func (h *Handler) buildAndAuthenticateClient(
	ctx context.Context,
	conn *vaultv1alpha1.VaultConnection,
) (*vault.Client, error) {
	// Build TLS config
	var tlsConfig *vault.TLSConfig
	if conn.Spec.TLS != nil {
		tlsConfig = &vault.TLSConfig{
			SkipVerify: conn.Spec.TLS.SkipVerify,
		}
		if conn.Spec.TLS.CASecretRef != nil {
			caCert, err := h.getSecretData(ctx, conn.Spec.TLS.CASecretRef)
			if err != nil {
				return nil, fmt.Errorf("failed to get CA certificate: %w", err)
			}
			tlsConfig.CACert = caCert
		}
	}

	// Create client
	vaultClient, err := vault.NewClient(vault.ClientConfig{
		Address:   conn.Spec.Address,
		TLSConfig: tlsConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Authenticate
	if err := h.authenticate(ctx, vaultClient, conn); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	return vaultClient, nil
}

// authenticate authenticates the Vault client using the configured auth method.
func (h *Handler) authenticate(
	ctx context.Context,
	vaultClient *vault.Client,
	conn *vaultv1alpha1.VaultConnection,
) error {
	auth := conn.Spec.Auth

	// Kubernetes auth - uses TokenProvider for token acquisition
	if auth.Kubernetes != nil {
		authPath := auth.Kubernetes.AuthPath
		if authPath == "" {
			authPath = defaultKubernetesAuthPath
		}

		// Get token using TokenProvider (supports both mounted and TokenRequest API)
		tokenInfo, err := h.getServiceAccountToken(ctx, conn)
		if err != nil {
			return fmt.Errorf("failed to get service account token: %w", err)
		}

		return vaultClient.AuthenticateKubernetesWithToken(ctx, auth.Kubernetes.Role, authPath, tokenInfo.Token)
	}

	// Token auth
	if auth.Token != nil {
		tokenValue, err := h.getSecretData(ctx, &auth.Token.SecretRef)
		if err != nil {
			return fmt.Errorf("failed to get token from secret: %w", err)
		}
		return vaultClient.AuthenticateToken(tokenValue)
	}

	// AppRole auth
	if auth.AppRole != nil {
		secretID, err := h.getSecretData(ctx, &auth.AppRole.SecretIDRef)
		if err != nil {
			return fmt.Errorf("failed to get secret ID from secret: %w", err)
		}
		mountPath := auth.AppRole.MountPath
		if mountPath == "" {
			mountPath = "approle"
		}
		return vaultClient.AuthenticateAppRole(ctx, auth.AppRole.RoleID, secretID, mountPath)
	}

	return fmt.Errorf("no authentication method configured")
}

// getServiceAccountToken gets a service account token using the configured provider.
func (h *Handler) getServiceAccountToken(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection,
) (*token.TokenInfo, error) {
	if h.tokenProvider == nil {
		return nil, fmt.Errorf("token provider not configured")
	}

	// Determine token duration
	duration := token.DefaultTokenDuration
	if conn.Spec.Auth.Kubernetes != nil && conn.Spec.Auth.Kubernetes.TokenDuration.Duration > 0 {
		duration = conn.Spec.Auth.Kubernetes.TokenDuration.Duration
	}

	// Use the operator's service account (from environment or default)
	saName := getOperatorServiceAccountName()
	saNamespace := getOperatorNamespace()

	return h.tokenProvider.GetToken(ctx, token.GetTokenOptions{
		ServiceAccount: token.ServiceAccountRef{
			Name:      saName,
			Namespace: saNamespace,
		},
		Duration:  duration,
		Audiences: []string{token.DefaultAudience},
	})
}

// getOperatorServiceAccountName returns the operator's service account name.
func getOperatorServiceAccountName() string {
	if sa := getEnv("OPERATOR_SERVICE_ACCOUNT", ""); sa != "" {
		return sa
	}
	return "vault-access-operator-controller-manager"
}

// getOperatorNamespace returns the operator's namespace.
func getOperatorNamespace() string {
	if ns := getEnv("OPERATOR_NAMESPACE", ""); ns != "" {
		return ns
	}
	// Try to read from mounted file in-cluster
	if data, err := readFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		return string(data)
	}
	return "vault-access-operator-system"
}

// getEnv returns environment variable value or default.
func getEnv(key, defaultValue string) string {
	if value := lookupEnv(key); value != "" {
		return value
	}
	return defaultValue
}

// Helper functions for testing.
var (
	lookupEnv = func(key string) string {
		val, _ := osLookupEnv(key)
		return val
	}
	readFile = osReadFile
)

// getSecretData retrieves data from a Kubernetes Secret.
func (h *Handler) getSecretData(ctx context.Context, ref *vaultv1alpha1.SecretKeySelector) (string, error) {
	secret := &corev1.Secret{}
	namespace := ref.Namespace
	if namespace == "" {
		namespace = "default"
	}

	if err := h.client.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, secret); err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, ref.Name, err)
	}

	data, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", ref.Key, namespace, ref.Name)
	}

	return string(data), nil
}

// setCondition sets a condition on the VaultConnection status.
func (h *Handler) setCondition(
	conn *vaultv1alpha1.VaultConnection,
	condType string,
	status metav1.ConditionStatus,
	reason, message string,
) {
	now := metav1.Now()
	condition := vaultv1alpha1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: conn.Generation,
	}

	// Find and update existing condition or append new one
	found := false
	for i, c := range conn.Status.Conditions {
		if c.Type == condType {
			if c.Status != status {
				conn.Status.Conditions[i] = condition
			} else {
				conn.Status.Conditions[i].Reason = reason
				conn.Status.Conditions[i].Message = message
				conn.Status.Conditions[i].ObservedGeneration = conn.Generation
			}
			found = true
			break
		}
	}

	if !found {
		conn.Status.Conditions = append(conn.Status.Conditions, condition)
	}
}

// Ensure Handler implements FeatureHandler interface.
var _ base.FeatureHandler[*vaultv1alpha1.VaultConnection] = (*Handler)(nil)
