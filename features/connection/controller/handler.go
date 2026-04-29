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
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/connection/controller/authprovider"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/pkg/vault/bootstrap"
	"github.com/panteparak/vault-access-operator/pkg/vault/token"
	"github.com/panteparak/vault-access-operator/shared/controller/base"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
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
	authRegistry     *authprovider.Registry
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
		clusterDiscovery: cfg.ClusterDiscovery,
		log:              cfg.Log,
	}

	// Create bootstrap manager if we have token provider
	if cfg.TokenProvider != nil && cfg.ClusterDiscovery != nil {
		h.bootstrapMgr = bootstrap.NewManager(cfg.TokenProvider, cfg.ClusterDiscovery, cfg.Log)
	}

	// Build auth provider registry. Ordering here is the semantic contract:
	// the first provider whose Applies(authCfg) returns true wins when
	// multiple auth methods are configured on a single VaultConnection.
	secrets := handlerSecretReader{h: h}
	h.authRegistry = authprovider.NewRegistry(
		authprovider.NewKubernetesProvider(cfg.TokenProvider),
		authprovider.NewTokenProvider(secrets),
		authprovider.NewAppRoleProvider(secrets),
		authprovider.NewJWTProvider(secrets, cfg.TokenProvider),
		authprovider.NewOIDCProvider(secrets, cfg.TokenProvider),
		authprovider.NewAWSProvider(nil),
		authprovider.NewGCPProvider(secrets, nil),
	)

	return h
}

// handlerSecretReader adapts Handler.getSecretData to the
// authprovider.SecretReader interface so providers depend on a narrow
// interface instead of the full Handler struct.
type handlerSecretReader struct{ h *Handler }

func (a handlerSecretReader) GetSecretData(
	ctx context.Context, ref *vaultv1alpha1.SecretKeySelector,
) (string, error) {
	return a.h.getSecretData(ctx, ref)
}

// Sync synchronizes the VaultConnection with Vault.
// It coordinates four phases: ensure-syncing → bootstrap → auth+health → finalize.
// Each phase is an independent method; this function is pure orchestration.
func (h *Handler) Sync(ctx context.Context, conn *vaultv1alpha1.VaultConnection) error {
	log := logr.FromContextOrDiscard(ctx)

	if err := h.ensurePhaseSyncing(ctx, conn); err != nil {
		return err
	}

	if h.isBootstrapRequired(conn) {
		log.Info("bootstrap required, running setup")
		return h.runBootstrap(ctx, conn)
	}

	vaultClient, renewed, err := h.syncClientLifecycle(ctx, conn)
	if err != nil {
		return h.handleSyncError(ctx, conn, err)
	}

	version, now, err := h.runHealthCheck(ctx, conn, vaultClient)
	if err != nil {
		return err
	}

	if conn.Spec.Auth.Kubernetes != nil {
		h.updateAuthStatus(conn, vaultClient)
		if renewed {
			h.trackRenewal(conn)
		}
	}

	return h.finalizeActiveStatus(ctx, conn, version, now)
}

// ensurePhaseSyncing sets the connection phase to Syncing unless it is
// already in Syncing or Active. Active connections that are re-reconciling
// skip this to avoid unnecessary status churn.
func (h *Handler) ensurePhaseSyncing(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection,
) error {
	if conn.Status.Phase == vaultv1alpha1.PhaseSyncing || conn.Status.Phase == vaultv1alpha1.PhaseActive {
		return nil
	}
	conn.Status.Phase = vaultv1alpha1.PhaseSyncing
	if err := h.client.Status().Update(ctx, conn); err != nil {
		return fmt.Errorf("failed to update status to Syncing: %w", err)
	}
	return nil
}

// syncClientLifecycle resolves an authenticated Vault client (from cache,
// via renewal, or a fresh re-auth) and stores it in the cache.
// Returns the client and whether a renewal or re-auth happened.
func (h *Handler) syncClientLifecycle(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection,
) (*vault.Client, bool, error) {
	log := logr.FromContextOrDiscard(ctx)

	vaultClient, renewed, err := h.getOrRenewClient(ctx, conn)
	if err != nil {
		return nil, false, err
	}

	h.clientCache.Set(conn.Name, vaultClient)
	log.V(1).Info("stored client in cache", "connectionName", conn.Name)
	return vaultClient, renewed, nil
}

// runHealthCheck pulls Vault version and verifies Vault is initialized and
// unsealed. Returns version and the health-check timestamp on success.
// Failures drive updateHealthStatus and exit via handleSyncError.
func (h *Handler) runHealthCheck(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection, vaultClient *vault.Client,
) (string, metav1.Time, error) {
	version, err := vaultClient.GetVersion(ctx)
	if err != nil {
		return "", metav1.Time{}, h.handleSyncError(ctx, conn,
			fmt.Errorf("failed to get Vault version: %w", err))
	}

	now := metav1.Now()
	conn.Status.LastHealthCheck = &now

	healthy, err := vaultClient.IsHealthy(ctx)
	if err != nil {
		h.updateHealthStatus(conn, false, fmt.Sprintf("health check failed: %v", err))
		return "", now, h.handleSyncError(ctx, conn,
			fmt.Errorf("vault health check failed: %w", err))
	}
	if !healthy {
		h.updateHealthStatus(conn, false, "vault is not healthy (sealed or uninitialized)")
		return "", now, h.handleSyncError(ctx, conn,
			fmt.Errorf("vault is not healthy (sealed or uninitialized)"))
	}

	h.updateHealthStatus(conn, true, "")
	return version, now, nil
}

// finalizeActiveStatus writes the Active phase, sets Ready condition,
// persists the status, and emits the ConnectionReady event.
func (h *Handler) finalizeActiveStatus(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection, version string, now metav1.Time,
) error {
	conn.Status.Phase = vaultv1alpha1.PhaseActive
	conn.Status.VaultVersion = version
	conn.Status.LastHeartbeat = &now
	conn.Status.Message = ""
	h.setCondition(conn, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Connected to Vault")

	if err := h.client.Status().Update(ctx, conn); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	if h.eventBus != nil {
		h.eventBus.PublishAsync(ctx, events.NewConnectionReady(conn.Name, conn.Spec.Address, version))
	}

	logr.FromContextOrDiscard(ctx).Info("VaultConnection synced successfully", "version", version)
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

// runBootstrap executes the bootstrap process: build a token-authenticated
// client, run the bootstrap manager, and persist the resulting status.
func (h *Handler) runBootstrap(ctx context.Context, conn *vaultv1alpha1.VaultConnection) error {
	if h.bootstrapMgr == nil {
		return fmt.Errorf("bootstrap manager not configured")
	}
	if conn.Spec.Auth.Kubernetes == nil {
		return h.handleSyncError(ctx, conn, fmt.Errorf("kubernetes auth config required for bootstrap"))
	}

	vaultClient, err := h.bootstrapAuthenticatedClient(ctx, conn)
	if err != nil {
		return err
	}

	bootstrapConfig := buildBootstrapConfig(conn)

	result, err := h.bootstrapMgr.Bootstrap(ctx, vaultClient, bootstrapConfig)
	if err != nil {
		return h.handleSyncError(ctx, conn, fmt.Errorf("bootstrap failed: %w", err))
	}

	logr.FromContextOrDiscard(ctx).Info("bootstrap completed successfully",
		"authMethodCreated", result.AuthMethodCreated,
		"roleCreated", result.RoleCreated,
		"bootstrapRevoked", result.BootstrapRevoked,
	)

	applyBootstrapStatus(conn, result)

	if err := h.client.Status().Update(ctx, conn); err != nil {
		return fmt.Errorf("failed to persist bootstrap status: %w", err)
	}

	// Publish bootstrap completed event
	if h.eventBus != nil {
		h.eventBus.PublishAsync(ctx, events.NewBootstrapCompleted(
			conn.Name,
			result.AuthPath,
			result.BootstrapRevoked,
			true, // transitioned to K8s auth
		))
	}

	// Bootstrap complete — return nil and let the requeue interval trigger
	// the next reconcile with a fresh object from the API server.
	h.log.Info("bootstrap completed, will re-sync on next reconcile")
	return nil
}

// bootstrapAuthenticatedClient creates a fresh Vault client and
// authenticates it with the bootstrap token from the user-provided secret.
// SECURITY: bootstrapToken must not appear in error messages or status fields.
func (h *Handler) bootstrapAuthenticatedClient(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection,
) (*vault.Client, error) {
	bootstrapToken, err := h.getSecretData(ctx, &conn.Spec.Auth.Bootstrap.SecretRef)
	if err != nil {
		return nil, h.handleSyncError(ctx, conn, fmt.Errorf("failed to get bootstrap token: %w", err))
	}

	vaultClient, err := h.newUnauthenticatedVaultClient(ctx, conn)
	if err != nil {
		return nil, h.handleSyncError(ctx, conn, fmt.Errorf("failed to create vault client: %w", err))
	}

	if err := vaultClient.AuthenticateToken(bootstrapToken); err != nil {
		return nil, h.handleSyncError(ctx, conn,
			fmt.Errorf("failed to authenticate with bootstrap token: %w", err))
	}
	return vaultClient, nil
}

// buildBootstrapConfig translates the user-facing CRD spec into the
// bootstrap manager's Config. Caller must ensure conn.Spec.Auth.Kubernetes
// is non-nil — runBootstrap guards that precondition.
func buildBootstrapConfig(conn *vaultv1alpha1.VaultConnection) *bootstrap.Config {
	k8sAuth := conn.Spec.Auth.Kubernetes
	authPath := k8sAuth.AuthPath
	if authPath == "" {
		authPath = defaultKubernetesAuthPath
	}

	autoRevoke := true
	if conn.Spec.Auth.Bootstrap.AutoRevoke != nil {
		autoRevoke = *conn.Spec.Auth.Bootstrap.AutoRevoke
	}

	saRef := token.ServiceAccountRef{
		Name:      getOperatorServiceAccountName(),
		Namespace: getOperatorNamespace(),
	}
	cfg := &bootstrap.Config{
		AuthMethodName:              authPath,
		OperatorRole:                k8sAuth.Role,
		OperatorServiceAccount:      saRef,
		TokenReviewerServiceAccount: &saRef,
		TokenReviewerDuration:       token.DefaultReviewerDuration,
		AutoRevoke:                  autoRevoke,
		OperatorPolicy:              "vault-access-operator",
	}

	// Pass KubernetesHost as override to prevent auto-discovery from using
	// the in-cluster address when external Vault can't reach the K8s API.
	if k8sAuth.KubernetesHost != "" {
		cfg.KubernetesConfig = &bootstrap.KubernetesClusterConfig{Host: k8sAuth.KubernetesHost}
	}
	return cfg
}

// applyBootstrapStatus updates the in-memory connection status from the
// bootstrap result. The caller is responsible for persisting via Status().Update().
func applyBootstrapStatus(conn *vaultv1alpha1.VaultConnection, result *bootstrap.Result) {
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
}

// newUnauthenticatedVaultClient constructs a Vault client from the
// connection spec (address + optional TLS). No authentication is attempted.
// Both the bootstrap path and the re-auth path share this construction to
// keep TLS secret resolution in a single place.
func (h *Handler) newUnauthenticatedVaultClient(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection,
) (*vault.Client, error) {
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
func (h *Handler) updateAuthStatus(conn *vaultv1alpha1.VaultConnection, vaultClient *vault.Client) {
	if conn.Status.AuthStatus == nil {
		conn.Status.AuthStatus = &vaultv1alpha1.AuthStatus{}
	}
	conn.Status.AuthStatus.AuthMethod = defaultKubernetesAuthPath

	// Set token expiration from Vault auth response
	if exp := vaultClient.TokenExpiration(); !exp.IsZero() {
		expTime := metav1.NewTime(exp)
		conn.Status.AuthStatus.TokenExpiration = &expTime
	}

	// Capture token accessor for audit correlation
	if accessor := vaultClient.TokenAccessor(); accessor != "" {
		conn.Status.AuthStatus.TokenAccessor = accessor
	}

	// Check if token reviewer rotation is disabled and add warning
	k8sAuth := conn.Spec.Auth.Kubernetes
	if k8sAuth.TokenReviewerRotation != nil && !*k8sAuth.TokenReviewerRotation {
		h.setCondition(conn, "TokenReviewerRotationDisabled", metav1.ConditionTrue,
			"ManualManagement",
			"Warning: TokenReviewerRotation is disabled. "+
				"You must manually update token_reviewer_jwt in Vault before it expires.")
	}
}

// dependentLister fetches one CRD type's resources and reports back those
// whose ConnectionRef matches the given connection name, formatted for
// display. The registry of listers (see dependentListers) drives the
// open-for-extension Cleanup dependency check: new CRD types attach here.
type dependentLister func(ctx context.Context, c client.Client, connName string) ([]string, error)

// dependentListers returns the registered CRD-type listers. Order here
// affects the order of entries in the user-visible "deletion blocked"
// message, so it follows the conceptual hierarchy: policies → roles.
func dependentListers() []dependentLister {
	return []dependentLister{
		namespacedLister("VaultPolicy",
			func() *vaultv1alpha1.VaultPolicyList { return &vaultv1alpha1.VaultPolicyList{} },
			func(l *vaultv1alpha1.VaultPolicyList, connName string) []dependentRef {
				refs := make([]dependentRef, 0, len(l.Items))
				for i := range l.Items {
					if l.Items[i].Spec.ConnectionRef == connName {
						refs = append(refs, dependentRef{namespace: l.Items[i].Namespace, name: l.Items[i].Name})
					}
				}
				return refs
			}),
		clusterLister("VaultClusterPolicy",
			func() *vaultv1alpha1.VaultClusterPolicyList { return &vaultv1alpha1.VaultClusterPolicyList{} },
			func(l *vaultv1alpha1.VaultClusterPolicyList, connName string) []dependentRef {
				refs := make([]dependentRef, 0, len(l.Items))
				for i := range l.Items {
					if l.Items[i].Spec.ConnectionRef == connName {
						refs = append(refs, dependentRef{name: l.Items[i].Name})
					}
				}
				return refs
			}),
		namespacedLister("VaultRole",
			func() *vaultv1alpha1.VaultRoleList { return &vaultv1alpha1.VaultRoleList{} },
			func(l *vaultv1alpha1.VaultRoleList, connName string) []dependentRef {
				refs := make([]dependentRef, 0, len(l.Items))
				for i := range l.Items {
					if l.Items[i].Spec.ConnectionRef == connName {
						refs = append(refs, dependentRef{namespace: l.Items[i].Namespace, name: l.Items[i].Name})
					}
				}
				return refs
			}),
		clusterLister("VaultClusterRole",
			func() *vaultv1alpha1.VaultClusterRoleList { return &vaultv1alpha1.VaultClusterRoleList{} },
			func(l *vaultv1alpha1.VaultClusterRoleList, connName string) []dependentRef {
				refs := make([]dependentRef, 0, len(l.Items))
				for i := range l.Items {
					if l.Items[i].Spec.ConnectionRef == connName {
						refs = append(refs, dependentRef{name: l.Items[i].Name})
					}
				}
				return refs
			}),
	}
}

// dependentRef captures the identity of a dependent CRD instance.
type dependentRef struct{ namespace, name string }

// namespacedLister constructs a lister that formats matches as
// "Kind/namespace/name" for namespaced CRD types.
func namespacedLister[L client.ObjectList](
	kind string,
	newList func() L,
	match func(L, string) []dependentRef,
) dependentLister {
	return func(ctx context.Context, c client.Client, connName string) ([]string, error) {
		list := newList()
		if err := c.List(ctx, list); err != nil {
			return nil, fmt.Errorf("failed to list %ss: %w", kind, err)
		}
		refs := match(list, connName)
		out := make([]string, 0, len(refs))
		for _, r := range refs {
			out = append(out, fmt.Sprintf("%s/%s/%s", kind, r.namespace, r.name))
		}
		return out, nil
	}
}

// clusterLister constructs a lister that formats matches as "Kind/name"
// for cluster-scoped CRD types.
func clusterLister[L client.ObjectList](
	kind string,
	newList func() L,
	match func(L, string) []dependentRef,
) dependentLister {
	return func(ctx context.Context, c client.Client, connName string) ([]string, error) {
		list := newList()
		if err := c.List(ctx, list); err != nil {
			return nil, fmt.Errorf("failed to list %ss: %w", kind, err)
		}
		refs := match(list, connName)
		out := make([]string, 0, len(refs))
		for _, r := range refs {
			out = append(out, fmt.Sprintf("%s/%s", kind, r.name))
		}
		return out, nil
	}
}

// listDependents returns all resources that reference this VaultConnection,
// formatted as "Type/namespace/name" (namespaced) or "Type/name" (cluster).
func (h *Handler) listDependents(ctx context.Context, connName string) ([]string, error) {
	var dependents []string
	for _, lister := range dependentListers() {
		found, err := lister(ctx, h.client, connName)
		if err != nil {
			return nil, err
		}
		dependents = append(dependents, found...)
	}
	return dependents, nil
}

// Cleanup tears down a VaultConnection: it blocks deletion if dependents
// still reference it, otherwise revokes Vault state and clears local caches.
func (h *Handler) Cleanup(ctx context.Context, conn *vaultv1alpha1.VaultConnection) error {
	log := logr.FromContextOrDiscard(ctx)

	if err := h.blockOnDependents(ctx, conn); err != nil {
		return err
	}

	h.markPhaseDeleting(ctx, conn)
	h.tearDownVaultState(ctx, conn)
	h.unregisterTokenControllers(conn)
	h.clientCache.Delete(conn.Name)
	log.V(1).Info("removed client from cache", "connectionName", conn.Name)

	if h.eventBus != nil {
		h.eventBus.PublishAsync(ctx, events.NewConnectionDisconnected(conn.Name, "resource deleted"))
	}

	log.Info("VaultConnection cleanup completed")
	return nil
}

// blockOnDependents returns a non-nil error when cleanup must abort: either
// the dependent listing itself failed, or at least one dependent resource
// still references this connection. The connection's Deleting condition is
// updated to surface the block reason to the user.
func (h *Handler) blockOnDependents(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection,
) error {
	log := logr.FromContextOrDiscard(ctx)

	dependents, err := h.listDependents(ctx, conn.Name)
	if err != nil {
		log.Error(err, "failed to list dependents")
		return fmt.Errorf("failed to check for dependent resources: %w", err)
	}
	if len(dependents) == 0 {
		return nil
	}

	msg := fmt.Sprintf("deletion blocked: %d dependent resource(s) still reference this connection: %s",
		len(dependents), strings.Join(dependents, ", "))
	log.Info(msg)

	conn.Status.Phase = vaultv1alpha1.PhaseDeleting
	conn.Status.Conditions = conditions.Set(conn.Status.Conditions, conn.Generation,
		vaultv1alpha1.ConditionTypeDeleting, metav1.ConditionFalse,
		vaultv1alpha1.ReasonChildrenExist, msg)
	if updateErr := h.client.Status().Update(ctx, conn); updateErr != nil {
		log.V(1).Info("failed to update deletion-blocked status", "error", updateErr)
	}
	return errors.New(msg)
}

// markPhaseDeleting persists Phase=Deleting on the connection. Failures are
// logged at V(1) — the cleanup proceeds regardless because losing the
// status update doesn't change the on-disk reality of the resources.
func (h *Handler) markPhaseDeleting(ctx context.Context, conn *vaultv1alpha1.VaultConnection) {
	conn.Status.Phase = vaultv1alpha1.PhaseDeleting
	if err := h.client.Status().Update(ctx, conn); err != nil {
		logr.FromContextOrDiscard(ctx).V(1).Info(
			"failed to update status to Deleting (ignoring)", "error", err)
	}
}

// tearDownVaultState revokes Vault-side resources we own:
// the bootstrap-created auth mount (when CleanupAuthMount opt-in) and the
// operator's own token. All operations are best-effort.
func (h *Handler) tearDownVaultState(ctx context.Context, conn *vaultv1alpha1.VaultConnection) {
	h.disableAuthMountIfOptedIn(ctx, conn)
	h.revokeOperatorToken(ctx, conn)
}

// disableAuthMountIfOptedIn disables the Kubernetes auth mount when the
// user explicitly set CleanupAuthMount=true and bootstrap had completed.
// WARNING: this revokes ALL tokens issued through the mount.
func (h *Handler) disableAuthMountIfOptedIn(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection,
) {
	if !shouldCleanupAuthMount(conn) {
		return
	}
	authPath := defaultKubernetesAuthPath
	if conn.Spec.Auth.Kubernetes != nil && conn.Spec.Auth.Kubernetes.AuthPath != "" {
		authPath = conn.Spec.Auth.Kubernetes.AuthPath
	}
	cachedClient, err := h.clientCache.Get(conn.Name)
	if err != nil {
		return
	}
	log := logr.FromContextOrDiscard(ctx)
	if disableErr := cachedClient.DisableAuth(ctx, authPath); disableErr != nil {
		log.Error(disableErr, "failed to disable auth mount (non-fatal)", "path", authPath)
		return
	}
	log.Info("disabled auth mount created during bootstrap", "path", authPath)
}

// shouldCleanupAuthMount reports whether the user opted in to disabling
// the bootstrap-created auth mount on connection deletion.
func shouldCleanupAuthMount(conn *vaultv1alpha1.VaultConnection) bool {
	return conn.Spec.Auth.Bootstrap != nil &&
		conn.Spec.Auth.Bootstrap.CleanupAuthMount != nil &&
		*conn.Spec.Auth.Bootstrap.CleanupAuthMount &&
		conn.Status.AuthStatus != nil &&
		conn.Status.AuthStatus.BootstrapComplete
}

// revokeOperatorToken revokes the operator's own Vault token before we
// lose the cached client reference. Bounded by a 5s timeout because Vault
// may be unreachable during cluster teardown.
func (h *Handler) revokeOperatorToken(ctx context.Context, conn *vaultv1alpha1.VaultConnection) {
	cachedClient, err := h.clientCache.Get(conn.Name)
	if err != nil || !cachedClient.IsAuthenticated() {
		return
	}
	revokeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	log := logr.FromContextOrDiscard(ctx)
	if revokeErr := cachedClient.RevokeSelf(revokeCtx); revokeErr != nil {
		log.V(1).Info("failed to revoke Vault token (non-fatal)", "error", revokeErr)
		return
	}
	log.Info("revoked Vault token for deleted connection")
}

// unregisterTokenControllers detaches this connection from the renewal
// and reviewer-rotation background loops.
func (h *Handler) unregisterTokenControllers(conn *vaultv1alpha1.VaultConnection) {
	if h.lifecycleCtrl != nil {
		h.lifecycleCtrl.Unregister(conn.Name)
	}
	if h.reviewerCtrl != nil {
		h.reviewerCtrl.Unregister(conn.Name)
	}
}

// isAuthError returns true if the error indicates a Vault authentication/authorization failure.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "invalid token") ||
		strings.Contains(msg, "Code: 403")
}

// handleSyncError updates the status to error state and returns the error.
func (h *Handler) handleSyncError(ctx context.Context, conn *vaultv1alpha1.VaultConnection, err error) error {
	// If the error looks like an auth failure, evict the cached client
	// so the next reconciliation performs a full re-auth with fresh credentials.
	if isAuthError(err) {
		h.clientCache.Delete(conn.Name)
		h.log.Info("evicted cached client due to auth failure", "connectionName", conn.Name)
	}

	conn.Status.Phase = vaultv1alpha1.PhaseError
	conn.Status.Message = err.Error()
	h.setCondition(conn, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
		vaultv1alpha1.ReasonFailed, err.Error())

	// Update health status if not already updated (for errors before explicit health check)
	if conn.Status.LastHealthCheck == nil {
		now := metav1.Now()
		conn.Status.LastHealthCheck = &now
		h.updateHealthStatus(conn, false, err.Error())
	}

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
	vaultClient, err := h.newUnauthenticatedVaultClient(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	if err := h.authenticate(ctx, vaultClient, conn); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	return vaultClient, nil
}

// renewalThreshold is the fraction of TTL at which to trigger renewal.
// At 0.75, renewal occurs when 75% of the TTL has elapsed (25% remaining).
const renewalThreshold = 0.75

// getOrRenewClient tries to reuse a cached Vault client, renewing if needed.
// Returns the client, whether a renewal occurred, and any error.
func (h *Handler) getOrRenewClient(
	ctx context.Context,
	conn *vaultv1alpha1.VaultConnection,
) (*vault.Client, bool, error) {
	log := logr.FromContextOrDiscard(ctx)

	// Try to reuse the cached client
	cachedClient, cacheErr := h.clientCache.Get(conn.Name)
	if cacheErr == nil && cachedClient != nil && cachedClient.IsAuthenticated() {
		// Verify the cached client points to the same Vault address
		if cachedClient.Address() == conn.Spec.Address {
			exp := cachedClient.TokenExpiration()
			ttl := cachedClient.TokenTTL()

			if !exp.IsZero() && ttl > 0 {
				remaining := time.Until(exp)

				if remaining > 0 {
					// Token hasn't expired yet
					threshold := time.Duration(float64(ttl) * (1 - renewalThreshold))

					if remaining > threshold {
						// Token still fresh, reuse without renewal
						log.V(1).Info("reusing cached vault client",
							"connectionName", conn.Name,
							"remaining", remaining.Round(time.Second),
						)
						return cachedClient, false, nil
					}

					// Token approaching expiration, check renewal strategy
					shouldTryRenew := true
					if conn.Spec.Auth.Kubernetes != nil &&
						conn.Spec.Auth.Kubernetes.RenewalStrategy == vaultv1alpha1.RenewalStrategyReauth {
						shouldTryRenew = false
						log.Info("reauth strategy configured, skipping renewal attempt",
							"connectionName", conn.Name,
						)
					}

					if shouldTryRenew {
						// Try renewal first (default strategy)
						log.Info("token approaching expiration, attempting renewal",
							"connectionName", conn.Name,
							"remaining", remaining.Round(time.Second),
							"ttl", ttl,
						)
						if err := cachedClient.RenewSelf(ctx); err == nil {
							log.Info("token renewed successfully",
								"connectionName", conn.Name,
								"newExpiration", cachedClient.TokenExpiration(),
							)
							return cachedClient, true, nil
						} else {
							log.Info("token renewal failed, re-authenticating",
								"connectionName", conn.Name,
								"error", err,
							)
						}
					}
				}
				// Token expired or renewal failed, fall through to re-auth
			} else {
				// No expiration info (e.g., static token), just reuse
				return cachedClient, false, nil
			}
		}
	}

	// Full re-authentication
	vaultClient, err := h.buildAndAuthenticateClient(ctx, conn)
	if err != nil {
		return nil, false, err
	}

	// Count re-auth as renewal if there was a previous cached client
	wasReauth := cacheErr == nil && cachedClient != nil && cachedClient.IsAuthenticated()
	return vaultClient, wasReauth, nil
}

// trackRenewal increments the renewal counter and timestamp in the CRD status.
func (h *Handler) trackRenewal(conn *vaultv1alpha1.VaultConnection) {
	if conn.Status.AuthStatus == nil {
		conn.Status.AuthStatus = &vaultv1alpha1.AuthStatus{}
	}
	conn.Status.AuthStatus.TokenRenewalCount++
	now := metav1.Now()
	conn.Status.AuthStatus.TokenLastRenewed = &now
}

// updateHealthStatus updates health monitoring fields and metrics.
func (h *Handler) updateHealthStatus(conn *vaultv1alpha1.VaultConnection, healthy bool, errMsg string) {
	now := metav1.Now()

	// Update health status fields
	conn.Status.Healthy = healthy

	if healthy {
		conn.Status.LastHealthyTime = &now
		conn.Status.HealthCheckError = ""
		conn.Status.ConsecutiveFails = 0
	} else {
		conn.Status.HealthCheckError = errMsg
		conn.Status.ConsecutiveFails++
	}

	// Update Prometheus metrics
	metrics.SetConnectionHealth(conn.Name, healthy)
	metrics.IncrementHealthCheck(conn.Name, healthy)
	metrics.SetConsecutiveFails(conn.Name, conn.Status.ConsecutiveFails)
}

// authenticate authenticates the Vault client using the configured auth method.
// Dispatch is delegated to authRegistry; per-method logic lives in authprovider.
func (h *Handler) authenticate(
	ctx context.Context,
	vaultClient *vault.Client,
	conn *vaultv1alpha1.VaultConnection,
) error {
	return h.authRegistry.Authenticate(ctx, vaultClient, conn)
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
	conn.Status.Conditions = conditions.Set(
		conn.Status.Conditions, conn.Generation,
		condType, status, reason, message,
	)
}

// Ensure Handler implements FeatureHandler interface.
var _ base.FeatureHandler[*vaultv1alpha1.VaultConnection] = (*Handler)(nil)
