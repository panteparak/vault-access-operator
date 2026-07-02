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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/pkg/vault/auth"
	"github.com/panteparak/vault-access-operator/pkg/vault/bootstrap"
	"github.com/panteparak/vault-access-operator/pkg/vault/token"
	"github.com/panteparak/vault-access-operator/shared/controller/base"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
	"github.com/panteparak/vault-access-operator/shared/markers"
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
	// recorder is optional; used for k8s-native events that should appear
	// in `kubectl describe vaultconnection X` (e.g. VaultUnsealed transition
	// per IMPROVEMENTS Missing Features §C). nil-safe — all uses guard.
	recorder record.EventRecorder
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
	// Recorder is optional. When set, the handler emits k8s events for
	// notable transitions (currently: VaultUnsealed). When nil, the
	// handler is silent on this channel.
	Recorder record.EventRecorder
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
		recorder:         cfg.Recorder,
	}

	// Create bootstrap manager if we have token provider
	if cfg.TokenProvider != nil && cfg.ClusterDiscovery != nil {
		h.bootstrapMgr = bootstrap.NewManager(cfg.TokenProvider, cfg.ClusterDiscovery, cfg.Log)
	}

	return h
}

// Sync synchronizes the VaultConnection with Vault.
// It handles three phases: bootstrap → transition → production.
//
// Design note (IMPROVEMENTS §16): this method deliberately does NOT use
// `shared/controller/workflow.SyncWorkflow` (which powers Policy/Role
// reconciliation). That workflow assumes a resource shape of
// "validate → conflict check → prepare content → write → readback" —
// steps which don't map onto a VaultConnection whose sync flow is
// "authenticate → health check → update auth status". Forcing a fit
// would require heavy per-step parameterization and still leave callers
// stepping around the connection-specific bootstrap state machine. The
// duplicated error-handling / status-update shape is intentional and
// should not be "unified" without revisiting the workflow interface.
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

	// Phase 2: Normal auth — try cached client with renewal, fall back to fresh auth
	vaultClient, renewed, err := h.getOrRenewClient(ctx, conn)
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

	// Explicit health validation — ensure Vault is initialized and unsealed
	now := metav1.Now()
	conn.Status.LastHealthCheck = &now

	// IMPROVEMENTS Missing Features §C: split health check into seal-status
	// + general health so a sealed Vault returns a typed VaultSealedError
	// (faster requeue, distinct condition reason) instead of a generic
	// "not healthy" failure.
	initialized, sealed, err := vaultClient.SealStatus(ctx)
	if err != nil {
		h.updateHealthStatus(conn, false, fmt.Sprintf("seal-status check failed: %v", err))
		return h.handleSyncError(ctx, conn, fmt.Errorf("vault seal-status check failed: %w", err))
	}
	if !initialized || sealed {
		var statusMsg string
		if !initialized {
			statusMsg = "vault is not initialized"
		} else {
			statusMsg = "vault is sealed"
		}
		h.updateHealthStatus(conn, false, statusMsg)
		return h.handleSyncError(ctx, conn,
			infraerrors.NewVaultSealedError(conn.Name, conn.Spec.Address, initialized))
	}

	// Detect a sealed→unsealed transition by inspecting the current
	// Ready/Healthy condition's reason: if the previous reconcile set
	// it to ReasonVaultSealed (or NotInitialized), and we just observed
	// Vault as healthy, emit a recovery event so operators see the
	// unseal moment in the event log.
	if h.recorder != nil && wasSealedReason(conn.Status.Conditions) {
		h.recorder.Event(conn, corev1.EventTypeNormal,
			"VaultUnsealed",
			"Vault transitioned from sealed to unsealed; resuming normal sync")
	}

	// Now perform the full health check (which includes the sealed check
	// for backward compat — already passed at this point so it's a no-op).
	healthy, err := vaultClient.IsHealthy(ctx)
	if err != nil {
		h.updateHealthStatus(conn, false, fmt.Sprintf("health check failed: %v", err))
		return h.handleSyncError(ctx, conn, fmt.Errorf("vault health check failed: %w", err))
	}
	if !healthy {
		h.updateHealthStatus(conn, false, "vault is not healthy")
		return h.handleSyncError(ctx, conn, fmt.Errorf("vault is not healthy"))
	}

	// Update health status on success
	h.updateHealthStatus(conn, true, "")

	// Ownership tracking (ADR 0008) identifies this operator by the auth
	// mount it logged in through. A static-token connection has no mount —
	// ownership records it writes carry no identity, so on a shared Vault
	// another operator cannot be told apart from this one. Warn once on the
	// transition into Active.
	if markers.Enabled() && conn.Status.Phase != vaultv1alpha1.PhaseActive &&
		vaultClient.AuthMount() == "" {
		logr.FromContextOrDiscard(ctx).Info(
			"ownership identity unavailable: static-token connections have no auth mount "+
				"(unsupported for multi-operator shared Vaults)", "connection", conn.Name)
		if h.recorder != nil {
			h.recorder.Event(conn, corev1.EventTypeWarning,
				"OwnershipIdentityUnavailable",
				"Managed-marker tracking is on, but this connection authenticates with a "+
					"static token and therefore has no auth-mount identity (ADR 0008). "+
					"Ownership records will not distinguish this operator from others "+
					"sharing the Vault server.")
		}
	}

	// Update AuthStatus for Kubernetes auth
	if conn.Spec.Auth.Kubernetes != nil {
		h.updateAuthStatus(conn, vaultClient)
		if renewed {
			h.trackRenewal(conn)
		}
		// IMPROVEMENTS §1: enroll this connection in the leader-gated reviewer
		// rotator so its token_reviewer_jwt is refreshed before expiry.
		h.registerTokenReviewer(ctx, conn, vaultClient)
	}

	// Update status to Active
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

	// The restore-managed-markers annotation (pre-ADR-0008) is obsolete:
	// ownership now travels in-band with each policy write, so a wiped
	// "marker tree" no longer exists. Policies self-heal on their next
	// sync. Clear the annotation if present so users get feedback instead
	// of a silent no-op.
	if conn.GetAnnotations()[vaultv1alpha1.AnnotationRestoreManagedMarkers] == vaultv1alpha1.AnnotationValueTrue {
		log.Info("restore-managed-markers annotation is obsolete (ADR 0008): " +
			"ownership is stored in-band and self-heals on each sync; clearing annotation")
		if patchErr := h.clearAnnotation(ctx, conn, vaultv1alpha1.AnnotationRestoreManagedMarkers); patchErr != nil {
			log.V(1).Info("failed to clear restore-managed-markers annotation (non-fatal)",
				"error", patchErr.Error())
		}
	}

	log.Info("VaultConnection synced successfully", "version", version)
	return nil
}

// clearAnnotation removes the named annotation via a strategic merge
// patch. Used after a successful one-shot trigger (e.g.
// restore-managed-markers) to prevent re-firing on the next reconcile.
func (h *Handler) clearAnnotation(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection, annotation string,
) error {
	if _, ok := conn.GetAnnotations()[annotation]; !ok {
		return nil
	}
	patch := client.RawPatch(
		types.MergePatchType,
		[]byte(fmt.Sprintf(`{"metadata":{"annotations":{%q:null}}}`, annotation)),
	)
	return h.client.Patch(ctx, conn, patch)
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

	// Get bootstrap token from secret.
	// SECURITY: bootstrapToken must not appear in error messages or status fields.
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

	// If KubernetesHost is set, pass it as override to prevent auto-discovery
	// from using in-cluster address that external Vault can't reach.
	if k8sAuth.KubernetesHost != "" {
		bootstrapConfig.KubernetesConfig = &bootstrap.KubernetesClusterConfig{
			Host: k8sAuth.KubernetesHost,
		}
	}

	// Run bootstrap
	result, err := h.bootstrapMgr.Bootstrap(ctx, vaultClient, bootstrapConfig)
	if err != nil {
		// IMPROVEMENTS §10: the manager returns a partially-populated result on
		// failure. Record the steps that completed so a failed bootstrap is
		// diagnosable via `kubectl get vaultconnection X -o yaml` instead of
		// leaving BootstrapSteps empty.
		if result != nil {
			if conn.Status.AuthStatus == nil {
				conn.Status.AuthStatus = &vaultv1alpha1.AuthStatus{}
			}
			conn.Status.AuthStatus.BootstrapSteps = bootstrapSteps(result, metav1.Now().UTC().Format(time.RFC3339))
		}
		return h.handleSyncError(ctx, conn, fmt.Errorf("bootstrap failed: %w", err))
	}

	// Update status with bootstrap result
	now := metav1.Now()
	if conn.Status.AuthStatus == nil {
		conn.Status.AuthStatus = &vaultv1alpha1.AuthStatus{}
	}
	// Only flip BootstrapComplete=true when the K8s auth test actually
	// passed. Earlier this was set unconditionally, which produced a
	// permanently stuck connection: the bootstrap manager returns
	// (result, nil) even on test failure (errors are captured to
	// result.K8sAuthTestError instead). With BootstrapComplete=true,
	// `isBootstrapRequired` returns false on every subsequent reconcile,
	// so the (idempotent) bootstrap path is never re-attempted, the
	// normal auth path fails for the same reason the test did, and the
	// operator reports BootstrapComplete=true while being unable to
	// authenticate. Gating on K8sAuthTestPassed keeps re-running
	// bootstrap until the test passes (which is what the manager's
	// "operator will retry on next reconcile" comment promised).
	conn.Status.AuthStatus.BootstrapComplete = result.K8sAuthTestPassed
	if result.K8sAuthTestPassed {
		conn.Status.AuthStatus.BootstrapCompletedAt = &now
	}
	conn.Status.AuthStatus.AuthMethod = defaultKubernetesAuthPath

	// IMPROVEMENTS §10: record which individual bootstrap steps completed so
	// operators inspecting `kubectl get vaultconnection X -o yaml` can see
	// exactly what ran. Shared with the partial-failure path above so a
	// bootstrap that fails midway records the same way.
	conn.Status.AuthStatus.BootstrapSteps = bootstrapSteps(result, now.UTC().Format(time.RFC3339))

	if !result.TokenReviewerExpiration.IsZero() {
		expTime := metav1.NewTime(result.TokenReviewerExpiration)
		conn.Status.AuthStatus.TokenReviewerExpiration = &expTime
	}

	// Pick log severity based on whether anything failed. Earlier this
	// always said "successfully" even when RevokeSelf or the K8s auth
	// test had failed — operators reading logs at default verbosity
	// thought everything was green when in fact a long-lived bootstrap
	// token might still be lingering or the K8s auth wiring was broken.
	switch {
	case result.K8sAuthTestError != "" || result.BootstrapRevokeError != "":
		log.Info("bootstrap completed with non-fatal errors",
			"authMethodCreated", result.AuthMethodCreated,
			"roleCreated", result.RoleCreated,
			"bootstrapRevoked", result.BootstrapRevoked,
			"k8sAuthTestError", result.K8sAuthTestError,
			"bootstrapRevokeError", result.BootstrapRevokeError,
		)
	default:
		log.Info("bootstrap completed successfully",
			"authMethodCreated", result.AuthMethodCreated,
			"roleCreated", result.RoleCreated,
			"bootstrapRevoked", result.BootstrapRevoked,
		)
	}

	// Set the Bootstrapped condition so operators querying conditions
	// see explicit confirmation immediately instead of having to wait
	// for the next reconcile to land Ready=True via the normal path.
	// Status reflects the actual K8s auth test outcome — False with
	// the captured reason when the test failed.
	bootstrapStatus := metav1.ConditionFalse
	bootstrapReason := vaultv1alpha1.ReasonFailed
	bootstrapMsg := "Bootstrap completed but K8s auth test failed; will retry on next reconcile"
	if result.K8sAuthTestError != "" {
		bootstrapMsg = "Bootstrap completed but K8s auth test failed: " + result.K8sAuthTestError
	}
	if result.K8sAuthTestPassed {
		bootstrapStatus = metav1.ConditionTrue
		bootstrapReason = vaultv1alpha1.ReasonSucceeded
		bootstrapMsg = "Bootstrap completed and K8s auth verified"
	}
	conn.Status.Conditions = conditions.Set(conn.Status.Conditions, conn.Generation,
		vaultv1alpha1.ConditionTypeBootstrapped, bootstrapStatus,
		bootstrapReason, bootstrapMsg)

	// Persist bootstrap status so the next reconcile sees BootstrapComplete = true
	// and proceeds to the normal auth path instead of re-running bootstrap.
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

// registerTokenReviewer enrolls this connection in the leader-gated reviewer
// rotator (IMPROVEMENTS §1) so the token_reviewer_jwt Vault uses to call the
// Kubernetes TokenReview API is refreshed before it expires. Without this the
// JWT expires (~24h after bootstrap configures it) and K8s auth silently breaks
// on long-running operators.
//
// Called every reconcile but careful to register only once: the controller's
// Register REPLACES per-connection state (resetting the refresh schedule), so
// calling it each reconcile (every 30s) would keep wiping NextRefresh and the
// background loop — which only fires when NextRefresh is set — would never run.
// SetVaultClient is refreshed every reconcile because getOrRenewClient may have
// produced a new *vault.Client for this connection. No-op when the controller
// isn't configured (unit tests) or rotation is explicitly disabled.
func (h *Handler) registerTokenReviewer(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection, vaultClient *vault.Client,
) {
	if h.reviewerCtrl == nil {
		return
	}
	k8sAuth := conn.Spec.Auth.Kubernetes
	if k8sAuth == nil {
		return
	}
	log := logr.FromContextOrDiscard(ctx)

	// Rotation enabled unless explicitly set false (mirrors the disabled warning
	// in updateAuthStatus). If toggled off, drop any prior registration.
	if k8sAuth.TokenReviewerRotation != nil && !*k8sAuth.TokenReviewerRotation {
		h.reviewerCtrl.Unregister(conn.Name)
		return
	}

	firstRegistration := h.reviewerCtrl.GetStatus(conn.Name) == nil
	if firstRegistration {
		authPath := k8sAuth.AuthPath
		if authPath == "" {
			authPath = defaultKubernetesAuthPath
		}
		if err := h.reviewerCtrl.Register(conn.Name, &token.ReviewerConfig{
			ServiceAccount: token.ServiceAccountRef{
				Name:      getOperatorServiceAccountName(),
				Namespace: getOperatorNamespace(),
			},
			VaultAuthPath: authPath,
		}); err != nil {
			log.Error(err, "failed to register connection for token-reviewer rotation",
				"connectionName", conn.Name)
			return
		}
	}

	// Always point the rotator at the current client — it may have been renewed
	// or rebuilt since the previous reconcile.
	h.reviewerCtrl.SetVaultClient(conn.Name, vaultClient)

	// Prime the refresh schedule once: an initial Refresh sets NextRefresh so the
	// background loop starts tracking this connection. Best-effort — on failure
	// the controller still schedules a retry, and the next reconcile re-attempts.
	if firstRegistration {
		if err := h.reviewerCtrl.Refresh(ctx, conn.Name); err != nil {
			log.V(1).Info("initial token_reviewer_jwt refresh failed; rotator will retry",
				"connectionName", conn.Name, "error", err.Error())
		}
	}
}

// listDependents returns a list of resources that reference this VaultConnection.
// Each entry is formatted as "Type/namespace/name" or "Type/name" for cluster-scoped resources.
// listDependents returns a human-readable list of every namespaced and
// cluster-scoped policy/role that references this VaultConnection. Used by
// Cleanup to block deletion while dependents exist.
//
// Implementation (IMPROVEMENTS §15): uses the spec.connectionRef field
// indexer registered in reconciler.SetupWithManager. This replaces four
// cluster-wide list-then-filter passes with four indexed queries that scale
// with the number of dependents rather than with total CRs.
func (h *Handler) listDependents(ctx context.Context, connName string) ([]string, error) {
	var dependents []string
	matcher := client.MatchingFields{IndexFieldConnectionRef: connName}

	var policies vaultv1alpha1.VaultPolicyList
	if err := h.client.List(ctx, &policies, matcher); err != nil {
		return nil, fmt.Errorf("failed to list VaultPolicies: %w", err)
	}
	for i := range policies.Items {
		dependents = append(dependents, fmt.Sprintf("VaultPolicy/%s/%s",
			policies.Items[i].Namespace, policies.Items[i].Name))
	}

	var clusterPolicies vaultv1alpha1.VaultClusterPolicyList
	if err := h.client.List(ctx, &clusterPolicies, matcher); err != nil {
		return nil, fmt.Errorf("failed to list VaultClusterPolicies: %w", err)
	}
	for i := range clusterPolicies.Items {
		dependents = append(dependents, fmt.Sprintf("VaultClusterPolicy/%s",
			clusterPolicies.Items[i].Name))
	}

	var roles vaultv1alpha1.VaultRoleList
	if err := h.client.List(ctx, &roles, matcher); err != nil {
		return nil, fmt.Errorf("failed to list VaultRoles: %w", err)
	}
	for i := range roles.Items {
		dependents = append(dependents, fmt.Sprintf("VaultRole/%s/%s",
			roles.Items[i].Namespace, roles.Items[i].Name))
	}

	var clusterRoles vaultv1alpha1.VaultClusterRoleList
	if err := h.client.List(ctx, &clusterRoles, matcher); err != nil {
		return nil, fmt.Errorf("failed to list VaultClusterRoles: %w", err)
	}
	for i := range clusterRoles.Items {
		dependents = append(dependents, fmt.Sprintf("VaultClusterRole/%s",
			clusterRoles.Items[i].Name))
	}

	return dependents, nil
}

// Cleanup removes the Vault client from the cache when the connection is deleted.
func (h *Handler) Cleanup(ctx context.Context, conn *vaultv1alpha1.VaultConnection) error {
	log := logr.FromContextOrDiscard(ctx)

	// Check for dependent resources before proceeding with cleanup
	dependents, err := h.listDependents(ctx, conn.Name)
	if err != nil {
		log.Error(err, "failed to list dependents")
		return fmt.Errorf("failed to check for dependent resources: %w", err)
	}
	if len(dependents) > 0 {
		// Cap the dependents enumeration in the condition message — at
		// ~50 bytes per "VaultPolicy/<ns>/<name>" entry, an unbounded
		// list for a connection with 1000+ dependents produced a 50KB+
		// condition message. Combined with other large status fields
		// (DiscoveredResources up to 500 entries, etc.) the per-object
		// size could push past etcd's 1.5MB limit and silently fail
		// the Status update. The full list still appears in the log
		// (which has its own bounds elsewhere).
		const maxDependentsInMsg = 20
		shortList := dependents
		summary := ""
		if len(dependents) > maxDependentsInMsg {
			shortList = dependents[:maxDependentsInMsg]
			summary = fmt.Sprintf(" (showing %d of %d; see operator logs for full list)",
				maxDependentsInMsg, len(dependents))
		}
		msg := fmt.Sprintf("deletion blocked: %d dependent resource(s) still reference this connection: %s%s",
			len(dependents), strings.Join(shortList, ", "), summary)

		// Log the full list so operators can grep `kubectl logs` for
		// the complete enumeration when the condition truncates.
		log.Info("deletion blocked by dependents",
			"count", len(dependents), "dependents", dependents)

		// Set Deleting condition to indicate blocked state
		conn.Status.Phase = vaultv1alpha1.PhaseDeleting
		conn.Status.Conditions = conditions.Set(conn.Status.Conditions, conn.Generation,
			vaultv1alpha1.ConditionTypeDeleting, metav1.ConditionFalse,
			vaultv1alpha1.ReasonChildrenExist, msg)
		if updateErr := h.client.Status().Update(ctx, conn); updateErr != nil {
			log.V(1).Info("failed to update deletion-blocked status", "error", updateErr)
		}
		return fmt.Errorf("%s", msg)
	}

	// Update phase to Deleting
	conn.Status.Phase = vaultv1alpha1.PhaseDeleting
	if err := h.client.Status().Update(ctx, conn); err != nil {
		log.V(1).Info("failed to update status to Deleting (ignoring)", "error", err)
	}

	// Disable auth mount if opted in (before token revocation, since disabling
	// the mount revokes all tokens through it anyway)
	if conn.Spec.Auth.Bootstrap != nil &&
		conn.Spec.Auth.Bootstrap.CleanupAuthMount != nil &&
		*conn.Spec.Auth.Bootstrap.CleanupAuthMount &&
		conn.Status.AuthStatus != nil &&
		conn.Status.AuthStatus.BootstrapComplete {
		authPath := defaultKubernetesAuthPath
		if conn.Spec.Auth.Kubernetes != nil && conn.Spec.Auth.Kubernetes.AuthPath != "" {
			authPath = conn.Spec.Auth.Kubernetes.AuthPath
		}
		if cachedClient, err := h.clientCache.Get(conn.Name); err == nil {
			if err := cachedClient.DisableAuth(ctx, authPath); err != nil {
				// The user opted into CleanupAuthMount=true expecting the
				// auth mount to be disabled on connection deletion.
				// Pre-fix this error was only logged — the K8s CR then
				// vanished via finalizer removal while the Vault auth
				// mount lived on, leaking. Surface via a Warning event
				// so the audit trail shows "we tried and failed" instead
				// of the user thinking cleanup was complete.
				log.Error(err, "failed to disable auth mount (non-fatal)", "path", authPath)
				if h.recorder != nil {
					h.recorder.Eventf(conn, corev1.EventTypeWarning,
						"DisableAuthFailed",
						"Failed to disable Vault auth mount %q on connection deletion: %v — "+
							"the mount may still be enabled in Vault and require manual cleanup",
						authPath, err)
				}
			} else {
				log.Info("disabled auth mount created during bootstrap", "path", authPath)
			}
		}
	}

	// Revoke operator token before losing the reference (best-effort).
	// Skip for TokenAuth: the token is supplied by the user via Secret,
	// so the user owns its lifecycle. Revoking it would kill every other
	// VaultConnection (and any non-operator caller) that shares the same
	// Secret — see e2e flake where TC-EDGE-REC's sidecar VaultConnection
	// poisoned the shared operator token used by every later suite.
	if conn.Spec.Auth.Token == nil {
		if cachedClient, err := h.clientCache.Get(conn.Name); err == nil && cachedClient.IsAuthenticated() {
			revokeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := cachedClient.RevokeSelf(revokeCtx); err != nil {
				log.V(1).Info("failed to revoke Vault token (non-fatal)", "error", err)
			} else {
				log.Info("revoked Vault token for deleted connection")
			}
		}
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

	// Wipe per-connection Prometheus series so the registry doesn't grow
	// linearly with connection churn. Without this, a CI cluster that
	// spins up ephemeral VaultConnection-per-PR resources accumulates
	// stale series for every PR ever merged. Mirrors the existing
	// metrics.DeleteDriftDetected pattern from the cleanup workflow.
	metrics.DeleteConnectionMetrics(conn.Name)
	metrics.DeleteOrphanedResourcesMetrics(conn.Name)
	metrics.DeleteDiscoveryMetrics(conn.Name)

	// Publish ConnectionDisconnected event
	if h.eventBus != nil {
		h.eventBus.PublishAsync(ctx, events.NewConnectionDisconnected(conn.Name, "resource deleted"))
	}

	log.Info("VaultConnection cleanup completed")
	return nil
}

// isAuthError returns true if the error indicates a Vault
// authentication/authorization failure.
//
// Primary path: typed `*vaultapi.ResponseError` with a 4xx status that
// Vault uses for auth failures (401 invalid token, 403 permission
// denied). The Vault SDK wraps API failures in this type, so
// `errors.As` traverses any fmt.Errorf("%w") wrap chain.
//
// Fallback substring match is kept for compatibility with the few code
// paths that synthesize errors from non-SDK sources, but the typed
// path catches the common case without depending on Vault's wording
// (which has changed across SDK versions). Earlier versions of this
// function were substring-only, which silently broke when the SDK
// changed "Code: 403" formatting.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		// 401 = bad token; 403 = permission denied. Both indicate the
		// cached token is no longer usable and the cache should be evicted.
		switch respErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "invalid token") ||
		strings.Contains(msg, "Code: 403")
}

// handleSyncError updates the status to error state and returns the error.
//
// Classifies the error to set a precise condition Reason — operators get
// a distinct signal for transport failures (NetworkError), sealed Vault
// (VaultSealed / VaultNotInitialized — IMPROVEMENTS Missing Features §C),
// or generic failures (Failed). The reason field is what the wasSealedReason
// helper inspects on the *next* reconcile to decide whether to emit the
// VaultUnsealed recovery event, so getting it right here is load-bearing.
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
		classifyConnectionError(err), err.Error())

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

// classifyConnectionError maps a sync error to the matching Ready
// condition Reason. Mirrors the logic in syncerror.Handle (used by
// policy/role) but kept local because the connection handler doesn't
// route through that shared classifier (see IMPROVEMENTS §16 — the
// connection feature deliberately doesn't use SyncWorkflow).
func classifyConnectionError(err error) string {
	var sealedErr *infraerrors.VaultSealedError
	if errors.As(err, &sealedErr) {
		if !sealedErr.Initialized {
			return vaultv1alpha1.ReasonVaultNotInitialized
		}
		return vaultv1alpha1.ReasonVaultSealed
	}
	if infraerrors.IsConnectionError(err) {
		return vaultv1alpha1.ReasonNetworkError
	}
	return vaultv1alpha1.ReasonFailed
}

// bootstrapSteps maps a bootstrap.Result into the AuthStatus.BootstrapSteps
// map (step name → RFC3339 timestamp, or an error string for the *Failed
// keys). Shared by the success and partial-failure paths (IMPROVEMENTS §10)
// so a bootstrap that fails midway records exactly the steps it completed
// rather than leaving the map empty.
func bootstrapSteps(result *bootstrap.Result, nowStr string) map[string]string {
	steps := map[string]string{}
	if result.AuthMethodCreated {
		steps["AuthMountEnabled"] = nowStr
	}
	if result.AuthConfigured {
		steps["AuthMountConfigured"] = nowStr
	}
	// OperatorPolicy is referenced by the role write rather than created as a
	// distinct step, so RoleCreated implies both.
	if result.RoleCreated {
		steps["OperatorPolicyCreated"] = nowStr
		steps["OperatorRoleCreated"] = nowStr
	}
	if result.BootstrapRevoked {
		steps["BootstrapTokenRevoked"] = nowStr
	}
	// *Failed keys carry the error text (not a timestamp) so they're
	// distinguishable from completed steps.
	if result.K8sAuthTestError != "" {
		steps["K8sAuthTestFailed"] = "failed at " + nowStr + ": " + result.K8sAuthTestError
	}
	if result.BootstrapRevokeError != "" {
		steps["BootstrapTokenRevokeFailed"] = "failed at " + nowStr + ": " + result.BootstrapRevokeError
	}
	return steps
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

// renewalThreshold is the fraction of TTL at which to trigger renewal.
// At 0.75, renewal occurs when 75% of the TTL has elapsed (25% remaining).
const renewalThreshold = 0.75

// getOrRenewClient tries to reuse a cached Vault client, renewing if needed.
// Returns the client, whether a renewal occurred, and any error.
//
// The function bridges three sources of "the cached client is no longer
// good":
//
//  1. The auth source (referenced Secret content, role name, etc.)
//     changed since the cache was populated — `computeAuthSourceHash`
//     detects this and forces a rebuild. This is how Secret rotation
//     propagates; without it, the TTL-based reuse path keeps serving
//     the stale credentials until the original TTL elapses.
//  2. The token TTL is about to elapse — the existing renew/re-auth
//     branch handles this.
//  3. The token was revoked Vault-side out of band — `LookupSelf` is
//     an authenticated round-trip that returns 403 in that case, so
//     we evict and re-auth instead of returning a client that will
//     fail on first use in downstream controllers (policy/role).
func (h *Handler) getOrRenewClient(
	ctx context.Context,
	conn *vaultv1alpha1.VaultConnection,
) (*vault.Client, bool, error) {
	log := logr.FromContextOrDiscard(ctx)

	// Fingerprint the live auth source. Failure here is fatal — without
	// the source we can't authenticate at all, and returning a stale
	// cached client would just defer the same error to a worse caller.
	currentHash, hashErr := h.computeAuthSourceHash(ctx, conn)
	if hashErr != nil {
		return nil, false, fmt.Errorf("compute auth source hash: %w", hashErr)
	}

	cachedClient, cacheErr := h.clientCache.Get(conn.Name)
	hadCached := cacheErr == nil && cachedClient != nil && cachedClient.IsAuthenticated()

	// Source drift forces a rebuild before any TTL/lookup checks — the
	// cached token was minted from material we no longer hold.
	if hadCached && cachedClient.AuthSourceHash() != currentHash {
		log.Info("auth source changed since cached client was built; evicting",
			"connectionName", conn.Name)
		h.clientCache.Delete(conn.Name)
		hadCached = false
	}

	if hadCached && cachedClient.Address() == conn.Spec.Address {
		exp := cachedClient.TokenExpiration()
		ttl := cachedClient.TokenTTL()

		if !exp.IsZero() && ttl > 0 {
			remaining := time.Until(exp)

			if remaining > 0 {
				// Token hasn't expired yet
				threshold := time.Duration(float64(ttl) * (1 - renewalThreshold))

				if remaining > threshold {
					// Token is fresh by TTL — verify it's still valid
					// server-side before trusting it. sys/health (used
					// by Sync's GetVersion) doesn't authenticate, so a
					// revoked token would only surface in a downstream
					// controller. lookup-self is the cheapest
					// authenticated probe and is allowed by default
					// policy on every token.
					if lookupErr := cachedClient.LookupSelf(ctx); lookupErr == nil {
						log.V(1).Info("reusing cached vault client",
							"connectionName", conn.Name,
							"remaining", remaining.Round(time.Second),
						)
						return cachedClient, false, nil
					} else {
						log.Info("cached token failed lookup-self; re-authenticating",
							"connectionName", conn.Name, "error", lookupErr,
						)
						h.clientCache.Delete(conn.Name)
					}
				} else {
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
			}
			// Token expired or renewal failed, fall through to re-auth
		} else {
			// No expiration info (e.g., a static token whose login
			// response carried no LeaseDuration). The token can still
			// be revoked Vault-side, so validate before reusing.
			if lookupErr := cachedClient.LookupSelf(ctx); lookupErr == nil {
				return cachedClient, false, nil
			} else {
				log.Info("cached static token failed lookup-self; re-authenticating",
					"connectionName", conn.Name, "error", lookupErr,
				)
				h.clientCache.Delete(conn.Name)
			}
		}
	}

	// Full re-authentication
	vaultClient, err := h.buildAndAuthenticateClient(ctx, conn)
	if err != nil {
		return nil, false, err
	}
	vaultClient.SetAuthSourceHash(currentHash)

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
func (h *Handler) authenticate(
	ctx context.Context,
	vaultClient *vault.Client,
	conn *vaultv1alpha1.VaultConnection,
) error {
	// IMPROVEMENTS §6: dispatched via a strategy table so adding a new auth
	// method is a one-line append rather than a new branch in a 100-line
	// if/else chain. Each strategy is tested in isolation with a per-method
	// table-driven test.
	authCfg := conn.Spec.Auth
	for _, s := range authStrategies {
		if s.match(&authCfg) {
			if err := s.run(ctx, h, vaultClient, conn); err != nil {
				return fmt.Errorf("%s auth: %w", s.name, err)
			}
			return nil
		}
	}
	return fmt.Errorf("no authentication method configured")
}

// authStrategy describes one Vault authentication method in the dispatch
// table below. `match` identifies which AuthConfig sub-struct this strategy
// handles; `run` performs the method-specific pre-auth work (fetch secret,
// sign JWT, etc.) and calls the right `vaultClient.Authenticate<Method>`.
type authStrategy struct {
	name  string
	match func(*vaultv1alpha1.AuthConfig) bool
	run   func(ctx context.Context, h *Handler, vc *vault.Client, conn *vaultv1alpha1.VaultConnection) error
}

// authStrategies is the ordered auth-method dispatch table. Order matters
// only because the operator honors the FIRST matching method — paired with
// the webhook's "exactly one method" check (IMPROVEMENTS §8), a well-formed
// VaultConnection spec matches exactly one entry here. Ordering is
// informational: most-common-first reduces the average number of match
// checks per authenticate() call.
var authStrategies = []authStrategy{
	{
		name:  "kubernetes",
		match: func(a *vaultv1alpha1.AuthConfig) bool { return a.Kubernetes != nil },
		run: func(ctx context.Context, h *Handler, vc *vault.Client, conn *vaultv1alpha1.VaultConnection) error {
			cfg := conn.Spec.Auth.Kubernetes
			authPath := cfg.AuthPath
			if authPath == "" {
				authPath = defaultKubernetesAuthPath
			}
			tokenInfo, err := h.getServiceAccountToken(ctx, conn)
			if err != nil {
				return fmt.Errorf("failed to get service account token: %w", err)
			}
			return vc.AuthenticateKubernetesWithToken(ctx, cfg.Role, authPath, tokenInfo.Token)
		},
	},
	{
		name:  "token",
		match: func(a *vaultv1alpha1.AuthConfig) bool { return a.Token != nil },
		run: func(ctx context.Context, h *Handler, vc *vault.Client, conn *vaultv1alpha1.VaultConnection) error {
			tokenValue, err := h.getSecretData(ctx, &conn.Spec.Auth.Token.SecretRef)
			if err != nil {
				return fmt.Errorf("failed to get token from secret: %w", err)
			}
			return vc.AuthenticateToken(tokenValue)
		},
	},
	{
		name:  "appRole",
		match: func(a *vaultv1alpha1.AuthConfig) bool { return a.AppRole != nil },
		run: func(ctx context.Context, h *Handler, vc *vault.Client, conn *vaultv1alpha1.VaultConnection) error {
			cfg := conn.Spec.Auth.AppRole
			secretID, err := h.getSecretData(ctx, &cfg.SecretIDRef)
			if err != nil {
				return fmt.Errorf("failed to get secret ID from secret: %w", err)
			}
			mountPath := cfg.MountPath
			if mountPath == "" {
				mountPath = "approle"
			}
			return vc.AuthenticateAppRole(ctx, cfg.RoleID, secretID, mountPath)
		},
	},
	{
		name:  "jwt",
		match: func(a *vaultv1alpha1.AuthConfig) bool { return a.JWT != nil },
		run: func(ctx context.Context, h *Handler, vc *vault.Client, conn *vaultv1alpha1.VaultConnection) error {
			cfg := conn.Spec.Auth.JWT
			jwt, err := h.getJWTToken(ctx, cfg)
			if err != nil {
				return fmt.Errorf("failed to get JWT: %w", err)
			}
			authPath := cfg.AuthPath
			if authPath == "" {
				authPath = "jwt"
			}
			return vc.AuthenticateJWT(ctx, cfg.Role, authPath, jwt)
		},
	},
	{
		name:  "oidc",
		match: func(a *vaultv1alpha1.AuthConfig) bool { return a.OIDC != nil },
		run: func(ctx context.Context, h *Handler, vc *vault.Client, conn *vaultv1alpha1.VaultConnection) error {
			cfg := conn.Spec.Auth.OIDC
			jwt, err := h.getOIDCToken(ctx, cfg)
			if err != nil {
				return fmt.Errorf("failed to get OIDC token: %w", err)
			}
			authPath := cfg.AuthPath
			if authPath == "" {
				authPath = "oidc"
			}
			return vc.AuthenticateOIDC(ctx, cfg.Role, authPath, jwt)
		},
	},
	{
		name:  "aws",
		match: func(a *vaultv1alpha1.AuthConfig) bool { return a.AWS != nil },
		run: func(ctx context.Context, h *Handler, vc *vault.Client, conn *vaultv1alpha1.VaultConnection) error {
			cfg := conn.Spec.Auth.AWS
			loginData, err := h.getAWSLoginData(ctx, cfg)
			if err != nil {
				return fmt.Errorf("failed to generate AWS login data: %w", err)
			}
			authPath := cfg.AuthPath
			if authPath == "" {
				authPath = "aws"
			}
			return vc.AuthenticateAWS(ctx, cfg.Role, authPath, loginData)
		},
	},
	{
		name:  "gcp",
		match: func(a *vaultv1alpha1.AuthConfig) bool { return a.GCP != nil },
		run: func(ctx context.Context, h *Handler, vc *vault.Client, conn *vaultv1alpha1.VaultConnection) error {
			cfg := conn.Spec.Auth.GCP
			signedJWT, err := h.getGCPSignedJWT(ctx, cfg)
			if err != nil {
				return fmt.Errorf("failed to generate GCP signed JWT: %w", err)
			}
			authPath := cfg.AuthPath
			if authPath == "" {
				authPath = "gcp"
			}
			return vc.AuthenticateGCP(ctx, cfg.Role, authPath, signedJWT)
		},
	},
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
//
// VaultConnection is cluster-scoped, so SecretRef.Namespace MUST be
// explicit. Earlier this silently fell back to "default", which:
//
//   - masked typos / unintentional empty values (the user thought their
//     namespace was being used);
//   - created a footgun where a malicious tenant could plant a secret in
//     `default` matching another tenant's SecretRef.Name and have the
//     operator read it (the operator's RBAC reads cluster-wide).
//
// The webhook should also reject empty namespace at admission, but this
// runtime check fails closed for any CR that was created before the
// webhook was deployed (or with the webhook bypassed via failurePolicy).
func (h *Handler) getSecretData(ctx context.Context, ref *vaultv1alpha1.SecretKeySelector) (string, error) {
	if ref.Namespace == "" {
		return "", fmt.Errorf(
			"secretRef.namespace is required for cluster-scoped VaultConnection "+
				"(no implicit namespace fallback) — secret name=%q",
			ref.Name)
	}

	secret := &corev1.Secret{}
	if err := h.client.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, secret); err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}

	data, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", ref.Key, ref.Namespace, ref.Name)
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

// getJWTToken retrieves a JWT for the JWT auth method.
// Uses either a secret reference or the TokenRequest API.
func (h *Handler) getJWTToken(ctx context.Context, jwtCfg *vaultv1alpha1.JWTAuth) (string, error) {
	// If a JWT secret is provided, use it
	if jwtCfg.JWTSecretRef != nil {
		return h.getSecretData(ctx, jwtCfg.JWTSecretRef)
	}

	// Otherwise, use TokenRequest API to generate a short-lived token
	if h.tokenProvider == nil {
		return "", fmt.Errorf("token provider not configured for JWT auth")
	}

	// Determine duration
	duration := token.DefaultTokenDuration
	if jwtCfg.TokenDuration.Duration > 0 {
		duration = jwtCfg.TokenDuration.Duration
	}

	// Determine audiences
	audiences := jwtCfg.Audiences
	if len(audiences) == 0 {
		audiences = []string{"vault"}
	}

	// Get token from operator's service account
	saName := getOperatorServiceAccountName()
	saNamespace := getOperatorNamespace()

	tokenInfo, err := h.tokenProvider.GetToken(ctx, token.GetTokenOptions{
		ServiceAccount: token.ServiceAccountRef{
			Name:      saName,
			Namespace: saNamespace,
		},
		Duration:  duration,
		Audiences: audiences,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get JWT from TokenRequest: %w", err)
	}

	return tokenInfo.Token, nil
}

// getOIDCToken retrieves a JWT for the OIDC auth method.
// Uses the TokenRequest API with OIDC-specific audience configuration.
func (h *Handler) getOIDCToken(ctx context.Context, oidcCfg *vaultv1alpha1.OIDCAuth) (string, error) {
	// If a JWT secret is provided, use it
	if oidcCfg.JWTSecretRef != nil {
		return h.getSecretData(ctx, oidcCfg.JWTSecretRef)
	}

	// Check if we should use service account token
	useServiceAccountToken := true
	if oidcCfg.UseServiceAccountToken != nil {
		useServiceAccountToken = *oidcCfg.UseServiceAccountToken
	}

	if !useServiceAccountToken {
		return "", fmt.Errorf("OIDC auth requires either jwtSecretRef or useServiceAccountToken=true")
	}

	// Use TokenRequest API to generate a short-lived token
	if h.tokenProvider == nil {
		return "", fmt.Errorf("token provider not configured for OIDC auth")
	}

	// Determine duration
	duration := token.DefaultTokenDuration
	if oidcCfg.TokenDuration.Duration > 0 {
		duration = oidcCfg.TokenDuration.Duration
	}

	// Determine audiences - for OIDC, use the provider URL if no audiences specified
	audiences := oidcCfg.Audiences
	if len(audiences) == 0 && oidcCfg.ProviderURL != "" {
		audiences = []string{oidcCfg.ProviderURL}
	}
	if len(audiences) == 0 {
		audiences = []string{"vault"}
	}

	// Get token from operator's service account
	saName := getOperatorServiceAccountName()
	saNamespace := getOperatorNamespace()

	tokenInfo, err := h.tokenProvider.GetToken(ctx, token.GetTokenOptions{
		ServiceAccount: token.ServiceAccountRef{
			Name:      saName,
			Namespace: saNamespace,
		},
		Duration:  duration,
		Audiences: audiences,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get OIDC token from TokenRequest: %w", err)
	}

	return tokenInfo.Token, nil
}

// getAWSLoginData generates AWS IAM login data for Vault authentication.
func (h *Handler) getAWSLoginData(ctx context.Context, awsCfg *vaultv1alpha1.AWSAuth) (map[string]interface{}, error) {
	opts := auth.AWSAuthOptions{
		Region:                 awsCfg.Region,
		STSEndpoint:            awsCfg.STSEndpoint,
		IAMServerIDHeaderValue: awsCfg.IAMServerIDHeaderValue,
		Role:                   awsCfg.Role,
	}

	return auth.GenerateAWSIAMLoginData(ctx, opts)
}

// getGCPSignedJWT generates a GCP-signed JWT for Vault authentication.
func (h *Handler) getGCPSignedJWT(ctx context.Context, gcpCfg *vaultv1alpha1.GCPAuth) (string, error) {
	// Get credentials JSON if provided
	var credentialsJSON []byte
	if gcpCfg.CredentialsSecretRef != nil {
		creds, err := h.getSecretData(ctx, gcpCfg.CredentialsSecretRef)
		if err != nil {
			return "", fmt.Errorf("failed to get GCP credentials from secret: %w", err)
		}
		credentialsJSON = []byte(creds)
	}

	opts := auth.GCPAuthOptions{
		AuthType:            gcpCfg.AuthType,
		ServiceAccountEmail: gcpCfg.ServiceAccountEmail,
		Role:                gcpCfg.Role,
		CredentialsJSON:     credentialsJSON,
	}

	// Use IAM auth type by default
	if opts.AuthType == "" || opts.AuthType == "iam" {
		return auth.GenerateGCPIAMJWT(ctx, opts)
	}

	// For GCE auth type, generate login data with identity token
	loginData, err := auth.GenerateGCPGCELoginData(ctx, opts)
	if err != nil {
		return "", err
	}

	// GCE auth returns the JWT in the login data
	jwt, ok := loginData["jwt"].(string)
	if !ok {
		return "", fmt.Errorf("GCE login data missing JWT")
	}

	return jwt, nil
}

// wasSealedReason inspects the existing condition set for a Ready
// condition that was previously set with a sealed/uninitialized reason.
// Returns true if the connection was last observed as sealed — used to
// drive the VaultUnsealed K8s event on the unseal moment.
//
// (Earlier comment said "Ready or Healthy" but the implementation only
// inspects Ready; there's no Healthy condition in this CRD, so the
// "or Healthy" was an aspirational doc bug. Code is correct as-is.)
//
// We use the condition's Reason rather than a dedicated status field
// because (a) Reason is already persisted, (b) it's the canonical way
// to express categorical state in k8s, and (c) avoids a CRD schema
// addition for what is essentially derived data.
//
// IMPROVEMENTS Missing Features §C.
func wasSealedReason(conds []vaultv1alpha1.Condition) bool {
	for i := range conds {
		c := &conds[i]
		if c.Type != vaultv1alpha1.ConditionTypeReady {
			continue
		}
		switch c.Reason {
		case vaultv1alpha1.ReasonVaultSealed, vaultv1alpha1.ReasonVaultNotInitialized:
			return true
		}
	}
	return false
}

// Ensure Handler implements FeatureHandler interface.
var _ base.FeatureHandler[*vaultv1alpha1.VaultConnection] = (*Handler)(nil)
