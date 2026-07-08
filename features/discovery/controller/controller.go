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

// Package controller provides the discovery controller implementation.
package controller

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	oplogger "github.com/panteparak/vault-access-operator/pkg/logger"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/base"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

const (
	// DefaultScanInterval is the default interval between discovery scans
	DefaultScanInterval = time.Hour

	// discoveryPlaceholder aliases the canonical
	// vaultv1alpha1.DiscoveryPlaceholderValue (which is also referenced by
	// the role/cluster-role webhooks) so the discovery feature can use a
	// short local name. Both must stay in sync — the alias is enforced
	// at compile time.
	discoveryPlaceholder = vaultv1alpha1.DiscoveryPlaceholderValue
)

// DefaultMinScanInterval is the minimum scan interval used when a
// ReconcilerConfig leaves MinScanInterval unset. Can still be overridden per
// call via the OPERATOR_MIN_SCAN_INTERVAL env var (see
// resolveMinScanInterval). Kept as a package-level const for tests that
// reference "the default minimum" without constructing a full config.
const DefaultMinScanInterval = time.Minute * 5

// MinScanInterval mirrors DefaultMinScanInterval for backward compatibility
// with test code that still references this package variable.
// IMPROVEMENTS §23 lifted the primary configuration path into
// ReconcilerConfig.MinScanInterval; this var is now a read-only default
// populated at init so existing callers (and the test helper that mutated
// it) see no change.
//
//nolint:gochecknoglobals // retained for backward compat during §23 transition
var MinScanInterval = DefaultMinScanInterval

func init() {
	// Use the shared helper so a misconfigured OPERATOR_MIN_SCAN_INTERVAL
	// produces a stderr warning at startup instead of silently falling
	// back to the default — matching the behavior of the REQUEUE_*
	// env vars.
	MinScanInterval = base.ParseIntervalEnv(
		"OPERATOR_MIN_SCAN_INTERVAL", DefaultMinScanInterval, os.Stderr)
}

// Reconciler reconciles VaultConnection resources for discovery
type Reconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	ClientCache     *vault.ClientCache
	Log             logr.Logger
	Recorder        record.EventRecorder
	minScanInterval time.Duration
}

// ReconcilerConfig holds configuration for creating a Reconciler
type ReconcilerConfig struct {
	Client      client.Client
	Scheme      *runtime.Scheme
	ClientCache *vault.ClientCache
	Log         logr.Logger
	Recorder    record.EventRecorder

	// MinScanInterval (IMPROVEMENTS §23) lets tests override the minimum
	// scan interval without mutating a package-level global. Zero uses the
	// package-level MinScanInterval value (which is itself resolved from
	// DefaultMinScanInterval + OPERATOR_MIN_SCAN_INTERVAL env var at init).
	MinScanInterval time.Duration
}

// NewReconciler creates a new discovery Reconciler
func NewReconciler(cfg ReconcilerConfig) *Reconciler {
	minInterval := cfg.MinScanInterval
	if minInterval <= 0 {
		minInterval = MinScanInterval
	}
	return &Reconciler{
		minScanInterval: minInterval,
		Client:          cfg.Client,
		Scheme:          cfg.Scheme,
		ClientCache:     cfg.ClientCache,
		Log:             cfg.Log.WithName("discovery-controller"),
		Recorder:        cfg.Recorder,
	}
}

// Reconcile handles discovery for a VaultConnection.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Context logger carries controller-runtime's per-reconcile reconcileID;
	// the struct logger r.Log is kept for non-reconcile paths only.
	log := logf.FromContext(ctx).WithValues(oplogger.KeyVaultConnection, req.Name)

	var conn vaultv1alpha1.VaultConnection
	if err := r.Get(ctx, req.NamespacedName, &conn); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if conn.Spec.Discovery == nil || !conn.Spec.Discovery.Enabled {
		log.V(2).Info("discovery not enabled for connection")
		return ctrl.Result{}, nil
	}

	// Check if it's time to scan. Floor honors the per-reconciler config
	// (IMPROVEMENTS §23) which falls back to the package-level
	// MinScanInterval when unset.
	scanInterval := ParseInterval(conn.Spec.Discovery.Interval)
	if scanInterval < r.minScanInterval {
		scanInterval = r.minScanInterval
	}
	if waitFor, due := timeUntilNextScan(&conn, scanInterval); !due {
		log.V(2).Info("skipping scan, not yet due", "nextScanIn", waitFor)
		return ctrl.Result{RequeueAfter: waitFor}, nil
	}

	vaultClient, err := r.ClientCache.Get(conn.Name)
	if err != nil {
		log.Error(err, "failed to get Vault client")
		return ctrl.Result{RequeueAfter: scanInterval}, nil
	}
	log = log.WithValues(oplogger.KeyAuthPath, vault.NormalizeAuthPath(vaultClient.AuthMount()))

	log.Info("starting discovery scan")
	result := r.runScan(ctx, &conn, vaultClient, log)

	if err := r.persistScanResult(ctx, req.Name, result); err != nil {
		log.Error(err, "failed to update VaultConnection status")
		// Don't return the error: the controller would double-requeue it.
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	r.emitDiscoveryEvent(&conn, result)
	r.maybeAutoCreateCRs(ctx, &conn, result, log)

	log.Info("discovery scan completed",
		"unmanagedPolicies", len(result.UnmanagedPolicies),
		"unmanagedRoles", len(result.UnmanagedRoles))
	return ctrl.Result{RequeueAfter: scanInterval}, nil
}

// timeUntilNextScan reports whether the connection is due for another scan.
// Returns (0, true) when due now; otherwise (remaining, false) where
// `remaining` is how long the caller should requeue for.
func timeUntilNextScan(conn *vaultv1alpha1.VaultConnection, interval time.Duration) (time.Duration, bool) {
	if conn.Status.DiscoveryStatus == nil || conn.Status.DiscoveryStatus.LastScanAt == nil {
		return 0, true
	}
	elapsed := time.Since(conn.Status.DiscoveryStatus.LastScanAt.Time)
	if elapsed >= interval {
		return 0, true
	}
	return interval - elapsed, false
}

// runScan invokes the scanner against Vault and emits Prometheus metrics.
// The role scan targets the connection's resolved role mount (defaults
// override or login mount); a connection with no role-capable mount still
// scans policies but skips roles.
func (r *Reconciler) runScan(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection,
	vaultClient *vault.Client, log logr.Logger,
) *ScanResult {
	authPath := ""
	if mount, _, err := conn.RoleMount(); err != nil {
		log.Info("connection has no role-capable mount, scanning policies only",
			"reason", err.Error())
	} else {
		authPath = vault.NormalizeAuthPath(mount)
	}
	scanner := NewScanner(vaultClient, conn.Spec.Discovery, authPath,
		r.managedRoleNames(ctx, authPath, log), log)
	result := scanner.Scan(ctx)
	scanner.UpdateMetrics(conn.Name, result)
	return result
}

// managedRoleNames derives the set of Vault role names owned by this
// cluster's role CRs on the scanned auth mount. Roles carry no in-band
// ownership record (ADR 0008), so the CR set is the ownership source for
// discovery. Roles carry no mount either — the connection is the sole
// source — so a role CR counts when its referenced connection resolves to
// the scanned mount (two connections sharing one mount both count; a naive
// connectionRef match would mis-flag the second connection's roles as
// unmanaged). A list failure yields an empty set — every role then surfaces
// as unmanaged, which is safe (discovery never mutates Vault).
func (r *Reconciler) managedRoleNames(
	ctx context.Context, authPath string, log logr.Logger,
) map[string]struct{} {
	managed := map[string]struct{}{}
	connsOnMount := r.connectionsOnMount(ctx, vault.AuthMountName(authPath), log)

	var roles vaultv1alpha1.VaultRoleList
	if err := r.List(ctx, &roles); err != nil {
		log.V(1).Info("failed to list VaultRoles for discovery ownership", "error", err.Error())
	} else {
		for i := range roles.Items {
			role := &roles.Items[i]
			if _, ok := connsOnMount[role.Spec.ConnectionRef]; !ok {
				continue
			}
			managed[naming.Vault(role.Namespace+"-"+role.Name)] = struct{}{}
		}
	}

	var clusterRoles vaultv1alpha1.VaultClusterRoleList
	if err := r.List(ctx, &clusterRoles); err != nil {
		log.V(1).Info("failed to list VaultClusterRoles for discovery ownership", "error", err.Error())
	} else {
		for i := range clusterRoles.Items {
			role := &clusterRoles.Items[i]
			if _, ok := connsOnMount[role.Spec.ConnectionRef]; !ok {
				continue
			}
			managed[naming.Vault(role.Name)] = struct{}{}
		}
	}
	return managed
}

// connectionsOnMount returns the names of the VaultConnections whose
// resolved role mount (VaultConnection.RoleMount) equals the given bare
// mount name.
func (r *Reconciler) connectionsOnMount(
	ctx context.Context, mount string, log logr.Logger,
) map[string]struct{} {
	set := map[string]struct{}{}
	var conns vaultv1alpha1.VaultConnectionList
	if err := r.List(ctx, &conns); err != nil {
		log.V(1).Info("failed to list VaultConnections for discovery ownership", "error", err.Error())
		return set
	}
	for i := range conns.Items {
		if m, _, err := conns.Items[i].RoleMount(); err == nil && m == mount {
			set[conns.Items[i].Name] = struct{}{}
		}
	}
	return set
}

// persistScanResult updates DiscoveryStatus with a retry loop to handle
// concurrent modifications from the connection reconciler.
func (r *Reconciler) persistScanResult(ctx context.Context, name string, result *ScanResult) error {
	return r.updateDiscoveryStatus(ctx, name, metav1.Now(), result)
}

// emitDiscoveryEvent posts a normal-type event whenever the scan found
// any unmanaged Vault resources, giving operators a visible signal.
func (r *Reconciler) emitDiscoveryEvent(conn *vaultv1alpha1.VaultConnection, result *ScanResult) {
	if len(result.DiscoveredResources) == 0 {
		return
	}
	r.Recorder.Eventf(conn, corev1.EventTypeNormal, "DiscoveryScanComplete",
		"Found %d unmanaged policies and %d unmanaged roles",
		len(result.UnmanagedPolicies), len(result.UnmanagedRoles))
}

// maybeAutoCreateCRs runs auto-creation only when the user opted in via
// AutoCreateCRs and at least one discovered resource exists. Failures are
// surfaced as a warning event but do not abort the reconcile.
func (r *Reconciler) maybeAutoCreateCRs(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection,
	result *ScanResult, log logr.Logger,
) {
	if !conn.Spec.Discovery.AutoCreateCRs || len(result.DiscoveredResources) == 0 {
		return
	}
	if err := r.autoCreateCRs(ctx, conn, result); err != nil {
		log.Error(err, "failed to auto-create CRs")
		r.Recorder.Eventf(conn, corev1.EventTypeWarning, "AutoCreateFailed",
			"Failed to auto-create CRs: %v", err)
	}
}

// autoCreateCRs creates K8s resources for discovered Vault resources
func (r *Reconciler) autoCreateCRs(ctx context.Context, conn *vaultv1alpha1.VaultConnection, result *ScanResult) error {
	if conn.Spec.Discovery.TargetNamespace == "" {
		return fmt.Errorf("targetNamespace is required when autoCreateCRs is enabled")
	}

	targetNS := conn.Spec.Discovery.TargetNamespace
	log := r.Log.WithValues("targetNamespace", targetNS)

	for _, discovered := range result.DiscoveredResources {
		switch discovered.Type {
		case "policy":
			if err := r.createPolicyCR(ctx, conn, targetNS, discovered); err != nil {
				log.Error(err, "failed to create VaultPolicy", "name", discovered.Name)
				continue
			}
			log.Info("created VaultPolicy for discovered resource", "name", discovered.Name)

		case "role":
			if err := r.createRoleCR(ctx, conn, targetNS, discovered); err != nil {
				log.Error(err, "failed to create VaultRole", "name", discovered.Name)
				continue
			}
			log.Info("created VaultRole for discovered resource", "name", discovered.Name)
		}
	}

	return nil
}

// createPolicyCR creates a VaultPolicy CR for a discovered policy
func (r *Reconciler) createPolicyCR(
	ctx context.Context,
	conn *vaultv1alpha1.VaultConnection,
	namespace string,
	discovered vaultv1alpha1.DiscoveredResource,
) error {
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      discovered.SuggestedCRName,
			Namespace: namespace,
			Annotations: map[string]string{
				vaultv1alpha1.AnnotationAdopt:            vaultv1alpha1.AnnotationValueTrue,
				vaultv1alpha1.AnnotationDiscovered:       discovered.DiscoveredAt.Format(time.RFC3339),
				vaultv1alpha1.AnnotationDiscoveredFrom:   conn.Name,
				vaultv1alpha1.AnnotationDiscoveryPending: vaultv1alpha1.AnnotationValueTrue,
			},
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  conn.Name,
			ConflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
			DriftMode:      vaultv1alpha1.DriftModeDetect,
			// Placeholder rule satisfies MinItems=1 validation.
			// Users should replace this with the actual policy rules.
			// The discovery-pending annotation prevents the operator from
			// overwriting the adopted Vault policy with this placeholder.
			Rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/placeholder",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
					Description:  "Placeholder rule - replace with actual policy rules from Vault",
				},
			},
		},
	}

	if err := r.Create(ctx, policy); err != nil {
		// AlreadyExists is the steady-state on every scan after the first
		// create — the placeholder CR is already there waiting for user
		// adoption. Treating it as success keeps the per-scan log clean
		// and prevents the spurious AutoCreateFailed warning event.
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("failed to create VaultPolicy: %w", err)
	}

	return nil
}

// createRoleCR creates a VaultRole CR for a discovered role
func (r *Reconciler) createRoleCR(
	ctx context.Context,
	conn *vaultv1alpha1.VaultConnection,
	namespace string,
	discovered vaultv1alpha1.DiscoveredResource,
) error {
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      discovered.SuggestedCRName,
			Namespace: namespace,
			Annotations: map[string]string{
				vaultv1alpha1.AnnotationAdopt:          vaultv1alpha1.AnnotationValueTrue,
				vaultv1alpha1.AnnotationDiscovered:     discovered.DiscoveredAt.Format(time.RFC3339),
				vaultv1alpha1.AnnotationDiscoveredFrom: conn.Name,
				// discovery-pending blocks RoleOps.WriteToVault from overwriting
				// the adopted Vault role with the placeholder spec below.
				// Users MUST remove this annotation after replacing the placeholders
				// with their real serviceAccounts and policies.
				vaultv1alpha1.AnnotationDiscoveryPending: vaultv1alpha1.AnnotationValueTrue,
			},
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:  conn.Name,
			ConflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
			DriftMode:      vaultv1alpha1.DriftModeDetect,
			// Placeholder values satisfy MinItems=1 on ServiceAccounts + Policies
			// so the K8s API server accepts the CR. The discovery-pending annotation
			// ensures these are never written to Vault; the user replaces them with
			// the real spec after reviewing the adopted Vault role.
			ServiceAccounts: []string{discoveryPlaceholder},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultClusterPolicy", Name: discoveryPlaceholder},
			},
		},
	}

	if err := r.Create(ctx, role); err != nil {
		// AlreadyExists = previous scan already created this placeholder.
		// Skip silently rather than emit a Warning AutoCreateFailed event
		// every scan interval (typically 5min) for every previously-seen role.
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("failed to create VaultRole: %w", err)
	}

	return nil
}

// MaxDiscoveredResourcesInStatus caps how many DiscoveredResource entries
// the controller will write to a single VaultConnection status (IMPROVEMENTS §5).
// The CRD's `+kubebuilder:validation:MaxItems=500` schema marker enforces this
// at the API server, so writes that exceed it would be rejected with
// "Too many: N: must have at most 500 items" — looping the reconciler forever.
// We pre-truncate here so the user gets a clean Truncated condition instead.
const MaxDiscoveredResourcesInStatus = 500

// updateDiscoveryStatus updates the discovery status using a server-side
// merge patch (IMPROVEMENTS §9). Previously this used Update inside
// retry.RetryOnConflict because the connection controller also writes to
// VaultConnection.Status — both writers using full Update produced
// optimistic-concurrency conflicts. With MergeFrom, the patch only carries
// the DiscoveryStatus subset of fields and tolerates concurrent changes to
// the connection-controller-owned fields (Phase, AuthStatus, Health).
//
// retry.RetryOnConflict is preserved as a belt-and-braces guard for the
// rare case where the resource is mid-deletion or the API server still
// rejects a stale patch.
func (r *Reconciler) updateDiscoveryStatus(
	ctx context.Context,
	connectionName string,
	scanTime metav1.Time,
	result *ScanResult,
) error {
	// IMPROVEMENTS §5: cap the slice before persisting. We track how many we
	// dropped so the user can see it via the DiscoveryResultsTruncated condition.
	totalDiscovered := len(result.DiscoveredResources)
	persistedResources := result.DiscoveredResources
	truncatedCount := 0
	if totalDiscovered > MaxDiscoveredResourcesInStatus {
		persistedResources = result.DiscoveredResources[:MaxDiscoveredResourcesInStatus]
		truncatedCount = totalDiscovered - MaxDiscoveredResourcesInStatus
	}

	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// Re-fetch the VaultConnection to get the latest version
		var conn vaultv1alpha1.VaultConnection
		if err := r.Get(ctx, types.NamespacedName{Name: connectionName}, &conn); err != nil {
			if apierrors.IsNotFound(err) {
				return nil // Connection was deleted, nothing to update
			}
			return err
		}

		// Capture the pre-mutation snapshot so MergeFrom can compute the
		// minimal field-level patch that touches ONLY the discovery-owned
		// status subset. Anything we don't change here stays untouched on
		// the server even if the connection controller wrote to it
		// concurrently.
		original := conn.DeepCopy()

		// Initialize discovery status if needed
		if conn.Status.DiscoveryStatus == nil {
			conn.Status.DiscoveryStatus = &vaultv1alpha1.DiscoveryStatus{}
		}

		// Update discovery status fields
		conn.Status.DiscoveryStatus.LastScanAt = &scanTime
		conn.Status.DiscoveryStatus.UnmanagedPolicies = len(result.UnmanagedPolicies)
		conn.Status.DiscoveryStatus.UnmanagedRoles = len(result.UnmanagedRoles)
		conn.Status.DiscoveryStatus.DiscoveredResources = persistedResources

		// Surface the truncation as a condition so users can tighten their
		// discovery patterns rather than wonder why the count doesn't match.
		setDiscoveryTruncatedCondition(&conn, truncatedCount, totalDiscovered)

		return r.Status().Patch(ctx, &conn, client.MergeFrom(original))
	})
}

// setDiscoveryTruncatedCondition adds, updates, or removes the
// DiscoveryResultsTruncated condition based on whether truncation happened.
// Idempotent: if the previous condition matches the desired state, no change
// is made (controller-runtime conditions library handles LastTransitionTime).
func setDiscoveryTruncatedCondition(conn *vaultv1alpha1.VaultConnection, truncated, total int) {
	const condType = "DiscoveryResultsTruncated"
	if truncated > 0 {
		msg := fmt.Sprintf(
			"%d of %d discovered resources omitted from status (cap=%d). "+
				"Tighten spec.discovery.{policy,role}Patterns to reduce.",
			truncated, total, MaxDiscoveredResourcesInStatus)
		conn.Status.Conditions = conditions.Set(
			conn.Status.Conditions, conn.Generation,
			condType, metav1.ConditionTrue,
			"Capped", msg,
		)
		return
	}
	// No truncation this scan — clear the condition to False so a previously-set
	// True doesn't linger after the user fixes their patterns.
	conn.Status.Conditions = conditions.Set(
		conn.Status.Conditions, conn.Generation,
		condType, metav1.ConditionFalse,
		"WithinCap",
		fmt.Sprintf("All %d discovered resources persisted (cap=%d).", total, MaxDiscoveredResourcesInStatus),
	)
}

// SetupWithManager sets up the controller with the Manager.
// Uses GenerationChangedPredicate to avoid reconciling on status-only updates
// from the connection controller's health checks.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultConnection{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("discovery").
		Complete(r)
}
