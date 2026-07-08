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

// Package orphan provides orphan detection for Vault resources managed by the operator.
package orphan

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

// DefaultScanInterval is the default interval between orphan detection scans.
const DefaultScanInterval = 1 * time.Hour

// Resource type constants for OrphanInfo.
const (
	ResourceTypePolicy = "policy"
	ResourceTypeRole   = "role"
)

// OrphanInfo contains information about an orphaned Vault resource.
type OrphanInfo struct {
	// VaultName is the name of the resource in Vault.
	VaultName string
	// ResourceType is "policy" or "role".
	ResourceType string
	// K8sResource is the K8s resource reference that should own this resource.
	K8sResource string
	// ConnectionName is the VaultConnection used.
	ConnectionName string
}

// Controller detects orphaned Vault resources that are no longer managed by K8s resources.
type Controller struct {
	k8sClient   client.Client
	clientCache *vault.ClientCache
	interval    time.Duration
	log         logr.Logger
	stopCh      chan struct{}
	stoppedCh   chan struct{}
	stopOnce    sync.Once
	// started flips to 1 on Start so Stop can short-circuit instead of
	// blocking on stoppedCh forever when Start was never called. Atomic
	// for happens-before correctness under -race. Mirrors the same
	// defense in pkg/cleanup/Controller.
	started atomic.Bool
}

// ControllerConfig contains configuration for the orphan detection controller.
type ControllerConfig struct {
	K8sClient   client.Client
	ClientCache *vault.ClientCache
	Interval    time.Duration
	Log         logr.Logger
}

// NewController creates a new orphan detection controller.
func NewController(cfg ControllerConfig) *Controller {
	interval := cfg.Interval
	if interval == 0 {
		interval = DefaultScanInterval
	}

	return &Controller{
		k8sClient:   cfg.K8sClient,
		clientCache: cfg.ClientCache,
		interval:    interval,
		log:         cfg.Log,
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
	}
}

// Start begins the orphan detection loop.
// This method blocks until Stop is called or the context is cancelled.
func (c *Controller) Start(ctx context.Context) error {
	c.log.Info("starting orphan detection controller", "interval", c.interval)

	c.started.Store(true)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	defer close(c.stoppedCh)

	// Initial scan
	c.detectOrphans(ctx)

	for {
		select {
		case <-ctx.Done():
			c.log.Info("orphan detection controller stopped due to context cancellation")
			return ctx.Err()
		case <-c.stopCh:
			c.log.Info("orphan detection controller stopped")
			return nil
		case <-ticker.C:
			c.detectOrphans(ctx)
		}
	}
}

// Stop signals the controller to stop.
// Safe to call multiple times. Safe to call even if Start was never
// invoked — earlier versions deadlocked on the stoppedCh receive
// because nothing would close it.
func (c *Controller) Stop() {
	c.stopOnce.Do(func() { close(c.stopCh) })
	if !c.started.Load() {
		// Nothing ever closed stoppedCh; don't block forever.
		return
	}
	<-c.stoppedCh
}

// detectOrphans scans for orphaned Vault resources across all VaultConnections.
func (c *Controller) detectOrphans(ctx context.Context) {
	c.log.V(1).Info("starting orphan detection scan")

	// Check if client cache is available
	if c.clientCache == nil {
		c.log.V(1).Info("no client cache available, skipping orphan scan")
		return
	}

	// Get all VaultConnections
	connections := c.clientCache.List()
	if len(connections) == 0 {
		c.log.V(1).Info("no vault connections in cache, skipping orphan scan")
		return
	}

	for _, connName := range connections {
		c.detectOrphansForConnection(ctx, connName)
	}
}

// detectOrphansForConnection detects orphans for a single VaultConnection.
func (c *Controller) detectOrphansForConnection(ctx context.Context, connName string) {
	vaultClient, err := c.clientCache.Get(connName)
	if err != nil {
		c.log.Error(err, "failed to get vault client", "connection", connName)
		return
	}

	// Detect orphaned policies
	orphanedPolicies := c.DetectOrphanedPolicies(ctx, vaultClient, connName)
	metrics.SetOrphanedResources(connName, ResourceTypePolicy, len(orphanedPolicies))
	if len(orphanedPolicies) > 0 {
		c.log.Info("found orphaned policies", "connection", connName, "count", len(orphanedPolicies))
		for _, orphan := range orphanedPolicies {
			c.log.Info("orphaned policy detected",
				"vaultName", orphan.VaultName,
				"k8sResource", orphan.K8sResource,
				"connection", connName)
		}
	}

	// Detect orphaned roles
	orphanedRoles := c.DetectOrphanedRoles(ctx, vaultClient, connName)
	metrics.SetOrphanedResources(connName, ResourceTypeRole, len(orphanedRoles))
	if len(orphanedRoles) > 0 {
		c.log.Info("found orphaned roles", "connection", connName, "count", len(orphanedRoles))
		for _, orphan := range orphanedRoles {
			c.log.Info("orphaned role detected",
				"vaultName", orphan.VaultName,
				"k8sResource", orphan.K8sResource,
				"connection", connName)
		}
	}
}

// DetectOrphanedPolicies finds policies whose in-band ownership header (ADR
// 0008) names THIS operator (same auth-mount identity) but whose owning K8s
// resource no longer exists. Foreign-owned and unmanaged policies are never
// flagged.
func (c *Controller) DetectOrphanedPolicies(
	ctx context.Context, vaultClient *vault.Client, connName string,
) []OrphanInfo {
	names, err := vaultClient.ListPolicies(ctx)
	if err != nil {
		c.log.Error(err, "failed to list policies", "connection", connName)
		return nil
	}

	var orphans []OrphanInfo
	for _, vaultName := range names {
		own, err := vaultClient.GetPolicyOwnership(ctx, vaultName)
		if err != nil {
			c.log.V(1).Info("failed to read policy ownership; skipping",
				"policy", vaultName, "error", err.Error())
			continue
		}
		if own == nil || own.AuthMount != vaultClient.AuthMount() {
			continue // unmanaged or another operator's — not ours to flag
		}
		if !c.k8sResourceExists(ctx, own.K8sResource, ResourceTypePolicy) {
			orphans = append(orphans, OrphanInfo{
				VaultName:      vaultName,
				ResourceType:   ResourceTypePolicy,
				K8sResource:    own.K8sResource,
				ConnectionName: connName,
			})
		}
	}
	return orphans
}

// DetectOrphanedRoles finds roles on THIS operator's own auth mount that no
// role CR derives to. Roles carry no in-band ownership record (ADR 0008);
// under the one-cluster-per-mount invariant every role on our mount belongs
// to this cluster, so a role with no matching CR is an orphan candidate. The
// owning CR is unknowable (no record), so K8sResource is left empty.
func (c *Controller) DetectOrphanedRoles(
	ctx context.Context, vaultClient *vault.Client, connName string,
) []OrphanInfo {
	mount := vaultClient.AuthMount()
	if mount == "" {
		// Static-token connection: no mount to scan, no identity to scope by.
		c.log.V(1).Info("skipping role orphan scan — connection has no auth mount",
			"connection", connName)
		return nil
	}

	roles, err := vaultClient.ListKubernetesAuthRoles(ctx, mount)
	if err != nil {
		c.log.Error(err, "failed to list roles", "connection", connName, "mount", mount)
		return nil
	}

	expected := c.expectedRoleNames(ctx, mount)
	if expected == nil {
		return nil // CR list failed — can't tell orphans apart, skip this pass
	}

	var orphans []OrphanInfo
	for _, vaultName := range roles {
		// Only operator-shaped names are orphan candidates (ADR 0010):
		// hand-created roles on the mount never carried the vao. marker,
		// so flagging them would be a false positive.
		if !strings.HasPrefix(vaultName, naming.Marker+".") {
			continue
		}
		if _, ok := expected[vaultName]; ok {
			continue
		}
		orphans = append(orphans, OrphanInfo{
			VaultName:      vaultName,
			ResourceType:   ResourceTypeRole,
			ConnectionName: connName,
		})
	}
	return orphans
}

// expectedRoleNames collects the RECORDED Vault role names (status,
// ADR 0010) this cluster's role CRs wrote on the given mount. The recorded
// name is what the sync actually wrote — deriving here would go stale when
// the naming config changes and mis-flag every managed role as an orphan.
// Roles carry no mount of their own — a role CR maps to the mount its
// referenced connection resolves to (VaultConnection.RoleMount), so two
// connections sharing one mount both contribute. Returns nil (distinct from
// empty) when a CR list fails, so the caller can skip the pass instead of
// flagging everything.
func (c *Controller) expectedRoleNames(ctx context.Context, mount string) map[string]struct{} {
	bareMount := vault.AuthMountName(mount)
	expected := map[string]struct{}{}

	var conns vaultv1alpha1.VaultConnectionList
	if err := c.k8sClient.List(ctx, &conns); err != nil {
		c.log.V(1).Info("failed to list VaultConnections for orphan scan", "error", err.Error())
		return nil
	}
	connsOnMount := map[string]struct{}{}
	for i := range conns.Items {
		if m, _, err := conns.Items[i].RoleMount(); err == nil && m == bareMount {
			connsOnMount[conns.Items[i].Name] = struct{}{}
		}
	}

	var roles vaultv1alpha1.VaultRoleList
	if err := c.k8sClient.List(ctx, &roles); err != nil {
		c.log.V(1).Info("failed to list VaultRoles for orphan scan", "error", err.Error())
		return nil
	}
	for i := range roles.Items {
		r := &roles.Items[i]
		if _, ok := connsOnMount[r.Spec.ConnectionRef]; !ok {
			continue
		}
		if r.Status.VaultRoleName == "" {
			continue // never synced — nothing written to Vault yet
		}
		expected[r.Status.VaultRoleName] = struct{}{}
	}

	var clusterRoles vaultv1alpha1.VaultClusterRoleList
	if err := c.k8sClient.List(ctx, &clusterRoles); err != nil {
		c.log.V(1).Info("failed to list VaultClusterRoles for orphan scan", "error", err.Error())
		return nil
	}
	for i := range clusterRoles.Items {
		r := &clusterRoles.Items[i]
		if _, ok := connsOnMount[r.Spec.ConnectionRef]; !ok {
			continue
		}
		if r.Status.VaultRoleName == "" {
			continue // never synced — nothing written to Vault yet
		}
		expected[r.Status.VaultRoleName] = struct{}{}
	}
	return expected
}

// k8sResourceExists checks if a K8s resource exists.
// The k8sResource format is "namespace/name" for namespaced resources or just "name" for cluster-scoped.
func (c *Controller) k8sResourceExists(ctx context.Context, k8sResource, resourceType string) bool {
	parts := strings.SplitN(k8sResource, "/", 2)

	var key types.NamespacedName
	var obj client.Object

	if len(parts) == 2 {
		// Namespaced resource: "namespace/name"
		key = types.NamespacedName{Namespace: parts[0], Name: parts[1]}
		if resourceType == ResourceTypePolicy {
			obj = &vaultv1alpha1.VaultPolicy{}
		} else {
			obj = &vaultv1alpha1.VaultRole{}
		}
	} else {
		// Cluster-scoped resource: just "name"
		key = types.NamespacedName{Name: parts[0]}
		if resourceType == ResourceTypePolicy {
			obj = &vaultv1alpha1.VaultClusterPolicy{}
		} else {
			obj = &vaultv1alpha1.VaultClusterRole{}
		}
	}

	err := c.k8sClient.Get(ctx, key, obj)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false
		}
		// On other errors, assume it exists to avoid false positives
		c.log.V(1).Info("error checking k8s resource existence", "resource", k8sResource, "error", err)
		return true
	}
	return true
}

// NeedsLeaderElection returns true as this controller should only run on the leader.
func (c *Controller) NeedsLeaderElection() bool {
	return true
}
