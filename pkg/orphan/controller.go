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
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
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
func (c *Controller) Stop() {
	close(c.stopCh)
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
	orphanedPolicies := c.detectOrphanedPolicies(ctx, vaultClient, connName)
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
	orphanedRoles := c.detectOrphanedRoles(ctx, vaultClient, connName)
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

// detectOrphanedPolicies finds policies in Vault that are marked as managed but
// whose corresponding K8s resource no longer exists.
func (c *Controller) detectOrphanedPolicies(
	ctx context.Context, vaultClient *vault.Client, connName string,
) []OrphanInfo {
	managed, err := vaultClient.ListManagedPolicies(ctx)
	if err != nil {
		c.log.Error(err, "failed to list managed policies", "connection", connName)
		return nil
	}

	var orphans []OrphanInfo
	for vaultName, metadata := range managed {
		if !c.k8sResourceExists(ctx, metadata.K8sResource, ResourceTypePolicy) {
			orphans = append(orphans, OrphanInfo{
				VaultName:      vaultName,
				ResourceType:   ResourceTypePolicy,
				K8sResource:    metadata.K8sResource,
				ConnectionName: connName,
			})
		}
	}
	return orphans
}

// detectOrphanedRoles finds roles in Vault that are marked as managed but
// whose corresponding K8s resource no longer exists.
func (c *Controller) detectOrphanedRoles(
	ctx context.Context, vaultClient *vault.Client, connName string,
) []OrphanInfo {
	managed, err := vaultClient.ListManagedRoles(ctx)
	if err != nil {
		c.log.Error(err, "failed to list managed roles", "connection", connName)
		return nil
	}

	var orphans []OrphanInfo
	for vaultName, metadata := range managed {
		if !c.k8sResourceExists(ctx, metadata.K8sResource, ResourceTypeRole) {
			orphans = append(orphans, OrphanInfo{
				VaultName:      vaultName,
				ResourceType:   ResourceTypeRole,
				K8sResource:    metadata.K8sResource,
				ConnectionName: connName,
			})
		}
	}
	return orphans
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
