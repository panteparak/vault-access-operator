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

package cleanup

import (
	"context"
	"time"

	"github.com/go-logr/logr"

	"github.com/panteparak/vault-access-operator/pkg/metrics"
)

// DefaultRetryInterval is the default interval between cleanup retry cycles.
const DefaultRetryInterval = 5 * time.Minute

// DefaultMaxAttempts is the default maximum number of retry attempts.
const DefaultMaxAttempts = 10

// VaultClient defines the Vault operations needed for cleanup.
type VaultClient interface {
	DeletePolicy(ctx context.Context, name string) error
	DeleteKubernetesAuthRole(ctx context.Context, authPath, roleName string) error
}

// ClientCache defines the client cache operations needed for cleanup.
type ClientCache interface {
	Get(name string) (VaultClient, error)
}

// Controller processes the cleanup queue and retries failed deletions.
type Controller struct {
	queue       *Queue
	clientCache ClientCache
	interval    time.Duration
	maxAttempts int
	log         logr.Logger
	stopCh      chan struct{}
	stoppedCh   chan struct{}
}

// ControllerConfig contains configuration for the cleanup controller.
type ControllerConfig struct {
	Queue       *Queue
	ClientCache ClientCache
	Interval    time.Duration
	MaxAttempts int
	Log         logr.Logger
}

// NewController creates a new cleanup controller.
func NewController(cfg ControllerConfig) *Controller {
	interval := cfg.Interval
	if interval == 0 {
		interval = DefaultRetryInterval
	}

	maxAttempts := cfg.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = DefaultMaxAttempts
	}

	return &Controller{
		queue:       cfg.Queue,
		clientCache: cfg.ClientCache,
		interval:    interval,
		maxAttempts: maxAttempts,
		log:         cfg.Log,
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
	}
}

// Start begins processing the cleanup queue.
// This method blocks until Stop is called or the context is cancelled.
func (c *Controller) Start(ctx context.Context) error {
	c.log.Info("starting cleanup controller", "interval", c.interval, "maxAttempts", c.maxAttempts)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	defer close(c.stoppedCh)

	// Initial processing
	c.processQueue(ctx)

	for {
		select {
		case <-ctx.Done():
			c.log.Info("cleanup controller stopped due to context cancellation")
			return ctx.Err()
		case <-c.stopCh:
			c.log.Info("cleanup controller stopped")
			return nil
		case <-ticker.C:
			c.processQueue(ctx)
		}
	}
}

// Stop signals the controller to stop processing.
func (c *Controller) Stop() {
	close(c.stopCh)
	<-c.stoppedCh
}

// processQueue processes all items in the cleanup queue.
func (c *Controller) processQueue(ctx context.Context) {
	items, err := c.queue.List(ctx)
	if err != nil {
		c.log.Error(err, "failed to list cleanup queue items")
		return
	}

	// Update queue size metric
	metrics.SetCleanupQueueSize(len(items))

	if len(items) == 0 {
		c.log.V(1).Info("cleanup queue is empty")
		return
	}

	c.log.Info("processing cleanup queue", "itemCount", len(items))

	for _, item := range items {
		// Check if we've exceeded max attempts
		if item.Attempts >= c.maxAttempts {
			c.log.Info("max retry attempts exceeded, removing from queue",
				"resourceType", item.ResourceType,
				"vaultName", item.VaultName,
				"attempts", item.Attempts)
			if err := c.queue.Dequeue(ctx, item.ID); err != nil {
				c.log.Error(err, "failed to dequeue item after max attempts")
			}
			continue
		}

		// Try to process the item
		if err := c.processItem(ctx, item); err != nil {
			c.log.Error(err, "cleanup retry failed",
				"resourceType", item.ResourceType,
				"vaultName", item.VaultName,
				"attempt", item.Attempts+1)

			// Update the item with the new attempt
			item.Attempts++
			item.LastAttemptAt = time.Now()
			item.LastError = err.Error()
			if err := c.queue.Enqueue(ctx, item); err != nil {
				c.log.Error(err, "failed to update item after retry failure")
			}

			metrics.IncrementCleanupRetry(string(item.ResourceType), false)
		} else {
			c.log.Info("cleanup retry succeeded",
				"resourceType", item.ResourceType,
				"vaultName", item.VaultName)

			// Remove from queue
			if err := c.queue.Dequeue(ctx, item.ID); err != nil {
				c.log.Error(err, "failed to dequeue item after successful cleanup")
			}

			metrics.IncrementCleanupRetry(string(item.ResourceType), true)
		}
	}

	// Update queue size metric after processing
	newSize, _ := c.queue.Size(ctx)
	metrics.SetCleanupQueueSize(newSize)
}

// processItem attempts to clean up a single item.
func (c *Controller) processItem(ctx context.Context, item Item) error {
	// Get Vault client from cache
	vaultClient, err := c.clientCache.Get(item.ConnectionName)
	if err != nil {
		return err
	}

	// Perform the cleanup based on resource type
	switch item.ResourceType {
	case ResourceTypePolicy:
		return vaultClient.DeletePolicy(ctx, item.VaultName)
	case ResourceTypeRole:
		return vaultClient.DeleteKubernetesAuthRole(ctx, item.AuthPath, item.VaultName)
	default:
		c.log.Error(nil, "unknown resource type in cleanup queue",
			"resourceType", item.ResourceType,
			"id", item.ID)
		// Remove unknown items from queue
		return nil
	}
}

// NeedsLeaderElection returns true as this controller should only run on the leader.
func (c *Controller) NeedsLeaderElection() bool {
	return true
}
