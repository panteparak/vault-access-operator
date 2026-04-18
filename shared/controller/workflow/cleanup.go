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

package workflow

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/cleanup"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// VaultClientGetter retrieves a Vault client from cache.
// Simpler than VaultClientResolver — used during cleanup where full validation is unnecessary.
type VaultClientGetter func(connRef string) (*vault.Client, error)

// CleanupQueuer is the narrow interface the workflow uses to persist failed
// deletes for later retry (IMPROVEMENTS §2). *cleanup.Queue satisfies this.
// Kept as an interface so unit tests can inject a fake without pulling in
// the ConfigMap-backed implementation.
type CleanupQueuer interface {
	Enqueue(ctx context.Context, item cleanup.Item) error
}

// CleanupWorkflow encapsulates the shared cleanup orchestration for Vault resources.
type CleanupWorkflow struct {
	client         client.Client
	getVaultClient VaultClientGetter
	eventBus       *events.EventBus
	queue          CleanupQueuer // optional — nil means "don't enqueue, same as pre-§2 behavior"
	log            logr.Logger
}

// NewCleanupWorkflow creates a new CleanupWorkflow without a retry queue.
// Prefer NewCleanupWorkflowWithQueue in production wiring.
func NewCleanupWorkflow(
	c client.Client,
	getter VaultClientGetter,
	bus *events.EventBus,
	log logr.Logger,
) *CleanupWorkflow {
	return &CleanupWorkflow{
		client:         c,
		getVaultClient: getter,
		eventBus:       bus,
		log:            log,
	}
}

// NewCleanupWorkflowWithQueue creates a CleanupWorkflow that persists failed
// Vault deletes to the retry queue (IMPROVEMENTS §2). Use this in production
// so that a Vault outage at deletion time doesn't leak the resource forever.
// Passing a nil queue is equivalent to NewCleanupWorkflow.
func NewCleanupWorkflowWithQueue(
	c client.Client,
	getter VaultClientGetter,
	bus *events.EventBus,
	queue CleanupQueuer,
	log logr.Logger,
) *CleanupWorkflow {
	return &CleanupWorkflow{
		client:         c,
		getVaultClient: getter,
		eventBus:       bus,
		queue:          queue,
		log:            log,
	}
}

// Execute runs the shared cleanup workflow for a Vault resource.
func (w *CleanupWorkflow) Execute(ctx context.Context, resource SyncableResource, ops ResourceOps) error {
	log := logr.FromContextOrDiscard(ctx)
	vaultResourceName := ops.VaultResourceName()
	label := strings.ToLower(resourceLabel(ops.ResourceKind()))

	// Step 1: Track deletion start time
	if resource.GetDeletionStartedAt() == nil {
		now := metav1.Now()
		resource.SetDeletionStartedAt(&now)
	}

	// Step 2: Update phase to Deleting with condition
	resource.SetPhase(vaultv1alpha1.PhaseDeleting)
	conds := conditions.Set(resource.GetConditions(), resource.GetGeneration(),
		vaultv1alpha1.ConditionTypeDeleting, metav1.ConditionTrue,
		vaultv1alpha1.ReasonDeletionInProgress, "Deletion in progress")
	resource.SetConditions(conds)

	// Step 3: Status update (non-fatal — informational only)
	if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
		log.V(1).Info("failed to update status to Deleting (ignoring)", "error", err)
	}

	// Step 4: Delete from Vault if deletion policy is Delete
	deletionPolicy := resource.GetDeletionPolicy()
	if deletionPolicy == "" {
		deletionPolicy = vaultv1alpha1.DeletionPolicyDelete // explicit default
	}
	if deletionPolicy == vaultv1alpha1.DeletionPolicyDelete {
		vaultClient, err := w.getVaultClient(resource.GetConnectionRef())
		switch {
		case err != nil:
			// IMPROVEMENTS §2: previously this path logged + proceeded with
			// finalizer removal, silently leaking the Vault resource. Enqueue
			// so the cleanup controller retries later when Vault is reachable.
			log.Info("failed to get Vault client during deletion — enqueuing for retry",
				"error", err, "resource", vaultResourceName)
			w.enqueueForRetry(ctx, resource, ops, err)
		case !vaultClient.IsAuthenticated():
			// Cached client exists but has no valid token — same fate: queue it.
			log.Info("cached Vault client is unauthenticated — enqueuing for retry",
				"resource", vaultResourceName)
			w.enqueueForRetry(ctx, resource, ops, errors.New("vault client unauthenticated"))
		default:
			// Step 5: Delete resource from Vault. Treat 404 as success —
			// the resource is already gone and retries would only generate noise.
			if err := ops.DeleteFromVault(ctx, vaultClient); err != nil {
				if isVaultNotFound(err) {
					log.V(1).Info("vault resource already absent (404 treated as success)",
						"resource", vaultResourceName)
				} else {
					log.Error(err, "failed to delete "+label+" from Vault — enqueuing for retry")
					w.enqueueForRetry(ctx, resource, ops, err)
				}
			} else {
				log.Info("deleted "+label+" from Vault", "resource", vaultResourceName)
			}

			// Step 6: Remove managed marker (best-effort, no enqueue — a stale
			// marker shows up in orphan detection rather than corrupting state).
			if err := ops.RemoveManaged(ctx, vaultClient); err != nil {
				log.V(1).Info("failed to remove managed marker (non-fatal)", "error", err)
			}
		}
	} else {
		log.Info("DeletionPolicy is Retain, keeping "+label+" in Vault", "resource", vaultResourceName)
	}

	// Step 7: Publish deletion event
	if w.eventBus != nil {
		ops.PublishDeleteEvent(ctx, w.eventBus)
	}

	log.Info(label+" cleanup completed", "resource", vaultResourceName)
	return nil
}

// enqueueForRetry persists a failed cleanup so the cleanup.Controller can
// retry against Vault later. Best-effort: if the queue itself fails (e.g.,
// API server unavailable), we log and carry on — better to lose an item
// than to block finalizer removal forever.
//
// The caller has already logged the underlying Vault error at Info or Error
// level; passing cause here is for correlating the queue item with the
// triggering condition in future log searches.
func (w *CleanupWorkflow) enqueueForRetry(
	ctx context.Context, resource SyncableResource, ops ResourceOps, cause error,
) {
	if w.queue == nil {
		// Pre-§2 behavior — no queue wired (e.g., unit tests). The finalizer
		// still gets removed by the base reconciler, so the resource leaks
		// silently. This is the bug §2 exists to fix; tests that exercise
		// the §2 wiring pass a queue.
		return
	}
	item := cleanup.Item{
		ID:             fmt.Sprintf("%s/%s", ops.ResourceKind(), ops.VaultResourceName()),
		ResourceType:   cleanupResourceType(ops.ResourceKind()),
		VaultName:      ops.VaultResourceName(),
		ConnectionName: resource.GetConnectionRef(),
		AuthPath:       ops.AuthPath(),
		K8sNamespace:   resource.GetNamespace(),
		K8sName:        resource.GetName(),
		LastError:      cause.Error(),
	}
	if err := w.queue.Enqueue(ctx, item); err != nil {
		// Not returning this error: finalizer removal must not block on a
		// queue-write hiccup. The item is lost but the orphan scanner will
		// eventually flag the leaked resource.
		logr.FromContextOrDiscard(ctx).Error(err, "failed to enqueue cleanup item for retry",
			"resource", item.VaultName)
	}
}

// cleanupResourceType maps a ResourceKind string (e.g. "VaultPolicy",
// "VaultClusterRole") to the cleanup.ResourceType enum. Defaults to the
// Role type if the kind contains "Role", else Policy — the only two kinds
// today that produce Vault writes.
func cleanupResourceType(kind string) cleanup.ResourceType {
	if strings.Contains(strings.ToLower(kind), "role") {
		return cleanup.ResourceTypeRole
	}
	return cleanup.ResourceTypePolicy
}

// isVaultNotFound detects a Vault 404 so we can treat "already gone" as
// success rather than requeuing indefinitely. The Vault SDK surfaces 404s
// as *api.ResponseError with StatusCode=404.
func isVaultNotFound(err error) bool {
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == 404
	}
	// Some operations wrap the raw error without a *ResponseError; fall back
	// to a string check as a belt-and-braces guard.
	return strings.Contains(strings.ToLower(err.Error()), "status 404")
}
