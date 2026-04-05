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
	"strings"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// VaultClientGetter retrieves a Vault client from cache.
// Simpler than VaultClientResolver — used during cleanup where full validation is unnecessary.
type VaultClientGetter func(connRef string) (*vault.Client, error)

// CleanupWorkflow encapsulates the shared cleanup orchestration for Vault resources.
type CleanupWorkflow struct {
	client         client.Client
	getVaultClient VaultClientGetter
	eventBus       *events.EventBus
	log            logr.Logger
}

// NewCleanupWorkflow creates a new CleanupWorkflow.
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
		if err != nil {
			log.Info("failed to get Vault client during deletion, continuing with finalizer removal")
		} else if vaultClient.IsAuthenticated() {
			// Step 5: Delete resource from Vault (best-effort)
			if err := ops.DeleteFromVault(ctx, vaultClient); err != nil {
				log.Error(err, "failed to delete "+label+" from Vault")
			} else {
				log.Info("deleted "+label+" from Vault", "resource", vaultResourceName)
			}

			// Step 6: Remove managed marker (best-effort)
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
