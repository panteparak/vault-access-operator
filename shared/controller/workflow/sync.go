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
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/controller/driftmode"
	"github.com/panteparak/vault-access-operator/shared/controller/syncerror"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// VaultClientResolver resolves an authenticated Vault client for a connection.
// In production this calls vaultclient.Resolve; tests can inject a simpler resolver.
type VaultClientResolver func(ctx context.Context, connRef, resourceID string) (*vault.Client, error)

// SyncWorkflow encapsulates the shared sync orchestration for Vault resources.
// It implements the common reconciliation flow used by both policy and role handlers,
// calling ResourceOps at the appropriate points for resource-specific behavior.
type SyncWorkflow struct {
	client        client.Client
	resolveClient VaultClientResolver
	eventBus      *events.EventBus
	recorder      record.EventRecorder
	log           logr.Logger
}

// NewSyncWorkflow creates a new SyncWorkflow.
func NewSyncWorkflow(
	c client.Client,
	resolver VaultClientResolver,
	bus *events.EventBus,
	log logr.Logger,
	recorder record.EventRecorder,
) *SyncWorkflow {
	return &SyncWorkflow{
		client:        c,
		resolveClient: resolver,
		eventBus:      bus,
		recorder:      recorder,
		log:           log,
	}
}

// Execute runs the shared sync workflow for a Vault resource.
// nolint:gocyclo // Reconciliation flow naturally handles drift modes, conflicts, and bindings
func (w *SyncWorkflow) Execute(ctx context.Context, resource SyncableResource, ops ResourceOps) error {
	log := logr.FromContextOrDiscard(ctx)
	vaultResourceName := ops.VaultResourceName()
	kind := ops.ResourceKind()
	label := resourceLabel(kind)

	// Step 1: Update last attempt time
	now := metav1.Now()
	resource.SetLastAttemptAt(&now)

	// Step 2: Resolve effective drift mode
	effectiveDriftMode := driftmode.Resolve(ctx, w.client, resource.GetDriftMode(), resource.GetConnectionRef())
	resource.SetEffectiveDriftMode(effectiveDriftMode)

	// Step 3: Set phase to Syncing if not already active
	phase := resource.GetPhase()
	if phase != vaultv1alpha1.PhaseSyncing && phase != vaultv1alpha1.PhaseActive {
		resource.SetPhase(vaultv1alpha1.PhaseSyncing)
		if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
			return fmt.Errorf("failed to update status to Syncing: %w", err)
		}
	}

	// Step 4: Get Vault client
	vaultClient, err := w.resolveClient(ctx, resource.GetConnectionRef(), resource.GetK8sResourceIdentifier())
	if err != nil {
		return w.handleSyncError(ctx, resource, err)
	}

	// Step 5: Resource-specific validation
	if err := ops.Validate(); err != nil {
		return w.handleSyncError(ctx, resource, err)
	}

	// Step 6: Check for conflicts (with adoption support)
	if err := ops.CheckConflict(ctx, vaultClient); err != nil {
		return w.handleSyncError(ctx, resource, err)
	}

	// Step 7: Prepare content and calculate spec hash
	specHash, err := ops.PrepareContent(ctx, vaultClient)
	if err != nil {
		return w.handleSyncError(ctx, resource, err)
	}

	// Step 8: Drift detection
	driftDetected := false
	driftSummary := ""

	log.V(1).Info("drift detection check",
		"resource", vaultResourceName,
		"phase", resource.GetPhase(),
		"driftMode", effectiveDriftMode,
		"shouldDetect", driftmode.ShouldDetect(effectiveDriftMode))

	if resource.GetPhase() == vaultv1alpha1.PhaseActive && driftmode.ShouldDetect(effectiveDriftMode) {
		driftDetected, driftSummary = ops.DetectDrift(ctx, vaultClient)
		if driftDetected {
			log.Info("drift detected", "resource", vaultResourceName,
				"summary", driftSummary, "mode", effectiveDriftMode)
		}

		// Update drift status
		resource.SetDriftDetected(driftDetected)
		resource.SetDriftSummary(driftSummary)
		resource.SetLastDriftCheckAt(&now)

		// Set Drifted condition and emit events
		if driftDetected {
			w.setCondition(resource, vaultv1alpha1.ConditionTypeDrifted, metav1.ConditionTrue,
				vaultv1alpha1.ReasonDriftDetected, driftSummary)
			if w.recorder != nil {
				w.recorder.Event(resource.GetObject(), corev1.EventTypeWarning,
					"DriftDetected", "Drift detected: "+driftSummary)
			}
		} else {
			w.setCondition(resource, vaultv1alpha1.ConditionTypeDrifted, metav1.ConditionFalse,
				vaultv1alpha1.ReasonNoDrift, "No drift detected")
		}

		// Record drift metric
		metrics.SetDriftDetected(kind, resource.GetNamespace(), resource.GetName(), driftDetected)
	} else if driftmode.IsIgnore(effectiveDriftMode) {
		log.V(1).Info("drift detection disabled", "resource", vaultResourceName, "mode", effectiveDriftMode)
		resource.SetDriftDetected(false)
		resource.SetDriftSummary("")
	}

	// Step 9: Handle drift detect mode — report drift but don't correct
	if driftDetected && driftmode.IsDetect(effectiveDriftMode) {
		log.Info("drift detected (detect mode - not correcting)", "resource", vaultResourceName)
		resource.SetMessage("Drift detected: " + driftSummary)

		// Update status to show drift without correcting
		if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
			log.V(1).Info("failed to update drift status (non-fatal)", "error", err)
		}

		// Skip update if hash matches — only drift detected, no spec change
		if resource.GetLastAppliedHash() == specHash {
			return nil
		}
	}

	// Step 10: Safety check for drift correction
	if driftDetected && driftmode.IsCorrect(effectiveDriftMode) {
		annotations := resource.GetAnnotations()
		if annotations[vaultv1alpha1.AnnotationAllowDestructive] != vaultv1alpha1.AnnotationValueTrue {
			log.Info("drift correction blocked - missing allow-destructive annotation",
				"resource", vaultResourceName)

			resource.SetPhase(vaultv1alpha1.PhaseConflict)
			resource.SetDriftDetected(true)
			resource.SetDriftSummary(driftSummary)
			resource.SetLastDriftCheckAt(&now)
			resource.SetMessage("Drift detected but vault.platform.io/allow-destructive annotation required")
			w.setCondition(resource, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
				vaultv1alpha1.ReasonConflict, "Drift correction requires allow-destructive annotation")

			if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
				return fmt.Errorf("failed to update conflict status: %w", err)
			}

			metrics.IncrementDestructiveBlocked(kind, resource.GetNamespace())
			return nil
		}
		log.Info("correcting drift with destructive annotation", "resource", vaultResourceName)
	}

	// Step 11: Skip if unchanged — no spec change, already active, no drift
	if resource.GetLastAppliedHash() == specHash &&
		resource.GetPhase() == vaultv1alpha1.PhaseActive &&
		!driftDetected {
		log.V(1).Info("resource unchanged and no drift, skipping update", "resource", vaultResourceName)
		// Update managed marker for metadata-only changes (best-effort)
		if err := ops.MarkManaged(ctx, vaultClient); err != nil {
			log.V(1).Info("failed to update managed marker (non-fatal)", "error", err)
		}
		// Still update status to record the drift check
		if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
			log.V(1).Info("failed to update status (non-fatal)", "error", err)
		}
		return nil
	}

	// Step 12: Write to Vault
	if err := ops.WriteToVault(ctx, vaultClient); err != nil {
		return w.handleSyncError(ctx, resource,
			infraerrors.NewTransientError("write "+strings.ToLower(label), err))
	}

	// Step 13: Readback verification
	if err := ops.ReadbackVerify(ctx, vaultClient); err != nil {
		return w.handleSyncError(ctx, resource, err)
	}

	// Step 14: Mark managed (best-effort — log and continue)
	if err := ops.MarkManaged(ctx, vaultClient); err != nil {
		log.V(1).Info("failed to mark as managed (non-fatal)", "error", err)
	}

	// Step 15: Apply resource-specific bindings
	ops.ApplyBindings()

	// Step 16: Track drift correction
	if driftDetected {
		resource.SetDriftCorrectedAt(&now)
		metrics.IncrementDriftCorrected(kind, resource.GetNamespace())
	}

	// Step 17: Apply resource-specific active status fields
	ops.ApplyActiveStatus(specHash, &now)

	// Step 18: Set common status fields and conditions
	resource.SetPhase(vaultv1alpha1.PhaseActive)
	resource.SetManaged(true)
	resource.SetLastAppliedHash(specHash)
	resource.SetLastSyncedAt(&now)
	resource.SetRetryCount(0)
	resource.SetNextRetryAt(nil)
	resource.SetMessage("")
	resource.SetDriftDetected(false)
	resource.SetDriftSummary("")
	resource.SetLastDriftCheckAt(&now)
	w.setCondition(resource, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, label+" synced to Vault")
	w.setCondition(resource, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, label+" synced successfully")
	w.setCondition(resource, vaultv1alpha1.ConditionTypeDependencyReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonDependencyReady, "All dependencies ready")
	w.setCondition(resource, vaultv1alpha1.ConditionTypeDrifted, metav1.ConditionFalse,
		vaultv1alpha1.ReasonNoDrift, "No drift detected")

	if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
		return fmt.Errorf("failed to update status to Active: %w", err)
	}

	// Step 19: Emit K8s events
	if driftDetected && w.recorder != nil {
		w.recorder.Event(resource.GetObject(), corev1.EventTypeNormal,
			"DriftCorrected", "Drift was detected and corrected in Vault")
	}

	// Step 20: Publish event bus event
	if w.eventBus != nil {
		ops.PublishSyncEvent(ctx, w.eventBus)
	}

	log.Info(strings.ToLower(label)+" synced successfully", "resource", vaultResourceName)
	return nil
}

// handleSyncError classifies the error and updates status via syncerror.Handle.
func (w *SyncWorkflow) handleSyncError(ctx context.Context, resource SyncableResource, err error) error {
	return syncerror.Handle(ctx, w.client, w.log, resource, err, w.recorder)
}

// setCondition sets or updates a condition on the resource.
func (w *SyncWorkflow) setCondition(
	resource SyncableResource,
	condType string,
	status metav1.ConditionStatus,
	reason, message string,
) {
	resource.SetConditions(conditions.Set(
		resource.GetConditions(), resource.GetGeneration(),
		condType, status, reason, message,
	))
}

// resourceLabel extracts a human-readable label from the resource kind.
// "VaultPolicy" → "Policy", "VaultClusterRole" → "Role"
func resourceLabel(kind string) string {
	s := strings.TrimPrefix(kind, "Vault")
	s = strings.TrimPrefix(s, "Cluster")
	return s
}
