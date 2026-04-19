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
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/controller/driftmode"
	"github.com/panteparak/vault-access-operator/shared/controller/dryrun"
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

type syncExecutionState struct {
	now                metav1.Time
	effectiveDriftMode vaultv1alpha1.DriftMode
	vaultResourceName  string
	kind               string
	label              string
	driftDetected      bool
	driftSummary       string
	specHash           string
	vaultClient        *vault.Client
	log                logr.Logger
	// usedAllowDestructive marks that the workflow consumed the
	// `vault.platform.io/allow-destructive` annotation in this reconcile
	// to authorize a drift-correction write. After the sync completes
	// successfully the annotation is auto-cleared so the user must
	// re-arm it for any future correction. Mirrors the one-shot
	// semantics of `vault.platform.io/reconcile-now`.
	usedAllowDestructive bool
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
	state, err := w.initializeSync(ctx, resource, ops)
	if err != nil {
		return err
	}

	if err := ops.Validate(); err != nil {
		return w.handleSyncError(ctx, resource, err)
	}

	if err := ops.CheckConflict(ctx, state.vaultClient); err != nil {
		return w.handleSyncError(ctx, resource, err)
	}

	state.specHash, err = ops.PrepareContent(ctx, state.vaultClient)
	if err != nil {
		return w.handleSyncError(ctx, resource, err)
	}

	w.handleDriftDetection(ctx, resource, ops, state)

	shouldReturn, err := w.handleDriftModes(ctx, resource, state)
	if err != nil || shouldReturn {
		return err
	}

	if shouldReturn := w.handleUnchangedResource(ctx, resource, ops, state); shouldReturn {
		return nil
	}

	if err := ops.WriteToVault(ctx, state.vaultClient); err != nil {
		return w.handleSyncError(ctx, resource,
			infraerrors.NewTransientError("write "+strings.ToLower(state.label), err))
	}

	if err := ops.ReadbackVerify(ctx, state.vaultClient); err != nil {
		return w.handleSyncError(ctx, resource, err)
	}

	return w.finalizeSuccessfulSync(ctx, resource, ops, state)
}

func (w *SyncWorkflow) initializeSync(
	ctx context.Context,
	resource SyncableResource,
	ops ResourceOps,
) (*syncExecutionState, error) {
	state := &syncExecutionState{
		now:                metav1.Now(),
		effectiveDriftMode: driftmode.Resolve(ctx, w.client, resource.GetDriftMode(), resource.GetConnectionRef()),
		vaultResourceName:  ops.VaultResourceName(),
		kind:               ops.ResourceKind(),
		label:              resourceLabel(ops.ResourceKind()),
		log:                logr.FromContextOrDiscard(ctx),
	}

	resource.SetLastAttemptAt(&state.now)
	resource.SetEffectiveDriftMode(state.effectiveDriftMode)

	phase := resource.GetPhase()
	if phase != vaultv1alpha1.PhaseSyncing && phase != vaultv1alpha1.PhaseActive {
		resource.SetPhase(vaultv1alpha1.PhaseSyncing)
		// Note: Status().Update errors are returned directly (not via handleSyncError)
		// because handleSyncError itself calls Status().Update, which would loop.
		if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
			return nil, fmt.Errorf("failed to update status to Syncing: %w", err)
		}
	}

	vaultClient, err := w.resolveClient(ctx, resource.GetConnectionRef(), resource.GetK8sResourceIdentifier())
	if err != nil {
		return nil, w.handleSyncError(ctx, resource, err)
	}
	state.vaultClient = vaultClient

	return state, nil
}

func (w *SyncWorkflow) handleDriftDetection(
	ctx context.Context,
	resource SyncableResource,
	ops ResourceOps,
	state *syncExecutionState,
) {
	state.log.V(1).Info("drift detection check",
		"resource", state.vaultResourceName,
		"phase", resource.GetPhase(),
		"driftMode", state.effectiveDriftMode,
		"shouldDetect", driftmode.ShouldDetect(state.effectiveDriftMode))

	if resource.GetPhase() == vaultv1alpha1.PhaseActive && driftmode.ShouldDetect(state.effectiveDriftMode) {
		state.driftDetected, state.driftSummary = ops.DetectDrift(ctx, state.vaultClient)
		if state.driftDetected {
			state.log.Info("drift detected", "resource", state.vaultResourceName,
				"summary", state.driftSummary, "mode", state.effectiveDriftMode)
		}

		resource.SetDriftDetected(state.driftDetected)
		resource.SetDriftSummary(state.driftSummary)
		resource.SetLastDriftCheckAt(&state.now)

		if state.driftDetected {
			w.setCondition(resource, vaultv1alpha1.ConditionTypeDrifted, metav1.ConditionTrue,
				vaultv1alpha1.ReasonDriftDetected, state.driftSummary)
			if w.recorder != nil {
				w.recorder.Event(resource.GetObject(), corev1.EventTypeWarning,
					"DriftDetected", "Drift detected: "+state.driftSummary)
			}
		} else {
			w.setCondition(resource, vaultv1alpha1.ConditionTypeDrifted, metav1.ConditionFalse,
				vaultv1alpha1.ReasonNoDrift, "No drift detected")
		}

		metrics.SetDriftDetected(state.kind, resource.GetNamespace(), resource.GetName(), state.driftDetected)
		return
	}

	if driftmode.IsIgnore(state.effectiveDriftMode) {
		state.log.V(1).Info("drift detection disabled", "resource", state.vaultResourceName, "mode", state.effectiveDriftMode)
		resource.SetDriftDetected(false)
		resource.SetDriftSummary("")
	}
}

func (w *SyncWorkflow) handleDriftModes(
	ctx context.Context,
	resource SyncableResource,
	state *syncExecutionState,
) (bool, error) {
	if state.driftDetected && driftmode.IsDetect(state.effectiveDriftMode) {
		state.log.Info("drift detected (detect mode - not correcting)", "resource", state.vaultResourceName)
		resource.SetMessage("Drift detected: " + state.driftSummary)

		if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
			state.log.V(1).Info("failed to update drift status (non-fatal)", "error", err)
		}

		if resource.GetLastAppliedHash() == state.specHash {
			return true, nil
		}
		// Spec changed while in detect mode — the write is a user-initiated update,
		// not a drift correction. Allow it to proceed.
		state.log.Info("spec changed in detect mode, proceeding with update",
			"resource", state.vaultResourceName)
	}

	if !state.driftDetected || !driftmode.IsCorrect(state.effectiveDriftMode) {
		return false, nil
	}

	annotations := resource.GetAnnotations()
	if annotations[vaultv1alpha1.AnnotationAllowDestructive] == vaultv1alpha1.AnnotationValueTrue {
		state.log.Info("correcting drift with destructive annotation", "resource", state.vaultResourceName)
		// Mark that we consumed the annotation so finalizeSuccessfulSync
		// can clear it after the write succeeds — one-shot semantics so
		// the user must re-arm for any future correction.
		state.usedAllowDestructive = true
		return false, nil
	}

	state.log.Info("drift correction blocked - missing allow-destructive annotation",
		"resource", state.vaultResourceName)

	resource.SetPhase(vaultv1alpha1.PhaseConflict)
	resource.SetDriftDetected(true)
	resource.SetDriftSummary(state.driftSummary)
	resource.SetLastDriftCheckAt(&state.now)
	resource.SetMessage("Drift detected but vault.platform.io/allow-destructive annotation required")
	w.setCondition(resource, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
		vaultv1alpha1.ReasonConflict, "Drift correction requires allow-destructive annotation")

	if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
		return false, fmt.Errorf("failed to update conflict status: %w", err)
	}

	metrics.IncrementDestructiveBlocked(state.kind, resource.GetNamespace())
	return true, nil
}

func (w *SyncWorkflow) handleUnchangedResource(
	ctx context.Context,
	resource SyncableResource,
	ops ResourceOps,
	state *syncExecutionState,
) bool {
	if resource.GetLastAppliedHash() != state.specHash ||
		resource.GetPhase() != vaultv1alpha1.PhaseActive ||
		state.driftDetected {
		return false
	}

	state.log.V(1).Info("resource unchanged and no drift, skipping update", "resource", state.vaultResourceName)
	if err := ops.MarkManaged(ctx, state.vaultClient); err != nil {
		state.log.V(1).Info("failed to update managed marker (non-fatal)", "error", err)
	}
	if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
		state.log.V(1).Info("failed to update status (non-fatal)", "error", err)
	}

	return true
}

func (w *SyncWorkflow) finalizeSuccessfulSync(
	ctx context.Context,
	resource SyncableResource,
	ops ResourceOps,
	state *syncExecutionState,
) error {
	if err := ops.MarkManaged(ctx, state.vaultClient); err != nil {
		state.log.V(1).Info("failed to mark as managed (non-fatal)", "error", err)
	}

	ops.ApplyBindings()

	if state.driftDetected {
		resource.SetDriftCorrectedAt(&state.now)
		metrics.IncrementDriftCorrected(state.kind, resource.GetNamespace())
	}

	ops.ApplyActiveStatus(state.specHash, &state.now)

	resource.SetPhase(vaultv1alpha1.PhaseActive)
	resource.SetManaged(true)
	resource.SetLastAppliedHash(state.specHash)
	resource.SetLastSyncedAt(&state.now)
	resource.SetRetryCount(0)
	resource.SetNextRetryAt(nil)
	resource.SetMessage("")
	resource.SetDriftDetected(false)
	resource.SetDriftSummary("")
	resource.SetLastDriftCheckAt(&state.now)
	w.setCondition(resource, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, state.label+" synced to Vault")
	w.setCondition(resource, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, state.label+" synced successfully")
	w.setCondition(resource, vaultv1alpha1.ConditionTypeDependencyReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonDependencyReady, "All dependencies ready")
	w.setCondition(resource, vaultv1alpha1.ConditionTypeDrifted, metav1.ConditionFalse,
		vaultv1alpha1.ReasonNoDrift, "No drift detected")

	// IMPROVEMENTS Missing Features §I: surface dry-run state. The ops
	// layer skipped Vault writes if the resource carries the dry-run
	// annotation; reflect that intent in conditions so dashboards and
	// `kubectl describe` make it obvious the policy/role isn't actually
	// pushed to Vault.
	if isDryRunResource(resource) {
		w.setCondition(resource, vaultv1alpha1.ConditionTypeDryRun, metav1.ConditionTrue,
			vaultv1alpha1.ReasonDryRunSkipped,
			"Vault writes skipped (vault.platform.io/dry-run=true) — remove the annotation to apply")
	} else {
		w.setCondition(resource, vaultv1alpha1.ConditionTypeDryRun, metav1.ConditionFalse,
			vaultv1alpha1.ReasonSucceeded, "")
	}

	if err := w.client.Status().Update(ctx, resource.GetObject()); err != nil {
		return fmt.Errorf("failed to update status to Active: %w", err)
	}

	if state.driftDetected && w.recorder != nil {
		w.recorder.Event(resource.GetObject(), corev1.EventTypeNormal,
			"DriftCorrected", "Drift was detected and corrected in Vault")
	}

	if w.eventBus != nil {
		ops.PublishSyncEvent(ctx, w.eventBus)
	}

	// Auto-clear the allow-destructive annotation if it was consumed in
	// this reconcile. One-shot semantics: the user must re-arm the
	// annotation for any future drift correction. Without this, a single
	// "I accept the risk" approval would become a standing permission
	// that auto-corrects every subsequent drift event silently.
	//
	// Best-effort: a patch failure here is logged but doesn't fail the
	// sync (the destructive write already succeeded). The next reconcile
	// can re-attempt the clear.
	if state.usedAllowDestructive {
		if err := w.clearAllowDestructiveAnnotation(ctx, resource); err != nil {
			state.log.V(1).Info("failed to clear allow-destructive annotation (non-fatal)",
				"resource", state.vaultResourceName, "error", err.Error())
		}
	}

	state.log.Info(strings.ToLower(state.label)+" synced successfully", "resource", state.vaultResourceName)
	return nil
}

// clearAllowDestructiveAnnotation patches off the
// `vault.platform.io/allow-destructive` annotation via a strategic merge
// patch. No-op if the annotation isn't set. Mirrors the reconcile-now
// auto-clear in BaseReconciler so safety annotations behave consistently
// (one-shot, must be re-armed for each use).
func (w *SyncWorkflow) clearAllowDestructiveAnnotation(
	ctx context.Context, resource SyncableResource,
) error {
	obj := resource.GetObject()
	if obj == nil {
		return nil
	}
	if _, ok := obj.GetAnnotations()[vaultv1alpha1.AnnotationAllowDestructive]; !ok {
		return nil
	}
	patch := client.RawPatch(
		ktypes.MergePatchType,
		[]byte(fmt.Sprintf(`{"metadata":{"annotations":{%q:null}}}`,
			vaultv1alpha1.AnnotationAllowDestructive)),
	)
	return w.client.Patch(ctx, obj, patch)
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

// isDryRunResource reports whether the resource carries the
// vault.platform.io/dry-run=true annotation. The PolicyOps and RoleOps
// guards skip Vault writes when this is set; the workflow uses it to
// surface ConditionTypeDryRun. IMPROVEMENTS Missing Features §I.
//
// Delegates to the shared dryrun package so all three call sites
// (policy ops, role ops, sync workflow) agree on the strict-equality
// semantics. nil resource → false (safe default).
func isDryRunResource(resource SyncableResource) bool {
	if resource == nil {
		return false
	}
	return dryrun.IsActive(resource.GetObject())
}
