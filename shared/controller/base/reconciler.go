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

// Package base provides shared controller infrastructure using the Template Method pattern.
// This reduces code duplication across feature controllers by extracting common
// reconciliation logic into reusable components.
package base

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"
	"time"

	"github.com/go-logr/logr"
	oplogger "github.com/panteparak/vault-access-operator/pkg/logger"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReconcileTrackable is implemented by CRD types that want the reconcileID
// automatically persisted to their status for debugging.
type ReconcileTrackable interface {
	SetLastReconcileID(id string)
}

// FeatureHandler defines the interface that each feature's handler must implement.
// This is the "hook" in the Template Method pattern - the varying part that each
// feature provides.
type FeatureHandler[T client.Object] interface {
	// Sync synchronizes the resource state with the external system (e.g., Vault).
	// Called when the resource exists and is not being deleted.
	Sync(ctx context.Context, resource T) error

	// Cleanup removes the resource from the external system.
	// Called when the resource is being deleted (has deletion timestamp).
	Cleanup(ctx context.Context, resource T) error
}

// ReconcileResult wraps the result of a reconciliation with additional metadata.
type ReconcileResult struct {
	Result      ctrl.Result
	Error       error
	RequeueMsg  string
	RequeueTime time.Duration
}

// Event reasons for K8s events
const (
	// EventReasonSyncing indicates sync has started
	EventReasonSyncing = "Syncing"
	// EventReasonSynced indicates sync completed successfully
	EventReasonSynced = "Synced"
	// EventReasonSyncFailed indicates sync failed
	EventReasonSyncFailed = "SyncFailed"
	// EventReasonDeleting indicates cleanup has started
	EventReasonDeleting = "Deleting"
	// EventReasonDeleted indicates cleanup completed successfully
	EventReasonDeleted = "Deleted"
	// EventReasonDeleteFailed indicates cleanup failed
	EventReasonDeleteFailed = "DeleteFailed"
	// EventReasonWaitingForDependency indicates a dependency is not ready
	EventReasonWaitingForDependency = "WaitingForDependency"
	// EventReasonDriftDetected indicates drift was detected in Vault
	EventReasonDriftDetected = "DriftDetected"
	// EventReasonDriftCorrected indicates drift was corrected in Vault
	EventReasonDriftCorrected = "DriftCorrected"
	// EventReasonDeletionBlocked indicates deletion is blocked by dependents
	EventReasonDeletionBlocked = "DeletionBlocked"
	// EventReasonPolicyNotInVault indicates a referenced policy doesn't exist in Vault
	EventReasonPolicyNotInVault = "PolicyNotInVault"
	// EventReasonDeletionStuck indicates deletion has been pending too long
	EventReasonDeletionStuck = "DeletionStuck"
)

// BaseReconciler provides the template method for controller reconciliation.
// It handles common tasks like fetching resources, managing finalizers, and updating status.
// Feature-specific logic is delegated to the FeatureHandler.
type BaseReconciler[T client.Object] struct {
	Client    client.Client
	Scheme    *runtime.Scheme
	Logger    logr.Logger
	Finalizer *FinalizerManager
	Status    *StatusManager[T]
	Recorder  record.EventRecorder
}

// NewBaseReconciler creates a new BaseReconciler with the given dependencies.
// The recorder parameter is optional - if nil, events will not be emitted.
func NewBaseReconciler[T client.Object](
	c client.Client,
	scheme *runtime.Scheme,
	logger logr.Logger,
	finalizerName string,
	statusUpdater StatusUpdater[T],
	recorder record.EventRecorder,
) *BaseReconciler[T] {
	return &BaseReconciler[T]{
		Client:    c,
		Scheme:    scheme,
		Logger:    logger,
		Finalizer: NewFinalizerManager(c, finalizerName),
		Status:    NewStatusManager(c, statusUpdater),
		Recorder:  recorder,
	}
}

// recordEvent emits a Kubernetes event if the recorder is configured.
func (r *BaseReconciler[T]) recordEvent(obj client.Object, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(obj, eventType, reason, message)
	}
}

// Reconcile implements the template method pattern for reconciliation.
// It defines the skeleton algorithm and delegates varying parts to the FeatureHandler.
//
// The algorithm steps are:
// 1. Fetch the resource
// 2. Handle deletion if timestamp is set
// 3. Ensure finalizer is present
// 4. Delegate to feature-specific Sync
// 5. Update success status
func (r *BaseReconciler[T]) Reconcile(
	ctx context.Context,
	req ctrl.Request,
	handler FeatureHandler[T],
	newResource func() T,
) (result ctrl.Result, err error) {
	// IMPROVEMENTS Missing Features §K: record Reconcile wall-clock duration
	// in the `vault_access_operator_reconcile_duration_seconds` histogram.
	// The `kind` label uses the concrete resource type's GoString via
	// newResource(); in tests this may be a fake type, which is fine.
	start := time.Now()
	defer func() {
		kind := kindLabelForResource(newResource)
		metrics.ObserveReconcileDuration(kind, time.Since(start).Seconds(), err == nil)
	}()

	reconcileID := shortID()
	log := r.Logger.WithValues(
		"name", req.Name,
		"namespace", req.Namespace,
		oplogger.KeyReconcileID, reconcileID,
	)
	ctx = logr.NewContext(ctx, log)

	// Step 1: Fetch the resource
	resource := newResource()
	if err := r.Client.Get(ctx, req.NamespacedName, resource); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("resource not found, likely deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to fetch resource")
		return ctrl.Result{}, err
	}

	// Set reconcileID on the in-memory resource for kubectl debugging.
	// This is persisted when the feature handler calls Status().Update()
	// at the end of Sync/Cleanup — no separate status write needed here.
	if trackable, ok := any(resource).(ReconcileTrackable); ok {
		trackable.SetLastReconcileID(reconcileID)
	}

	// Step 2: Handle deletion
	if !resource.GetDeletionTimestamp().IsZero() {
		return r.handleDeletion(ctx, resource, handler, log)
	}

	// Step 3: Ensure finalizer
	if err := r.Finalizer.Ensure(ctx, resource); err != nil {
		log.Error(err, "failed to ensure finalizer")
		return r.Status.Error(ctx, resource, err)
	}

	// Step 4: Feature-specific sync
	r.recordEvent(resource, corev1.EventTypeNormal, EventReasonSyncing, "Syncing resource to Vault")
	if err := handler.Sync(ctx, resource); err != nil {
		log.Error(err, "sync failed")
		r.recordEvent(resource, corev1.EventTypeWarning, EventReasonSyncFailed, err.Error())
		return r.Status.Error(ctx, resource, err)
	}

	// Step 5: Clear the reconcile-now annotation (§H) if set — the trigger
	// is one-shot, so after a successful sync we remove it to prevent the
	// watch predicate from re-firing on the next reconciliation tick.
	// Failure here is non-fatal (the status update below will still
	// proceed); it just means the annotation lingers and a future watcher
	// still treats it as stale.
	if err := r.clearReconcileNowAnnotation(ctx, resource); err != nil {
		log.V(1).Info("failed to clear reconcile-now annotation (non-fatal)", "error", err.Error())
	}

	// Step 6: Update success status
	r.recordEvent(resource, corev1.EventTypeNormal, EventReasonSynced, "Successfully synced to Vault")
	return r.Status.Success(ctx, resource)
}

// clearReconcileNowAnnotation removes the reconcile-now annotation via a
// strategic merge patch if present. No-op if the annotation isn't set.
// Introduced for IMPROVEMENTS Missing Features §H.
func (r *BaseReconciler[T]) clearReconcileNowAnnotation(ctx context.Context, resource T) error {
	anns := resource.GetAnnotations()
	if _, ok := anns[reconcileNowAnnotation]; !ok {
		return nil
	}
	patch := client.RawPatch(
		types.MergePatchType,
		[]byte(fmt.Sprintf(`{"metadata":{"annotations":{%q:null}}}`, reconcileNowAnnotation)),
	)
	return r.Client.Patch(ctx, resource, patch)
}

// reconcileNowAnnotation mirrors api/v1alpha1.AnnotationReconcileNow but
// we define it locally to keep the base package dependency-free of the
// concrete API types. Changing the annotation name requires updating
// both locations (guarded by a tests that pin the exact string).
const reconcileNowAnnotation = "vault.platform.io/reconcile-now"

// handleDeletion manages the finalizer removal and cleanup process.
func (r *BaseReconciler[T]) handleDeletion(
	ctx context.Context,
	resource T,
	handler FeatureHandler[T],
	log logr.Logger,
) (ctrl.Result, error) {
	if !r.Finalizer.HasFinalizer(resource) {
		// No finalizer, nothing to do
		return ctrl.Result{}, nil
	}

	log.Info("handling deletion, running cleanup")
	r.recordEvent(resource, corev1.EventTypeNormal, EventReasonDeleting, "Deleting resource from Vault")

	// Run feature-specific cleanup
	if err := handler.Cleanup(ctx, resource); err != nil {
		log.Error(err, "cleanup failed")
		r.recordEvent(resource, corev1.EventTypeWarning, EventReasonDeleteFailed, err.Error())

		// Warn if deletion has been pending too long (stuck finalizer)
		if ts := resource.GetDeletionTimestamp(); ts != nil {
			if time.Since(ts.Time) > 5*time.Minute {
				r.recordEvent(resource, corev1.EventTypeWarning, EventReasonDeletionStuck,
					fmt.Sprintf("Deletion has been pending for %s", time.Since(ts.Time).Round(time.Second)))
			}
		}

		return r.Status.Error(ctx, resource, err)
	}

	// Remove finalizer after successful cleanup
	if err := r.Finalizer.Remove(ctx, resource); err != nil {
		log.Error(err, "failed to remove finalizer")
		return ctrl.Result{}, err
	}

	r.recordEvent(resource, corev1.EventTypeNormal, EventReasonDeleted, "Successfully deleted from Vault")
	log.Info("cleanup completed, finalizer removed")
	return ctrl.Result{}, nil
}

// shortID generates a short random hex string for reconcile correlation.
func shortID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// kindLabelForResource returns the `kind` label to use for the reconcile
// duration histogram. We derive it from the resource factory (not a live
// resource) so the label is available even when Reconcile errors before
// fetching. Returns just the type name (e.g. "VaultRole"), suitable as a
// Prometheus label value.
//
// In practice, freshly-constructed CR pointers don't have TypeMeta
// populated (controller-runtime doesn't auto-populate it on local
// constructions, only on Get from the API server). So
// `GetObjectKind().GroupVersionKind().Kind` typically returns the empty
// string here — we fall back to deriving the kind from the Go type name.
//
// The Go type name path uses reflect to strip the leading `*` and the
// package qualifier, leaving just the bare type name.
//
// Falling back to the empty string is a safe last resort: Prometheus
// treats it as a valid label.
func kindLabelForResource[T client.Object](newResource func() T) string {
	if newResource == nil {
		return ""
	}
	resource := newResource()
	if k := resource.GetObjectKind().GroupVersionKind().Kind; k != "" {
		return k
	}
	// Reflect on the pointer-target type to get the bare type name.
	// reflect.TypeOf(resource) returns *vaultv1alpha1.VaultRole;
	// .Elem() gives vaultv1alpha1.VaultRole; .Name() gives "VaultRole".
	t := reflect.TypeOf(resource)
	if t == nil {
		return ""
	}
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}
