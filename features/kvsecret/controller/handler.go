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
	"fmt"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/controller/dryrun"
	"github.com/panteparak/vault-access-operator/shared/controller/vaultclient"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

// Handler implements the trimmed Sync/Cleanup logic for VaultKVSecret.
//
// Unlike the policy/role features it does NOT route through the shared
// SyncWorkflow: seeding is create-only-if-absent and deliberately abandons
// ownership of the secret's DATA after creation, so the workflow's
// drift-detect-and-correct machinery (built around "operator owns and
// reconciles the artifact to spec") does not apply. The handler resolves a
// Vault client, creates the path when absent, stamps ownership metadata, and on
// deletion removes the secret only if it is still untouched.
//
// Handler satisfies base.FeatureHandler[*VaultKVSecret] directly (Sync/Cleanup)
// and provides updateStatus as the BaseReconciler's StatusUpdater.
type Handler struct {
	client      client.Client
	clientCache *vault.ClientCache
	log         logr.Logger
	recorder    record.EventRecorder
}

// NewHandler creates a new VaultKVSecret handler.
func NewHandler(c client.Client, cache *vault.ClientCache, log logr.Logger, recorder record.EventRecorder) *Handler {
	return &Handler{client: c, clientCache: cache, log: log, recorder: recorder}
}

// Sync seeds the KV path when absent. It never overwrites an existing path
// (create-only-if-absent) and never reads secret data values — existence is
// determined via metadata, so the operator needs no `read` on `<mount>/data/*`.
func (h *Handler) Sync(ctx context.Context, kvs *vaultv1alpha1.VaultKVSecret) error {
	log := logr.FromContextOrDiscard(ctx)
	resourceID := kvs.Namespace + "/" + kvs.Name

	mount, rel, ok := vault.SplitKVv2Path(kvs.Spec.Path)
	if !ok {
		return infraerrors.NewValidationError("spec.path", kvs.Spec.Path,
			"must be a KV v2 data path containing a '/data/' segment")
	}
	kvs.Status.VaultPath = kvs.Spec.Path

	vc, err := vaultclient.Resolve(ctx, h.client, h.clientCache, kvs.Spec.ConnectionRef, resourceID)
	if err != nil {
		return err
	}

	// Dry-run: surface intent without writing to Vault.
	if dryrun.IsActive(kvs) {
		kvs.Status.Phase = vaultv1alpha1.PhaseActive
		kvs.Status.Managed = true
		kvs.Status.Message = fmt.Sprintf("dry-run: would seed %s if absent", kvs.Spec.Path)
		h.setCondition(kvs, vaultv1alpha1.ConditionTypeDryRun, metav1.ConditionTrue,
			vaultv1alpha1.ReasonDryRunSkipped, kvs.Status.Message)
		return nil
	}
	// Annotation removed since a prior dry-run: reflect that it's off now.
	h.setCondition(kvs, vaultv1alpha1.ConditionTypeDryRun, metav1.ConditionFalse,
		vaultv1alpha1.ReasonSucceeded, "dry-run not active")

	created, version, err := vc.CreateKVSecretIfAbsent(ctx, mount, rel, kvs.Spec.Data)
	if err != nil {
		return infraerrors.NewTransientError("seed KV secret", err)
	}

	if created {
		own := vault.KVOwnership{
			K8sResource: resourceID,
			AuthMount:   vc.AuthMount(),
			Cluster:     naming.Cluster(),
		}
		if err := vc.StampKVOwnership(ctx, mount, rel, own); err != nil {
			return infraerrors.NewTransientError("stamp KV ownership", err)
		}
		kvs.Status.Seeded = true
		kvs.Status.SeededVersion = version
		kvs.Status.Message = fmt.Sprintf("seeded empty secret at %s (version %d)", kvs.Spec.Path, version)
		log.Info("seeded KV secret", "path", kvs.Spec.Path, "version", version)
	} else {
		kvs.Status.Seeded = false
		kvs.Status.SeededVersion = 0
		kvs.Status.Message = fmt.Sprintf("path %s already exists; left untouched (create-only)", kvs.Spec.Path)
		log.V(1).Info("KV path already present; skipping seed", "path", kvs.Spec.Path)
	}

	now := metav1.Now()
	kvs.Status.Phase = vaultv1alpha1.PhaseActive
	kvs.Status.Managed = true
	kvs.Status.Binding = vaultv1alpha1.VaultResourceBinding{
		VaultPath:         kvs.Spec.Path,
		VaultResourceName: rel,
		BoundAt:           &now,
		BindingVerified:   true,
		LastVerifiedAt:    &now,
	}
	return nil
}

// Cleanup deletes the seeded secret only if it is still operator-owned AND
// unmodified since seeding (delete-if-untouched). A secret that has been written
// to since seeding, is foreign-owned, or whose DeletionPolicy is Retain is left
// in place — the operator never destroys real data.
func (h *Handler) Cleanup(ctx context.Context, kvs *vaultv1alpha1.VaultKVSecret) error {
	log := logr.FromContextOrDiscard(ctx)
	resourceID := kvs.Namespace + "/" + kvs.Name

	if kvs.Spec.DeletionPolicy == vaultv1alpha1.DeletionPolicyRetain {
		log.V(1).Info("DeletionPolicy=Retain; leaving seeded secret in place", "path", kvs.Spec.Path)
		return nil
	}
	if dryrun.IsActive(kvs) {
		log.V(1).Info("dry-run: skipping delete-if-untouched", "path", kvs.Spec.Path)
		return nil
	}
	// Only a secret the operator actually seeded is eligible for deletion.
	if !kvs.Status.Seeded {
		log.V(1).Info("not operator-seeded; nothing to delete", "path", kvs.Spec.Path)
		return nil
	}

	mount, rel, ok := vault.SplitKVv2Path(kvs.Spec.Path)
	if !ok {
		return nil // unparseable path: nothing we can safely delete
	}

	vc, err := vaultclient.Resolve(ctx, h.client, h.clientCache, kvs.Spec.ConnectionRef, resourceID)
	if err != nil {
		return err
	}

	md, err := vc.ReadKVMetadata(ctx, mount, rel)
	if err != nil {
		return infraerrors.NewTransientError("read KV metadata for cleanup", err)
	}
	own, owned := vault.KVOwnedBy(md)
	switch {
	case md == nil:
		log.V(1).Info("seeded secret already gone", "path", kvs.Spec.Path)
		return nil
	case !owned || !own.SameOwner(vc.AuthMount(), resourceID):
		// Identity-aware (ADR 0008): a colliding path seeded by another
		// operator instance (or another CR) is never ours to delete, even
		// though it carries the same managed-by sentinel.
		log.Info("retaining KV secret: not owned by this resource",
			"path", kvs.Spec.Path, "owner", own.String())
		return nil
	case md.CurrentVersion != kvs.Status.SeededVersion:
		log.Info("retaining KV secret: written since seeding",
			"path", kvs.Spec.Path, "seededVersion", kvs.Status.SeededVersion, "currentVersion", md.CurrentVersion)
		return nil
	}

	if err := vc.DeleteKVSecret(ctx, mount, rel); err != nil {
		return infraerrors.NewTransientError("delete KV secret", err)
	}
	log.Info("deleted untouched seeded KV secret", "path", kvs.Spec.Path)
	return nil
}

// updateStatus is the BaseReconciler's StatusUpdater. It is called with err=nil
// after a successful Sync (persisting the status Sync computed) and with err!=nil
// after a failed Sync/Cleanup.
func (h *Handler) updateStatus(ctx context.Context, kvs *vaultv1alpha1.VaultKVSecret, reconcileErr error) error {
	gen := kvs.Generation
	now := metav1.Now()
	kvs.Status.LastAttemptAt = &now

	if reconcileErr != nil {
		kvs.Status.Phase = vaultv1alpha1.PhaseError
		kvs.Status.Message = reconcileErr.Error()
		reason := reasonForError(reconcileErr)
		kvs.Status.Conditions = conditions.Set(kvs.Status.Conditions, gen,
			vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, reason, reconcileErr.Error())
		kvs.Status.Conditions = conditions.Set(kvs.Status.Conditions, gen,
			vaultv1alpha1.ConditionTypeSynced, metav1.ConditionFalse, reason, reconcileErr.Error())
	} else {
		kvs.Status.LastSyncedAt = &now
		kvs.Status.Conditions = conditions.Set(kvs.Status.Conditions, gen,
			vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, kvs.Status.Message)
		kvs.Status.Conditions = conditions.Set(kvs.Status.Conditions, gen,
			vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, kvs.Status.Message)
	}
	return h.client.Status().Update(ctx, kvs)
}

// setCondition is a thin wrapper over conditions.Set bound to the resource's
// current generation.
func (h *Handler) setCondition(
	kvs *vaultv1alpha1.VaultKVSecret, condType string, status metav1.ConditionStatus, reason, msg string,
) {
	kvs.Status.Conditions = conditions.Set(kvs.Status.Conditions, kvs.Generation, condType, status, reason, msg)
}

// reasonForError maps an error to a status condition reason.
func reasonForError(err error) string {
	switch {
	case infraerrors.IsDependencyError(err):
		return vaultv1alpha1.ReasonConnectionNotReady
	case infraerrors.IsValidationError(err):
		return vaultv1alpha1.ReasonValidationFailed
	default:
		return vaultv1alpha1.ReasonFailed
	}
}
