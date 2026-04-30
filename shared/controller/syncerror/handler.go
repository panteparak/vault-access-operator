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

// Package syncerror provides shared error handling for Vault resource sync operations.
// It classifies errors and updates CRD status conditions accordingly.
package syncerror

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// MaxConditionMessageLen caps each condition Message field. Vault SDK
// errors that wrap a 500-response body verbatim can reach tens of KB;
// each Status update writes 3 messages (Ready, Synced, optional
// DependencyReady) plus Status.Message. Without this cap, a single
// pathological error could push the per-object size past etcd's
// 1.5MB limit and silently fail the Status().Update — leaving the
// CR stale with no explanation. 4KB per field is the K8s convention
// for condition messages and well under any realistic per-object
// budget even when accumulated.
const MaxConditionMessageLen = 4096

// truncateMsg shortens long error strings while preserving the prefix
// and a tail marker so the operator can see "this got cut off".
func truncateMsg(s string) string {
	if len(s) <= MaxConditionMessageLen {
		return s
	}
	const tail = " …[truncated]"
	keep := MaxConditionMessageLen - len(tail)
	return s[:keep] + tail
}

// StatusTarget is the minimal interface for updating sync error status.
// Both PolicyAdapter and RoleAdapter satisfy this implicitly.
type StatusTarget interface {
	GetObject() client.Object
	GetGeneration() int64
	SetPhase(vaultv1alpha1.Phase)
	SetMessage(string)
	GetConditions() []vaultv1alpha1.Condition
	SetConditions([]vaultv1alpha1.Condition)
	// RetryCount tracking — incremented on every error so operators see
	// `kubectl get vp -o jsonpath='{..status.retryCount}'` advance.
	// Earlier this was a dead field: the workflow's success path reset it
	// to 0 but no error path ever incremented it, so the status always
	// showed 0 even after dozens of consecutive failures.
	GetRetryCount() int
	SetRetryCount(count int)
}

// Handle classifies the error, sets the appropriate phase and conditions on the target,
// and updates the status subresource. It returns the original error for upstream handling.
// An optional EventRecorder can be passed to emit K8s events for dependency errors.
func Handle(
	ctx context.Context, k8sClient client.Client, log logr.Logger,
	target StatusTarget, err error, recorder ...record.EventRecorder,
) error {
	gen := target.GetGeneration()

	phase, reason := classifyError(err)
	target.SetPhase(phase)

	errMsg := truncateMsg(err.Error())
	conds := target.GetConditions()
	conds = conditions.Set(conds, gen, vaultv1alpha1.ConditionTypeReady,
		metav1.ConditionFalse, reason, errMsg)
	conds = conditions.Set(conds, gen, vaultv1alpha1.ConditionTypeSynced,
		metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, errMsg)

	// Set DependencyReady condition for dependency errors
	var depErr *infraerrors.DependencyError
	if errors.As(err, &depErr) {
		msg := truncateMsg(fmt.Sprintf("Blocked by %s/%s: %s",
			depErr.DependencyType, depErr.DependencyName, depErr.Reason))
		conds = conditions.Set(conds, gen, vaultv1alpha1.ConditionTypeDependencyReady,
			metav1.ConditionFalse, vaultv1alpha1.ReasonDependencyNotReady, msg)

		// Emit K8s event if recorder is available
		if len(recorder) > 0 && recorder[0] != nil {
			recorder[0].Event(target.GetObject(), corev1.EventTypeWarning,
				"WaitingForDependency", msg)
		}
	}

	target.SetConditions(conds)
	target.SetMessage(errMsg)
	// Advance the retry counter so operators can see "this has failed N
	// times in a row" without reading logs. The workflow's success path
	// resets to 0; here we only ever increment.
	target.SetRetryCount(target.GetRetryCount() + 1)

	if updateErr := k8sClient.Status().Update(ctx, target.GetObject()); updateErr != nil {
		log.Error(updateErr, "failed to update error status")
	}

	return err
}

// classifyError maps an error to the (Phase, Ready-condition reason) pair
// the workflow uses to surface failures to the user. Conflict errors set
// PhaseConflict so users see a distinct state from generic Error; all
// other classified errors land in PhaseError with a more specific reason.
//
// IMPROVEMENTS §29 + Missing Features §C: NotFoundError, ConnectionError,
// and VaultSealedError get distinct reasons so operators can grep status
// conditions for a specific failure class without parsing Message strings.
func classifyError(err error) (vaultv1alpha1.Phase, string) {
	switch {
	case infraerrors.IsConflictError(err):
		return vaultv1alpha1.PhaseConflict, vaultv1alpha1.ReasonConflict
	case infraerrors.IsValidationError(err):
		return vaultv1alpha1.PhaseError, vaultv1alpha1.ReasonValidationFailed
	case infraerrors.IsDependencyError(err):
		return vaultv1alpha1.PhaseError, vaultv1alpha1.ReasonConnectionNotReady
	case infraerrors.IsNotFoundError(err):
		// Referenced K8s resource (Secret / ServiceAccount / other CR) not
		// found. Distinct from ReasonPolicyNotFound which is specific to
		// Vault policy references.
		return vaultv1alpha1.PhaseError, vaultv1alpha1.ReasonResourceNotFound
	case infraerrors.IsConnectionError(err):
		// Transport-layer failure reaching Vault (TLS, DNS, TCP, refused).
		// Users often want to alert distinctly on this — it's network/infra,
		// not policy/role-specific.
		return vaultv1alpha1.PhaseError, vaultv1alpha1.ReasonNetworkError
	case infraerrors.IsVaultSealedError(err):
		// Vault is reachable but in a recoverable sealed/uninitialized
		// state. Distinct reason so alerts can suppress (no operator action
		// needed beyond unseal).
		var sealedErr *infraerrors.VaultSealedError
		if errors.As(err, &sealedErr) && !sealedErr.Initialized {
			return vaultv1alpha1.PhaseError, vaultv1alpha1.ReasonVaultNotInitialized
		}
		return vaultv1alpha1.PhaseError, vaultv1alpha1.ReasonVaultSealed
	default:
		return vaultv1alpha1.PhaseError, vaultv1alpha1.ReasonFailed
	}
}
