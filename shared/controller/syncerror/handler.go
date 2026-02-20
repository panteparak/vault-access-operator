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

// StatusTarget is the minimal interface for updating sync error status.
// Both PolicyAdapter and RoleAdapter satisfy this implicitly.
type StatusTarget interface {
	GetObject() client.Object
	GetGeneration() int64
	SetPhase(vaultv1alpha1.Phase)
	SetMessage(string)
	GetConditions() []vaultv1alpha1.Condition
	SetConditions([]vaultv1alpha1.Condition)
}

// Handle classifies the error, sets the appropriate phase and conditions on the target,
// and updates the status subresource. It returns the original error for upstream handling.
// An optional EventRecorder can be passed to emit K8s events for dependency errors.
func Handle(
	ctx context.Context, k8sClient client.Client, log logr.Logger,
	target StatusTarget, err error, recorder ...record.EventRecorder,
) error {
	gen := target.GetGeneration()

	// Determine phase and reason based on error type
	var reason string
	if infraerrors.IsConflictError(err) {
		target.SetPhase(vaultv1alpha1.PhaseConflict)
		reason = vaultv1alpha1.ReasonConflict
	} else if infraerrors.IsValidationError(err) {
		target.SetPhase(vaultv1alpha1.PhaseError)
		reason = vaultv1alpha1.ReasonValidationFailed
	} else if infraerrors.IsDependencyError(err) {
		target.SetPhase(vaultv1alpha1.PhaseError)
		reason = vaultv1alpha1.ReasonConnectionNotReady
	} else {
		target.SetPhase(vaultv1alpha1.PhaseError)
		reason = vaultv1alpha1.ReasonFailed
	}

	conds := target.GetConditions()
	conds = conditions.Set(conds, gen, vaultv1alpha1.ConditionTypeReady,
		metav1.ConditionFalse, reason, err.Error())
	conds = conditions.Set(conds, gen, vaultv1alpha1.ConditionTypeSynced,
		metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, err.Error())

	// Set DependencyReady condition for dependency errors
	var depErr *infraerrors.DependencyError
	if errors.As(err, &depErr) {
		msg := fmt.Sprintf("Blocked by %s/%s: %s", depErr.DependencyType, depErr.DependencyName, depErr.Reason)
		conds = conditions.Set(conds, gen, vaultv1alpha1.ConditionTypeDependencyReady,
			metav1.ConditionFalse, vaultv1alpha1.ReasonDependencyNotReady, msg)

		// Emit K8s event if recorder is available
		if len(recorder) > 0 && recorder[0] != nil {
			recorder[0].Event(target.GetObject(), corev1.EventTypeWarning,
				"WaitingForDependency", msg)
		}
	}

	target.SetConditions(conds)
	target.SetMessage(err.Error())

	if updateErr := k8sClient.Status().Update(ctx, target.GetObject()); updateErr != nil {
		log.Error(updateErr, "failed to update error status")
	}

	return err
}
