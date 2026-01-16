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
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/shared/controller/base"
)

// PolicyReconciler reconciles VaultPolicy resources using the BaseReconciler pattern.
type PolicyReconciler struct {
	base    *base.BaseReconciler[*vaultv1alpha1.VaultPolicy]
	handler *Handler
}

// NewPolicyReconciler creates a new VaultPolicy Reconciler.
func NewPolicyReconciler(
	c client.Client,
	scheme *runtime.Scheme,
	handler *Handler,
	log logr.Logger,
) *PolicyReconciler {
	// Create base reconciler
	baseReconciler := base.NewBaseReconciler[*vaultv1alpha1.VaultPolicy](
		c,
		scheme,
		log.WithName("vaultpolicy"),
		vaultv1alpha1.FinalizerName,
		nil, // Status is updated in the handler
	)

	// Configure requeue intervals
	baseReconciler.Status.
		WithRequeueOnSuccess(5 * time.Minute). // Periodic re-sync
		WithRequeueOnError(30 * time.Second)

	return &PolicyReconciler{
		base:    baseReconciler,
		handler: handler,
	}
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultpolicies/finalizers,verbs=update

// Reconcile implements the reconciliation loop for VaultPolicy.
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return r.base.Reconcile(ctx, req, &policyFeatureHandler{handler: r.handler}, func() *vaultv1alpha1.VaultPolicy {
		return &vaultv1alpha1.VaultPolicy{}
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultPolicy{}).
		Named("vaultpolicy").
		Complete(r)
}

// policyFeatureHandler adapts the shared Handler to the FeatureHandler interface for VaultPolicy.
type policyFeatureHandler struct {
	handler *Handler
}

func (h *policyFeatureHandler) Sync(ctx context.Context, policy *vaultv1alpha1.VaultPolicy) error {
	adapter := domain.NewVaultPolicyAdapter(policy)
	return h.handler.SyncPolicy(ctx, adapter)
}

func (h *policyFeatureHandler) Cleanup(ctx context.Context, policy *vaultv1alpha1.VaultPolicy) error {
	adapter := domain.NewVaultPolicyAdapter(policy)
	return h.handler.CleanupPolicy(ctx, adapter)
}

// Ensure policyFeatureHandler implements FeatureHandler interface.
var _ base.FeatureHandler[*vaultv1alpha1.VaultPolicy] = (*policyFeatureHandler)(nil)
