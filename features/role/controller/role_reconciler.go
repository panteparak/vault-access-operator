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

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/panteparak/vault-access-operator/shared/controller/watches"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/shared/controller/base"
)

// RoleReconciler reconciles VaultRole resources using the BaseReconciler pattern.
type RoleReconciler struct {
	base    *base.BaseReconciler[*vaultv1alpha1.VaultRole]
	handler *Handler
}

// NewRoleReconciler creates a new VaultRole Reconciler.
func NewRoleReconciler(
	c client.Client,
	scheme *runtime.Scheme,
	h *Handler,
	log logr.Logger,
	recorder record.EventRecorder,
) *RoleReconciler {
	// Create base reconciler
	baseReconciler := base.NewBaseReconciler[*vaultv1alpha1.VaultRole](
		c,
		scheme,
		log.WithName("vaultrole"),
		vaultv1alpha1.FinalizerName,
		nil, // Status is updated in the handler
		recorder,
	)

	// Configure requeue intervals (overridable via OPERATOR_REQUEUE_SUCCESS_INTERVAL env var)
	baseReconciler.Status.
		WithRequeueOnSuccess(base.DefaultRequeueSuccess).
		WithRequeueOnError(base.DefaultRequeueError)

	return &RoleReconciler{
		base:    baseReconciler,
		handler: h,
	}
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultroles/finalizers,verbs=update
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultconnections,verbs=get;list;watch

// Reconcile implements the reconciliation loop for VaultRole.
// Emits `vault_access_operator_role_reconcile_total{kind, namespace, result}`
// per IMPROVEMENTS §31 (registered-but-dead before this fix).
func (r *RoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	result, err := r.base.Reconcile(ctx, req, &roleFeatureHandler{handler: r.handler}, func() *vaultv1alpha1.VaultRole {
		return &vaultv1alpha1.VaultRole{}
	})
	metrics.IncrementRoleReconcile(kindLabelVaultRole, req.Namespace, err == nil)
	return result, err
}

// SetupWithManager sets up the controller with the Manager. It watches
// three event sources:
//   - The VaultRole itself (generation changes OR reconcile-now annotation
//     changes via IMPROVEMENTS Missing Features §H).
//   - VaultConnection phase transitions (IMPROVEMENTS §1 / existing behavior).
//   - VaultPolicy + VaultClusterPolicy creates/updates (IMPROVEMENTS §27) —
//     so a role blocked on an unresolved PolicyBinding reconciles within
//     milliseconds of the policy appearing instead of waiting up to 30s
//     for the next scheduled sync.
func (r *RoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultRole{},
			builder.WithPredicates(predicate.Or(
				predicate.GenerationChangedPredicate{},
				watches.ReconcileNowAnnotationPredicate{},
			))).
		Watches(
			&vaultv1alpha1.VaultConnection{},
			handler.EnqueueRequestsFromMapFunc(
				watches.RoleRequestsForConnection(mgr.GetClient()),
			),
			builder.WithPredicates(watches.ConnectionPhaseChangedPredicate{}),
		).
		Watches(
			&vaultv1alpha1.VaultPolicy{},
			handler.EnqueueRequestsFromMapFunc(
				watches.RoleRequestsForPolicy(mgr.GetClient()),
			),
			builder.WithPredicates(watches.PolicyCreatedOrUpdatedPredicate),
		).
		Watches(
			&vaultv1alpha1.VaultClusterPolicy{},
			handler.EnqueueRequestsFromMapFunc(
				watches.RoleRequestsForPolicy(mgr.GetClient()),
			),
			builder.WithPredicates(watches.PolicyCreatedOrUpdatedPredicate),
		).
		Named("vaultrole").
		Complete(r)
}

// roleFeatureHandler adapts the shared Handler to the FeatureHandler interface for VaultRole.
type roleFeatureHandler struct {
	handler *Handler
}

func (h *roleFeatureHandler) Sync(ctx context.Context, role *vaultv1alpha1.VaultRole) error {
	adapter := domain.NewVaultRoleAdapter(role)
	return h.handler.SyncRole(ctx, adapter)
}

func (h *roleFeatureHandler) Cleanup(ctx context.Context, role *vaultv1alpha1.VaultRole) error {
	adapter := domain.NewVaultRoleAdapter(role)
	return h.handler.CleanupRole(ctx, adapter)
}

// Ensure roleFeatureHandler implements FeatureHandler interface.
var _ base.FeatureHandler[*vaultv1alpha1.VaultRole] = (*roleFeatureHandler)(nil)
