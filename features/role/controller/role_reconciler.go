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
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
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
	handler *Handler,
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

	// Configure requeue intervals
	baseReconciler.Status.
		WithRequeueOnSuccess(5 * time.Minute). // Periodic re-sync
		WithRequeueOnError(30 * time.Second)

	return &RoleReconciler{
		base:    baseReconciler,
		handler: handler,
	}
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultroles/finalizers,verbs=update

// Reconcile implements the reconciliation loop for VaultRole.
func (r *RoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return r.base.Reconcile(ctx, req, &roleFeatureHandler{handler: r.handler}, func() *vaultv1alpha1.VaultRole {
		return &vaultv1alpha1.VaultRole{}
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *RoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultRole{}).
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
