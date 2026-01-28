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

// ClusterRoleReconciler reconciles VaultClusterRole resources using the BaseReconciler pattern.
type ClusterRoleReconciler struct {
	base    *base.BaseReconciler[*vaultv1alpha1.VaultClusterRole]
	handler *Handler
}

// NewClusterRoleReconciler creates a new VaultClusterRole Reconciler.
func NewClusterRoleReconciler(
	c client.Client,
	scheme *runtime.Scheme,
	handler *Handler,
	log logr.Logger,
	recorder record.EventRecorder,
) *ClusterRoleReconciler {
	// Create base reconciler
	baseReconciler := base.NewBaseReconciler[*vaultv1alpha1.VaultClusterRole](
		c,
		scheme,
		log.WithName("vaultclusterrole"),
		vaultv1alpha1.FinalizerName,
		nil, // Status is updated in the handler
		recorder,
	)

	// Configure requeue intervals
	baseReconciler.Status.
		WithRequeueOnSuccess(5 * time.Minute). // Periodic re-sync
		WithRequeueOnError(30 * time.Second)

	return &ClusterRoleReconciler{
		base:    baseReconciler,
		handler: handler,
	}
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterroles,verbs=get;list;watch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterroles,verbs=create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterroles/finalizers,verbs=update

// Reconcile implements the reconciliation loop for VaultClusterRole.
func (r *ClusterRoleReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	return r.base.Reconcile(
		ctx, req,
		&clusterRoleFeatureHandler{handler: r.handler},
		func() *vaultv1alpha1.VaultClusterRole {
			return &vaultv1alpha1.VaultClusterRole{}
		},
	)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultClusterRole{}).
		Named("vaultclusterrole").
		Complete(r)
}

// clusterRoleFeatureHandler adapts the shared Handler to the FeatureHandler interface for VaultClusterRole.
type clusterRoleFeatureHandler struct {
	handler *Handler
}

func (h *clusterRoleFeatureHandler) Sync(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) error {
	adapter := domain.NewVaultClusterRoleAdapter(role)
	return h.handler.SyncRole(ctx, adapter)
}

func (h *clusterRoleFeatureHandler) Cleanup(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) error {
	adapter := domain.NewVaultClusterRoleAdapter(role)
	return h.handler.CleanupRole(ctx, adapter)
}

// Ensure clusterRoleFeatureHandler implements FeatureHandler interface.
var _ base.FeatureHandler[*vaultv1alpha1.VaultClusterRole] = (*clusterRoleFeatureHandler)(nil)
