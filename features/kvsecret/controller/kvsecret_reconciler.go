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

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/shared/controller/base"
	"github.com/panteparak/vault-access-operator/shared/controller/watches"
)

// KVSecretReconciler reconciles VaultKVSecret resources using the BaseReconciler
// (Template Method) pattern. The varying Sync/Cleanup logic lives in Handler.
type KVSecretReconciler struct {
	base    *base.BaseReconciler[*vaultv1alpha1.VaultKVSecret]
	handler *Handler
}

// NewKVSecretReconciler creates a new VaultKVSecret reconciler. The handler's
// updateStatus is wired as the base reconciler's StatusUpdater so status is
// persisted on both success and failure.
func NewKVSecretReconciler(
	c client.Client, scheme *runtime.Scheme, h *Handler, log logr.Logger, recorder record.EventRecorder,
) *KVSecretReconciler {
	br := base.NewBaseReconciler[*vaultv1alpha1.VaultKVSecret](
		c,
		scheme,
		log.WithName("vaultkvsecret"),
		vaultv1alpha1.FinalizerName,
		h.updateStatus,
		recorder,
	)
	br.Status.
		WithRequeueOnSuccess(base.DefaultRequeueSuccess).
		WithRequeueOnError(base.DefaultRequeueError)

	return &KVSecretReconciler{base: br, handler: h}
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultkvsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultkvsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultkvsecrets/finalizers,verbs=update

// Reconcile implements the reconciliation loop for VaultKVSecret.
func (r *KVSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	newObj := func() *vaultv1alpha1.VaultKVSecret { return &vaultv1alpha1.VaultKVSecret{} }
	return r.base.Reconcile(ctx, req, r.handler, newObj)
}

// SetupWithManager registers the controller with the manager.
//
// The `For` predicate fires on generation changes (spec mutations) OR when the
// `vault.platform.io/reconcile-now` annotation is added/updated. The
// VaultConnection watch re-enqueues seeds blocked on a not-yet-Active connection.
func (r *KVSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultKVSecret{},
			builder.WithPredicates(predicate.Or(
				predicate.GenerationChangedPredicate{},
				watches.ReconcileNowAnnotationPredicate{},
			))).
		Watches(
			&vaultv1alpha1.VaultConnection{},
			handler.EnqueueRequestsFromMapFunc(watches.KVSecretRequestsForConnection(mgr.GetClient())),
			builder.WithPredicates(watches.ConnectionPhaseChangedPredicate{}),
		).
		Named("vaultkvsecret").
		Complete(r)
}

// Ensure Handler implements the FeatureHandler interface for VaultKVSecret.
var _ base.FeatureHandler[*vaultv1alpha1.VaultKVSecret] = (*Handler)(nil)
