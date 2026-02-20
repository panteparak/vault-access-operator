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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/pkg/vault/bootstrap"
	"github.com/panteparak/vault-access-operator/pkg/vault/token"
	"github.com/panteparak/vault-access-operator/shared/controller/base"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// Reconciler reconciles VaultConnection resources using the BaseReconciler pattern.
// This dramatically reduces boilerplate by delegating common logic to the base.
type Reconciler struct {
	base    *base.BaseReconciler[*vaultv1alpha1.VaultConnection]
	handler *Handler
}

// ReconcilerConfig contains all configuration for creating a Reconciler.
type ReconcilerConfig struct {
	Client       client.Client
	Scheme       *runtime.Scheme
	ClientCache  *vault.ClientCache
	EventBus     *events.EventBus
	K8sClientset kubernetes.Interface
	Log          logr.Logger
	Recorder     record.EventRecorder
}

// NewReconciler creates a new VaultConnection Reconciler.
func NewReconciler(cfg ReconcilerConfig) *Reconciler {
	log := cfg.Log

	// Create token provider (uses TokenRequest API)
	var tokenProvider token.TokenProvider
	var clusterDiscovery bootstrap.K8sClusterDiscovery
	if cfg.K8sClientset != nil {
		tokenProvider = token.NewTokenRequestProvider(cfg.K8sClientset, log.WithName("token-provider"))
		clusterDiscovery = bootstrap.NewInClusterDiscovery(log)
	}

	// Create the feature handler with all dependencies
	handler := NewHandler(HandlerConfig{
		Client:           cfg.Client,
		ClientCache:      cfg.ClientCache,
		EventBus:         cfg.EventBus,
		K8sClientset:     cfg.K8sClientset,
		TokenProvider:    tokenProvider,
		ClusterDiscovery: clusterDiscovery,
		Log:              log.WithName("handler"),
	})

	// Create base reconciler with custom requeue times
	baseReconciler := base.NewBaseReconciler[*vaultv1alpha1.VaultConnection](
		cfg.Client,
		cfg.Scheme,
		log.WithName("reconciler"),
		vaultv1alpha1.FinalizerName,
		nil, // Status is updated in the handler
		cfg.Recorder,
	)

	// Configure requeue intervals
	baseReconciler.Status.
		WithRequeueOnSuccess(30 * time.Second). // Health check interval
		WithRequeueOnError(30 * time.Second)

	return &Reconciler{
		base:    baseReconciler,
		handler: handler,
	}
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultconnections,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultconnections/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultconnections/finalizers,verbs=update
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultpolicies;vaultclusterpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultroles;vaultclusterroles,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create

// Reconcile implements the reconciliation loop for VaultConnection.
// The actual logic is delegated to the BaseReconciler and Handler.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return r.base.Reconcile(ctx, req, r.handler, func() *vaultv1alpha1.VaultConnection {
		return &vaultv1alpha1.VaultConnection{}
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultConnection{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("vaultconnection").
		Complete(r)
}
