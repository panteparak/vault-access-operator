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
	"github.com/panteparak/vault-access-operator/shared/controller/watches"
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
		Recorder:         cfg.Recorder,
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

// IndexFieldConnectionRef is the field-indexer key used by `listDependents` to
// find every VaultPolicy / VaultClusterPolicy / VaultRole / VaultClusterRole
// that references a given VaultConnection without doing a cluster-wide list
// scan (IMPROVEMENTS §15).
const IndexFieldConnectionRef = "spec.connectionRef"

// SetupWithManager sets up the controller with the Manager. Registers the
// spec.connectionRef field indexer on the four dependent CRD kinds so that
// Cleanup can query `client.MatchingFields{IndexFieldConnectionRef: name}`
// instead of listing every resource cluster-wide and filtering in Go.
//
// The For predicate accepts:
//   - Spec changes (GenerationChangedPredicate — the default).
//   - The `vault.platform.io/reconcile-now` annotation being added or
//     updated (IMPROVEMENTS Missing Features §H — same trigger that
//     works on policy/role reconcilers; previously omitted from
//     VaultConnection by oversight).
//
// Note: the `vault.platform.io/restore-managed-markers` annotation (§G)
// does NOT trigger an immediate reconcile via this predicate — that
// predicate is specific to AnnotationReconcileNow. Setting
// restore-managed-markers takes effect on the next scheduled reconcile
// (≤30s, the requeueOnSuccess interval). To force-trigger immediately,
// also set `vault.platform.io/reconcile-now` on the same connection.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := registerConnectionRefIndexers(context.Background(), mgr); err != nil {
		return fmt.Errorf("register connectionRef field indexers: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultConnection{},
			builder.WithPredicates(predicate.Or(
				predicate.GenerationChangedPredicate{},
				watches.ReconcileNowAnnotationPredicate{},
			))).
		Named("vaultconnection").
		Complete(r)
}

// registerConnectionRefIndexers adds a field index on spec.connectionRef for
// each dependent CRD kind. The indexer runs once per kind at manager startup
// and is idempotent across reconciler setups (controller-runtime dedupes by
// key + type). Errors here are fatal — without the indexer the MatchingFields
// query in listDependents fails at request time, which would stall cleanup.
func registerConnectionRefIndexers(ctx context.Context, mgr ctrl.Manager) error {
	indexer := mgr.GetFieldIndexer()
	types := []struct {
		obj      client.Object
		accessor func(client.Object) []string
	}{
		{
			obj: &vaultv1alpha1.VaultPolicy{},
			accessor: func(o client.Object) []string {
				return []string{o.(*vaultv1alpha1.VaultPolicy).Spec.ConnectionRef}
			},
		},
		{
			obj: &vaultv1alpha1.VaultClusterPolicy{},
			accessor: func(o client.Object) []string {
				return []string{o.(*vaultv1alpha1.VaultClusterPolicy).Spec.ConnectionRef}
			},
		},
		{
			obj: &vaultv1alpha1.VaultRole{},
			accessor: func(o client.Object) []string {
				return []string{o.(*vaultv1alpha1.VaultRole).Spec.ConnectionRef}
			},
		},
		{
			obj: &vaultv1alpha1.VaultClusterRole{},
			accessor: func(o client.Object) []string {
				return []string{o.(*vaultv1alpha1.VaultClusterRole).Spec.ConnectionRef}
			},
		},
	}
	for _, t := range types {
		if err := indexer.IndexField(ctx, t.obj, IndexFieldConnectionRef, t.accessor); err != nil {
			return fmt.Errorf("index %T: %w", t.obj, err)
		}
	}
	return nil
}
