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

// Package role implements the Role feature for the Vault Access Operator.
// This feature manages VaultRole (namespaced) and VaultClusterRole (cluster-scoped)
// resources which define Kubernetes auth roles in HashiCorp Vault.
//
// Feature-Driven Design: This package is organized as a vertical slice containing
// all components needed for the role feature (controller, domain, handler).
package role

import (
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/panteparak/vault-access-operator/features/role/controller"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// Feature is the entry point for the Role feature.
// It wires together all components and provides a clean interface for setup.
type Feature struct {
	// RoleReconciler handles VaultRole reconciliation
	RoleReconciler *controller.RoleReconciler

	// ClusterRoleReconciler handles VaultClusterRole reconciliation
	ClusterRoleReconciler *controller.ClusterRoleReconciler

	// Handler provides shared role sync/cleanup logic
	handler *controller.Handler

	// eventBus for publishing role events
	eventBus *events.EventBus

	// log for feature-level logging
	log logr.Logger
}

// New creates a new Role Feature with all dependencies wired together.
func New(
	eventBus *events.EventBus,
	clientCache *vault.ClientCache,
	k8sClient client.Client,
	scheme *runtime.Scheme,
	log logr.Logger,
	recorder record.EventRecorder,
) *Feature {
	featureLog := log.WithName("role")

	// Create the shared handler
	handler := controller.NewHandler(k8sClient, clientCache, eventBus, featureLog)

	// Create the reconcilers (both use the same handler)
	roleReconciler := controller.NewRoleReconciler(
		k8sClient,
		scheme,
		handler,
		featureLog,
		recorder,
	)

	clusterRoleReconciler := controller.NewClusterRoleReconciler(
		k8sClient,
		scheme,
		handler,
		featureLog,
		recorder,
	)

	return &Feature{
		RoleReconciler:        roleReconciler,
		ClusterRoleReconciler: clusterRoleReconciler,
		handler:               handler,
		eventBus:              eventBus,
		log:                   featureLog,
	}
}

// SetupWithManager registers the Role feature's controllers with the manager.
func (f *Feature) SetupWithManager(mgr ctrl.Manager) error {
	f.log.Info("setting up Role feature")

	// Setup VaultRole controller
	if err := f.RoleReconciler.SetupWithManager(mgr); err != nil {
		return err
	}

	// Setup VaultClusterRole controller
	if err := f.ClusterRoleReconciler.SetupWithManager(mgr); err != nil {
		return err
	}

	return nil
}
