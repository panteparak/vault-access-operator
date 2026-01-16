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

// Package connection implements the Connection feature for the Vault Access Operator.
// This feature manages VaultConnection resources which establish authenticated
// connections to HashiCorp Vault servers.
//
// Feature-Driven Design: This package is organized as a vertical slice containing
// all components needed for the connection feature (controller, service, repository).
package connection

import (
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/panteparak/vault-access-operator/features/connection/controller"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// Feature is the entry point for the Connection feature.
// It wires together all components and provides a clean interface for setup.
type Feature struct {
	// Reconciler handles VaultConnection reconciliation
	Reconciler *controller.Reconciler

	// ClientCache provides cached Vault clients to other features
	ClientCache *vault.ClientCache

	// EventBus for publishing connection events
	eventBus *events.EventBus

	// log for feature-level logging
	log logr.Logger
}

// Config contains configuration for creating a Connection Feature.
type Config struct {
	EventBus     *events.EventBus
	K8sClient    client.Client
	K8sClientset kubernetes.Interface
	Scheme       *runtime.Scheme
	Log          logr.Logger
}

// New creates a new Connection Feature with all dependencies wired together.
func New(cfg Config) *Feature {
	featureLog := cfg.Log.WithName("connection")

	// Create the client cache (repository layer)
	clientCache := vault.NewClientCache()

	// Create the reconciler (controller layer)
	reconciler := controller.NewReconciler(controller.ReconcilerConfig{
		Client:       cfg.K8sClient,
		Scheme:       cfg.Scheme,
		ClientCache:  clientCache,
		EventBus:     cfg.EventBus,
		K8sClientset: cfg.K8sClientset,
		Log:          featureLog,
	})

	return &Feature{
		Reconciler:  reconciler,
		ClientCache: clientCache,
		eventBus:    cfg.EventBus,
		log:         featureLog,
	}
}

// SetupWithManager registers the Connection feature's controller with the manager.
func (f *Feature) SetupWithManager(mgr ctrl.Manager) error {
	f.log.Info("setting up Connection feature")
	return f.Reconciler.SetupWithManager(mgr)
}

// GetClient returns a Vault client for the specified connection name.
// This is the main interface other features use to access Vault.
func (f *Feature) GetClient(connectionName string) (*vault.Client, error) {
	return f.ClientCache.Get(connectionName)
}

// InvalidateClient removes a client from the cache.
// Called when a VaultConnection is updated or deleted.
func (f *Feature) InvalidateClient(connectionName string) {
	f.ClientCache.Delete(connectionName)
}
