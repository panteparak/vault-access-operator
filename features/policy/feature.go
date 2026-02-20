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

// Package policy implements the Policy feature for the Vault Access Operator.
// This feature manages VaultPolicy (namespaced) and VaultClusterPolicy (cluster-scoped)
// resources which define access policies in HashiCorp Vault.
//
// Feature-Driven Design: This package is organized as a vertical slice containing
// all components needed for the policy feature (controller, domain, handler).
package policy

import (
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/panteparak/vault-access-operator/features/policy/controller"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// Feature is the entry point for the Policy feature.
// It wires together all components and provides a clean interface for setup.
type Feature struct {
	// PolicyReconciler handles VaultPolicy reconciliation
	PolicyReconciler *controller.PolicyReconciler

	// ClusterPolicyReconciler handles VaultClusterPolicy reconciliation
	ClusterPolicyReconciler *controller.ClusterPolicyReconciler

	// Handler provides shared policy sync/cleanup logic
	handler *controller.Handler

	// eventBus for publishing policy events
	eventBus *events.EventBus

	// log for feature-level logging
	log logr.Logger
}

// New creates a new Policy Feature with all dependencies wired together.
func New(
	eventBus *events.EventBus,
	clientCache *vault.ClientCache,
	k8sClient client.Client,
	scheme *runtime.Scheme,
	log logr.Logger,
	recorder record.EventRecorder,
) *Feature {
	featureLog := log.WithName("policy")

	// Create the shared handler
	handler := controller.NewHandler(k8sClient, clientCache, eventBus, featureLog, recorder)

	// Create the reconcilers (both use the same handler)
	policyReconciler := controller.NewPolicyReconciler(
		k8sClient,
		scheme,
		handler,
		featureLog,
		recorder,
	)

	clusterPolicyReconciler := controller.NewClusterPolicyReconciler(
		k8sClient,
		scheme,
		handler,
		featureLog,
		recorder,
	)

	return &Feature{
		PolicyReconciler:        policyReconciler,
		ClusterPolicyReconciler: clusterPolicyReconciler,
		handler:                 handler,
		eventBus:                eventBus,
		log:                     featureLog,
	}
}

// SetupWithManager registers the Policy feature's controllers with the manager.
func (f *Feature) SetupWithManager(mgr ctrl.Manager) error {
	f.log.Info("setting up Policy feature")

	// Setup VaultPolicy controller
	if err := f.PolicyReconciler.SetupWithManager(mgr); err != nil {
		return err
	}

	// Setup VaultClusterPolicy controller
	if err := f.ClusterPolicyReconciler.SetupWithManager(mgr); err != nil {
		return err
	}

	return nil
}
