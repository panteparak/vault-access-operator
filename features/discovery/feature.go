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

// Package discovery implements the Discovery feature for the Vault Access Operator.
// This feature scans Vault for unmanaged resources (policies and roles) and optionally
// creates Kubernetes CRs to adopt them.
//
// Feature-Driven Design: This package is organized as a vertical slice containing
// all components needed for the discovery feature (controller, scanner).
package discovery

import (
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/panteparak/vault-access-operator/features/discovery/controller"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// Feature is the entry point for the Discovery feature.
// It wires together all components and provides a clean interface for setup.
type Feature struct {
	// Reconciler handles discovery scanning for VaultConnections
	Reconciler *controller.Reconciler

	// log for feature-level logging
	log logr.Logger
}

// Config contains configuration for creating a Discovery Feature.
type Config struct {
	K8sClient   client.Client
	Scheme      *runtime.Scheme
	ClientCache *vault.ClientCache
	Log         logr.Logger
	Recorder    record.EventRecorder
}

// New creates a new Discovery Feature with all dependencies wired together.
func New(cfg Config) *Feature {
	featureLog := cfg.Log.WithName("discovery")

	reconciler := controller.NewReconciler(controller.ReconcilerConfig{
		Client:      cfg.K8sClient,
		Scheme:      cfg.Scheme,
		ClientCache: cfg.ClientCache,
		Log:         featureLog,
		Recorder:    cfg.Recorder,
	})

	return &Feature{
		Reconciler: reconciler,
		log:        featureLog,
	}
}

// SetupWithManager registers the Discovery feature's controller with the manager.
func (f *Feature) SetupWithManager(mgr ctrl.Manager) error {
	f.log.Info("setting up Discovery feature")
	return f.Reconciler.SetupWithManager(mgr)
}
