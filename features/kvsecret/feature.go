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

// Package kvsecret implements the KVSecret feature for the Vault Access Operator.
// It manages VaultKVSecret resources, which pre-create ("seed") KV v2 secret
// paths so consumers such as External Secrets Operator don't fail when a source
// path is missing on a fresh deployment. The operator only creates paths when
// absent — it never overwrites or reads the values stored there.
//
// Feature-Driven Design: this package is a vertical slice containing the
// controller and handler for the feature.
package kvsecret

import (
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/panteparak/vault-access-operator/features/kvsecret/controller"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// Feature is the entry point for the KVSecret feature.
type Feature struct {
	// Reconciler handles VaultKVSecret reconciliation.
	Reconciler *controller.KVSecretReconciler

	// log for feature-level logging.
	log logr.Logger
}

// New creates a new KVSecret Feature with all dependencies wired together.
func New(
	clientCache *vault.ClientCache,
	k8sClient client.Client,
	scheme *runtime.Scheme,
	log logr.Logger,
	recorder record.EventRecorder,
) *Feature {
	featureLog := log.WithName("kvsecret")

	h := controller.NewHandler(k8sClient, clientCache, featureLog, recorder)
	reconciler := controller.NewKVSecretReconciler(k8sClient, scheme, h, featureLog, recorder)

	return &Feature{
		Reconciler: reconciler,
		log:        featureLog,
	}
}

// SetupWithManager registers the KVSecret feature's controller with the manager.
func (f *Feature) SetupWithManager(mgr ctrl.Manager) error {
	f.log.Info("setting up KVSecret feature")
	return f.Reconciler.SetupWithManager(mgr)
}
