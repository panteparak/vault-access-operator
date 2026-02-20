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

package watches

import (
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// ConnectionPhaseChangedPredicate triggers only on meaningful connection state changes:
// - Phase transitions (e.g., Pending → Active, Active → Error)
// - Health transitions (e.g., healthy → unhealthy)
// - Create/Delete events (always trigger)
//
// This prevents connection heartbeats (every 30s) from causing reconciliation storms
// on dependent policies and roles.
type ConnectionPhaseChangedPredicate struct {
	predicate.Funcs
}

func (ConnectionPhaseChangedPredicate) Create(e event.CreateEvent) bool {
	return true
}

func (ConnectionPhaseChangedPredicate) Delete(e event.DeleteEvent) bool {
	return true
}

func (ConnectionPhaseChangedPredicate) Update(e event.UpdateEvent) bool {
	oldConn, okOld := e.ObjectOld.(*vaultv1alpha1.VaultConnection)
	newConn, okNew := e.ObjectNew.(*vaultv1alpha1.VaultConnection)
	if !okOld || !okNew {
		// Not a VaultConnection, let it through
		return true
	}

	// Trigger on phase change
	if oldConn.Status.Phase != newConn.Status.Phase {
		return true
	}

	// Trigger on health change
	if oldConn.Status.Healthy != newConn.Status.Healthy {
		return true
	}

	return false
}

func (ConnectionPhaseChangedPredicate) Generic(e event.GenericEvent) bool {
	return false
}
