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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// ConnectionReadyChangedPredicate triggers only when the VaultConnection's
// `Ready` condition transitions between True and False (or enters/leaves
// the condition set).
//
// This is a stricter filter than `ConnectionPhaseChangedPredicate`, which
// also fires on intermediate Phase transitions (Pending → Syncing → Active)
// that don't actually affect dependent-CR readiness. Use this predicate
// when a dependent controller only needs to react to "can I use this
// connection now?" changes — the k8s-idiomatic pattern.
//
// Introduced for IMPROVEMENTS.md Missing Features §F.
type ConnectionReadyChangedPredicate struct {
	predicate.Funcs
}

func (ConnectionReadyChangedPredicate) Create(event.CreateEvent) bool { return true }

func (ConnectionReadyChangedPredicate) Delete(event.DeleteEvent) bool { return true }

func (ConnectionReadyChangedPredicate) Update(e event.UpdateEvent) bool {
	oldConn, okOld := e.ObjectOld.(*vaultv1alpha1.VaultConnection)
	newConn, okNew := e.ObjectNew.(*vaultv1alpha1.VaultConnection)
	if !okOld || !okNew {
		return true
	}
	return isConnectionReady(oldConn) != isConnectionReady(newConn)
}

func (ConnectionReadyChangedPredicate) Generic(event.GenericEvent) bool { return false }

// ReconcileNowAnnotationPredicate triggers on Update events where the
// `vault.platform.io/reconcile-now` annotation was added or changed value
// between the old and new resource. Combined with
// `predicate.GenerationChangedPredicate` via `predicate.Or`, it gives
// users a way to force an immediate reconcile of a CR whose spec hasn't
// changed — e.g. after fixing a problem in Vault manually.
//
// The handler is responsible for clearing the annotation after a successful
// sync so the predicate doesn't re-fire on every reconcile. Create/Delete
// events fall through to the always-enqueue default so newly-annotated CRs
// are picked up immediately on first sight.
//
// Introduced for IMPROVEMENTS.md Missing Features §H.
type ReconcileNowAnnotationPredicate struct {
	predicate.Funcs
}

func (ReconcileNowAnnotationPredicate) Create(event.CreateEvent) bool { return true }

func (ReconcileNowAnnotationPredicate) Delete(event.DeleteEvent) bool { return false }

func (ReconcileNowAnnotationPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		return false
	}
	oldVal := e.ObjectOld.GetAnnotations()[vaultv1alpha1.AnnotationReconcileNow]
	newVal := e.ObjectNew.GetAnnotations()[vaultv1alpha1.AnnotationReconcileNow]
	// Trigger only when the annotation newly appears or its value changed
	// while non-empty. Clearing the annotation (non-empty → empty) is NOT
	// a trigger — that's the handler acknowledging the previous reconcile.
	return newVal != "" && newVal != oldVal
}

func (ReconcileNowAnnotationPredicate) Generic(event.GenericEvent) bool { return false }

// isConnectionReady reports whether the connection's Ready condition is
// present and True. A missing condition counts as not-ready.
func isConnectionReady(conn *vaultv1alpha1.VaultConnection) bool {
	for _, c := range conn.Status.Conditions {
		if c.Type == vaultv1alpha1.ConditionTypeReady {
			return c.Status == metav1.ConditionTrue
		}
	}
	return false
}
