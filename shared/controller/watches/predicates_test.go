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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

func TestConnectionPhaseChangedPredicate_Create(t *testing.T) {
	p := ConnectionPhaseChangedPredicate{}
	if !p.Create(event.CreateEvent{}) {
		t.Error("Create should always return true")
	}
}

func TestConnectionPhaseChangedPredicate_Delete(t *testing.T) {
	p := ConnectionPhaseChangedPredicate{}
	if !p.Delete(event.DeleteEvent{}) {
		t.Error("Delete should always return true")
	}
}

func TestConnectionPhaseChangedPredicate_Generic(t *testing.T) {
	p := ConnectionPhaseChangedPredicate{}
	if p.Generic(event.GenericEvent{}) {
		t.Error("Generic should return false")
	}
}

func TestConnectionPhaseChangedPredicate_Update_PhaseChange(t *testing.T) {
	p := ConnectionPhaseChangedPredicate{}

	oldConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status:     vaultv1alpha1.VaultConnectionStatus{Phase: vaultv1alpha1.PhasePending},
	}
	newConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status:     vaultv1alpha1.VaultConnectionStatus{Phase: vaultv1alpha1.PhaseActive},
	}

	e := event.UpdateEvent{ObjectOld: oldConn, ObjectNew: newConn}
	if !p.Update(e) {
		t.Error("expected true for phase change")
	}
}

func TestConnectionPhaseChangedPredicate_Update_HealthChange(t *testing.T) {
	p := ConnectionPhaseChangedPredicate{}

	oldConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseActive,
			Healthy: true,
		},
	}
	newConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseActive,
			Healthy: false,
		},
	}

	e := event.UpdateEvent{ObjectOld: oldConn, ObjectNew: newConn}
	if !p.Update(e) {
		t.Error("expected true for health change")
	}
}

func TestConnectionPhaseChangedPredicate_Update_NoChange(t *testing.T) {
	p := ConnectionPhaseChangedPredicate{}

	oldConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseActive,
			Healthy: true,
		},
	}
	newConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:        vaultv1alpha1.PhaseActive,
			Healthy:      true,
			VaultVersion: "1.15.0", // Only version changed
		},
	}

	e := event.UpdateEvent{ObjectOld: oldConn, ObjectNew: newConn}
	if p.Update(e) {
		t.Error("expected false when only heartbeat fields change")
	}
}

// TestConnectionPhaseChangedPredicate_Update_ReadyReasonChange pins the
// followup fix where the predicate was missing transitions on the Ready
// condition Reason field even though Phase + Healthy stayed the same.
//
// Concrete scenario this guards: VaultSealed → Succeeded after a
// `vault operator unseal`. Phase may temporarily linger at Error while
// the Reason flips, and dependent CRs need to retry immediately rather
// than wait for the next ~5min scheduled reconcile.
func TestConnectionPhaseChangedPredicate_Update_ReadyReasonChange(t *testing.T) {
	p := ConnectionPhaseChangedPredicate{}
	oldConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseError,
			Healthy: false,
			Conditions: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeReady, Reason: vaultv1alpha1.ReasonVaultSealed},
			},
		},
	}
	newConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseError, // intentionally same
			Healthy: false,                    // intentionally same
			Conditions: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeReady, Reason: vaultv1alpha1.ReasonSucceeded},
			},
		},
	}
	e := event.UpdateEvent{ObjectOld: oldConn, ObjectNew: newConn}
	if !p.Update(e) {
		t.Error("expected trigger when Ready reason flips even with Phase/Healthy unchanged")
	}
}

// ---------------------------------------------------------------------------
// ConnectionReadyChangedPredicate — IMPROVEMENTS Missing Features §F.
// ---------------------------------------------------------------------------

func connWithReady(status metav1.ConditionStatus) *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Conditions: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeReady, Status: status},
			},
		},
	}
}

func TestConnectionReadyChangedPredicate_Create(t *testing.T) {
	if !(ConnectionReadyChangedPredicate{}).Create(event.CreateEvent{}) {
		t.Error("Create should always enqueue")
	}
}

func TestConnectionReadyChangedPredicate_Delete(t *testing.T) {
	if !(ConnectionReadyChangedPredicate{}).Delete(event.DeleteEvent{}) {
		t.Error("Delete should always enqueue")
	}
}

func TestConnectionReadyChangedPredicate_Update_TrueToFalse(t *testing.T) {
	p := ConnectionReadyChangedPredicate{}
	e := event.UpdateEvent{
		ObjectOld: connWithReady(metav1.ConditionTrue),
		ObjectNew: connWithReady(metav1.ConditionFalse),
	}
	if !p.Update(e) {
		t.Error("expected trigger when Ready flipped True → False")
	}
}

func TestConnectionReadyChangedPredicate_Update_FalseToTrue(t *testing.T) {
	p := ConnectionReadyChangedPredicate{}
	e := event.UpdateEvent{
		ObjectOld: connWithReady(metav1.ConditionFalse),
		ObjectNew: connWithReady(metav1.ConditionTrue),
	}
	if !p.Update(e) {
		t.Error("expected trigger when Ready flipped False → True")
	}
}

func TestConnectionReadyChangedPredicate_Update_NoChange(t *testing.T) {
	p := ConnectionReadyChangedPredicate{}
	e := event.UpdateEvent{
		ObjectOld: connWithReady(metav1.ConditionTrue),
		ObjectNew: connWithReady(metav1.ConditionTrue),
	}
	if p.Update(e) {
		t.Error("expected no trigger when Ready unchanged")
	}
}

// TestConnectionReadyChangedPredicate_Update_PhaseOnlyChange pins that the
// Ready predicate is STRICTER than the Phase predicate: a Pending → Syncing
// transition (both intermediate states, Ready still False) must not trigger.
func TestConnectionReadyChangedPredicate_Update_PhaseOnlyChange(t *testing.T) {
	p := ConnectionReadyChangedPredicate{}
	oldConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase: vaultv1alpha1.PhasePending,
			Conditions: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeReady, Status: metav1.ConditionFalse},
			},
		},
	}
	newConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "conn"},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase: vaultv1alpha1.PhaseSyncing,
			Conditions: []vaultv1alpha1.Condition{
				{Type: vaultv1alpha1.ConditionTypeReady, Status: metav1.ConditionFalse},
			},
		},
	}
	e := event.UpdateEvent{ObjectOld: oldConn, ObjectNew: newConn}
	if p.Update(e) {
		t.Error("Ready predicate must NOT fire on Phase-only transitions " +
			"when Ready status is unchanged (Pending → Syncing, both Ready=False)")
	}
}

// TestConnectionReadyChangedPredicate_Update_AbsentToPresent: a fresh
// connection starting with no Ready condition, then gaining one that's True,
// should trigger — "absent" counts as not-ready.
func TestConnectionReadyChangedPredicate_Update_AbsentToPresent(t *testing.T) {
	p := ConnectionReadyChangedPredicate{}
	oldConn := &vaultv1alpha1.VaultConnection{ObjectMeta: metav1.ObjectMeta{Name: "conn"}}
	newConn := connWithReady(metav1.ConditionTrue)
	e := event.UpdateEvent{ObjectOld: oldConn, ObjectNew: newConn}
	if !p.Update(e) {
		t.Error("expected trigger when Ready condition first appears as True")
	}
}

func TestConnectionReadyChangedPredicate_Generic(t *testing.T) {
	if (ConnectionReadyChangedPredicate{}).Generic(event.GenericEvent{}) {
		t.Error("Generic events should not enqueue")
	}
}

// ---------------------------------------------------------------------------
// ReconcileNowAnnotationPredicate — IMPROVEMENTS Missing Features §H.
//
// Fires on Update when the `vault.platform.io/reconcile-now` annotation is
// added or changed. Handler is expected to clear the annotation after the
// triggered reconcile to prevent an infinite loop.
// ---------------------------------------------------------------------------

func roleWithAnnotations(anns map[string]string) *vaultv1alpha1.VaultRole {
	return &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns", Annotations: anns},
	}
}

func TestReconcileNowAnnotationPredicate_Create(t *testing.T) {
	if !(ReconcileNowAnnotationPredicate{}).Create(event.CreateEvent{}) {
		t.Error("Create should always enqueue to catch first-time annotated CRs")
	}
}

func TestReconcileNowAnnotationPredicate_Delete(t *testing.T) {
	if (ReconcileNowAnnotationPredicate{}).Delete(event.DeleteEvent{}) {
		t.Error("Delete should NOT enqueue through this predicate")
	}
}

func TestReconcileNowAnnotationPredicate_Generic(t *testing.T) {
	if (ReconcileNowAnnotationPredicate{}).Generic(event.GenericEvent{}) {
		t.Error("Generic events should not enqueue")
	}
}

// TestReconcileNowAnnotationPredicate_Update_AnnotationAdded pins the main
// case: a user kubectl-annotates an existing CR with reconcile-now=true.
func TestReconcileNowAnnotationPredicate_Update_AnnotationAdded(t *testing.T) {
	p := ReconcileNowAnnotationPredicate{}
	e := event.UpdateEvent{
		ObjectOld: roleWithAnnotations(nil),
		ObjectNew: roleWithAnnotations(map[string]string{
			vaultv1alpha1.AnnotationReconcileNow: "2026-04-18T10:00:00Z",
		}),
	}
	if !p.Update(e) {
		t.Error("expected trigger when reconcile-now annotation is added")
	}
}

// TestReconcileNowAnnotationPredicate_Update_ValueChanged pins that
// repeated kubectl-annotate commands (with different timestamps) still
// fire — each triggers a fresh reconcile.
func TestReconcileNowAnnotationPredicate_Update_ValueChanged(t *testing.T) {
	p := ReconcileNowAnnotationPredicate{}
	e := event.UpdateEvent{
		ObjectOld: roleWithAnnotations(map[string]string{
			vaultv1alpha1.AnnotationReconcileNow: "first",
		}),
		ObjectNew: roleWithAnnotations(map[string]string{
			vaultv1alpha1.AnnotationReconcileNow: "second",
		}),
	}
	if !p.Update(e) {
		t.Error("expected trigger when reconcile-now annotation value changes")
	}
}

// TestReconcileNowAnnotationPredicate_Update_AnnotationCleared pins that
// when the handler clears the annotation (non-empty → empty) the predicate
// does NOT fire — otherwise we'd get an infinite reconcile loop.
func TestReconcileNowAnnotationPredicate_Update_AnnotationCleared(t *testing.T) {
	p := ReconcileNowAnnotationPredicate{}
	e := event.UpdateEvent{
		ObjectOld: roleWithAnnotations(map[string]string{
			vaultv1alpha1.AnnotationReconcileNow: "true",
		}),
		ObjectNew: roleWithAnnotations(nil),
	}
	if p.Update(e) {
		t.Error("clearing the annotation must NOT re-trigger — " +
			"that's the handler acknowledging the previous reconcile")
	}
}

// TestReconcileNowAnnotationPredicate_Update_UnrelatedAnnotationChange
// ensures the predicate ignores changes to other annotations — only the
// reconcile-now key should matter.
func TestReconcileNowAnnotationPredicate_Update_UnrelatedAnnotationChange(t *testing.T) {
	p := ReconcileNowAnnotationPredicate{}
	e := event.UpdateEvent{
		ObjectOld: roleWithAnnotations(map[string]string{"other": "a"}),
		ObjectNew: roleWithAnnotations(map[string]string{"other": "b"}),
	}
	if p.Update(e) {
		t.Error("expected no trigger for unrelated annotation changes")
	}
}
