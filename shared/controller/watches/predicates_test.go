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
