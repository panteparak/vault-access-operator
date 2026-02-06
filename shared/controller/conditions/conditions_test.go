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

package conditions

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

func TestSet_AppendsNewCondition(t *testing.T) {
	var conds []vaultv1alpha1.Condition

	result := Set(conds, 1, "Ready", metav1.ConditionTrue, "Succeeded", "all good")
	if len(result) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(result))
	}
	if result[0].Type != "Ready" {
		t.Errorf("Type = %q, want %q", result[0].Type, "Ready")
	}
	if result[0].Status != metav1.ConditionTrue {
		t.Errorf("Status = %v, want %v", result[0].Status, metav1.ConditionTrue)
	}
	if result[0].Reason != "Succeeded" {
		t.Errorf("Reason = %q, want %q", result[0].Reason, "Succeeded")
	}
	if result[0].ObservedGeneration != 1 {
		t.Errorf("ObservedGeneration = %d, want 1", result[0].ObservedGeneration)
	}
}

func TestSet_UpdatesExistingCondition_StatusChanged(t *testing.T) {
	conds := []vaultv1alpha1.Condition{
		{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "Succeeded",
			Message:            "all good",
			ObservedGeneration: 1,
		},
	}

	originalTime := conds[0].LastTransitionTime

	result := Set(conds, 2, "Ready", metav1.ConditionFalse, "Failed", "something broke")
	if len(result) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(result))
	}
	if result[0].Status != metav1.ConditionFalse {
		t.Errorf("Status = %v, want %v", result[0].Status, metav1.ConditionFalse)
	}
	if result[0].Reason != "Failed" {
		t.Errorf("Reason = %q, want %q", result[0].Reason, "Failed")
	}
	// LastTransitionTime should have changed since status changed
	if result[0].LastTransitionTime.Equal(&originalTime) {
		t.Error("LastTransitionTime should change when status changes")
	}
}

func TestSet_UpdatesExistingCondition_StatusUnchanged(t *testing.T) {
	originalTime := metav1.Now()
	conds := []vaultv1alpha1.Condition{
		{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: originalTime,
			Reason:             "Succeeded",
			Message:            "all good",
			ObservedGeneration: 1,
		},
	}

	result := Set(conds, 2, "Ready", metav1.ConditionTrue, "StillGood", "updated message")
	if len(result) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(result))
	}
	// Status unchanged → reason/message/generation should update, but LastTransitionTime preserved
	if result[0].Reason != "StillGood" {
		t.Errorf("Reason = %q, want %q", result[0].Reason, "StillGood")
	}
	if result[0].Message != "updated message" {
		t.Errorf("Message = %q, want %q", result[0].Message, "updated message")
	}
	if result[0].ObservedGeneration != 2 {
		t.Errorf("ObservedGeneration = %d, want 2", result[0].ObservedGeneration)
	}
	if !result[0].LastTransitionTime.Equal(&originalTime) {
		t.Error("LastTransitionTime should NOT change when status is unchanged")
	}
}

func TestSet_PreservesOtherConditions(t *testing.T) {
	conds := []vaultv1alpha1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue, Reason: "OK"},
		{Type: "Synced", Status: metav1.ConditionTrue, Reason: "OK"},
	}

	result := Set(conds, 1, "Ready", metav1.ConditionFalse, "Failed", "broke")
	if len(result) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(result))
	}
	// "Synced" should be untouched
	if result[1].Type != "Synced" || result[1].Reason != "OK" {
		t.Error("other conditions should be preserved")
	}
}
