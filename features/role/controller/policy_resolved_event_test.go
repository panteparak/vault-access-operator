/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
)

// TestEmitPolicyResolvedEvents_FiresOnTransition pins IMPROVEMENTS Missing
// Features §J: a binding flipping from Resolved=false to Resolved=true
// emits a PolicyResolved K8s event so operators inspecting
// `kubectl describe vaultrole X` see when each dependency landed.
func TestEmitPolicyResolvedEvents_FiresOnTransition(t *testing.T) {
	recorder := record.NewFakeRecorder(5)
	h := &Handler{recorder: recorder}

	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
	}
	adapter := domain.NewVaultRoleAdapter(role)

	previous := []vaultv1alpha1.PolicyBinding{
		{K8sRef: "VaultPolicy/ns/a", VaultPolicyPath: "ns-a", Resolved: false},
		{K8sRef: "VaultPolicy/ns/b", VaultPolicyPath: "ns-b", Resolved: true},
	}
	current := []vaultv1alpha1.PolicyBinding{
		{K8sRef: "VaultPolicy/ns/a", VaultPolicyPath: "ns-a", Resolved: true},
		{K8sRef: "VaultPolicy/ns/b", VaultPolicyPath: "ns-b", Resolved: true},
	}

	h.emitPolicyResolvedEvents(adapter, previous, current)

	events := collectRecorderEvents(recorder)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d: %v", len(events), events)
	}
	if !strings.Contains(events[0], "PolicyResolved") {
		t.Errorf("event missing PolicyResolved reason: %q", events[0])
	}
	if !strings.Contains(events[0], "VaultPolicy/ns/a") {
		t.Errorf("event missing K8sRef: %q", events[0])
	}
	if !strings.Contains(events[0], "ns-a") {
		t.Errorf("event missing Vault policy path: %q", events[0])
	}
}

// TestEmitPolicyResolvedEvents_NoEventWhenUnchanged pins that a binding
// still-resolved between reconciles does NOT re-emit — otherwise every
// reconcile would spam duplicate events on a healthy role.
func TestEmitPolicyResolvedEvents_NoEventWhenUnchanged(t *testing.T) {
	recorder := record.NewFakeRecorder(5)
	h := &Handler{recorder: recorder}

	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
	}
	adapter := domain.NewVaultRoleAdapter(role)

	previous := []vaultv1alpha1.PolicyBinding{
		{K8sRef: "VaultPolicy/ns/a", Resolved: true},
	}
	current := []vaultv1alpha1.PolicyBinding{
		{K8sRef: "VaultPolicy/ns/a", Resolved: true},
	}

	h.emitPolicyResolvedEvents(adapter, previous, current)

	events := collectRecorderEvents(recorder)
	if len(events) != 0 {
		t.Errorf("expected 0 events for steady-state, got %d: %v", len(events), events)
	}
}

// TestEmitPolicyResolvedEvents_FreshBindingAlreadyResolved covers the
// first-reconcile case: no previous bindings, current binding is already
// resolved (policy existed before role was created). Should fire — this
// is the first time the user sees this binding at all.
func TestEmitPolicyResolvedEvents_FreshBindingAlreadyResolved(t *testing.T) {
	recorder := record.NewFakeRecorder(5)
	h := &Handler{recorder: recorder}

	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
	}
	adapter := domain.NewVaultRoleAdapter(role)

	var previous []vaultv1alpha1.PolicyBinding // nil — first reconcile
	current := []vaultv1alpha1.PolicyBinding{
		{K8sRef: "VaultPolicy/ns/a", VaultPolicyPath: "ns-a", Resolved: true},
	}

	h.emitPolicyResolvedEvents(adapter, previous, current)

	events := collectRecorderEvents(recorder)
	if len(events) != 1 {
		t.Fatalf("expected 1 event for fresh-resolved binding, got %d", len(events))
	}
}

// TestEmitPolicyResolvedEvents_NoRecorderIsNoOp: if the handler was
// constructed without a recorder (some test codepaths), the function
// must not panic and should silently skip.
func TestEmitPolicyResolvedEvents_NoRecorderIsNoOp(t *testing.T) {
	h := &Handler{recorder: nil}

	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
	}
	adapter := domain.NewVaultRoleAdapter(role)

	// Would panic on recorder.Eventf if guard missing.
	h.emitPolicyResolvedEvents(
		adapter,
		nil,
		[]vaultv1alpha1.PolicyBinding{
			{K8sRef: "VaultPolicy/ns/a", Resolved: true},
		},
	)
}

// TestEmitPolicyResolvedEvents_OnlyFiresOnNewlyResolved pins that bindings
// that remained unresolved across reconciles do NOT fire (no event for
// still-not-found policies — user gets the usual "PolicyNotFound" warning
// event from the existing validation path instead).
func TestEmitPolicyResolvedEvents_OnlyFiresOnNewlyResolved(t *testing.T) {
	recorder := record.NewFakeRecorder(5)
	h := &Handler{recorder: recorder}

	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
	}
	adapter := domain.NewVaultRoleAdapter(role)

	previous := []vaultv1alpha1.PolicyBinding{
		{K8sRef: "VaultPolicy/ns/a", Resolved: false},
	}
	current := []vaultv1alpha1.PolicyBinding{
		{K8sRef: "VaultPolicy/ns/a", Resolved: false},
	}

	h.emitPolicyResolvedEvents(adapter, previous, current)

	events := collectRecorderEvents(recorder)
	if len(events) != 0 {
		t.Errorf("expected 0 events for still-unresolved binding, got %d: %v",
			len(events), events)
	}
}
