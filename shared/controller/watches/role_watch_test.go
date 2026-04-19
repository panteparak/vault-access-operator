/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package watches

import (
	"context"
	"sort"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// TestPoliciesReferencedByRole_VaultRole_DefaultsNamespace pins
// IMPROVEMENTS Missing Features §B: when a VaultRole references a
// VaultPolicy with no namespace, the role's own namespace is the
// default — matching what the role reconciler does at sync time.
func TestPoliciesReferencedByRole_VaultRole_DefaultsNamespace(t *testing.T) {
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "app"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p1"},                      // defaults to "app"
				{Kind: "VaultPolicy", Name: "p2", Namespace: "shared"}, // explicit override
				{Kind: "VaultClusterPolicy", Name: "cluster-p"},        // wrong kind, skipped
			},
		},
	}

	mapFn := PoliciesReferencedByRole("VaultPolicy")
	got := mapFn(context.Background(), role)
	if len(got) != 2 {
		t.Fatalf("expected 2 requests, got %d: %+v", len(got), got)
	}
	keys := make([]string, len(got))
	for i, r := range got {
		keys[i] = r.Namespace + "/" + r.Name
	}
	sort.Strings(keys)
	if keys[0] != "app/p1" {
		t.Errorf("expected app/p1 (defaulted), got %v", keys)
	}
	if keys[1] != "shared/p2" {
		t.Errorf("expected shared/p2 (explicit), got %v", keys)
	}
}

// TestPoliciesReferencedByRole_VaultRole_KindFilter pins that the kind
// filter selects the right subset — calling with "VaultClusterPolicy"
// returns only the cluster-policy refs, not the namespaced ones.
func TestPoliciesReferencedByRole_VaultRole_KindFilter(t *testing.T) {
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "app"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p1"},
				{Kind: "VaultClusterPolicy", Name: "cp1"},
			},
		},
	}

	mapFn := PoliciesReferencedByRole("VaultClusterPolicy")
	got := mapFn(context.Background(), role)
	if len(got) != 1 {
		t.Fatalf("expected 1 cluster-policy request, got %d", len(got))
	}
	if got[0].Name != "cp1" {
		t.Errorf("expected cp1, got %s", got[0].Name)
	}
	if got[0].Namespace != "" {
		t.Errorf("VaultClusterPolicy refs must have empty namespace, got %q",
			got[0].Namespace)
	}
}

// TestPoliciesReferencedByRole_VaultClusterRole_NoDefaultNamespace
// pins that VaultClusterRole's policy refs MUST carry an explicit
// namespace (the webhook enforces this) — no fallback default.
func TestPoliciesReferencedByRole_VaultClusterRole_NoDefaultNamespace(t *testing.T) {
	cr := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "cr"},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p1", Namespace: "team-a"},
				{Kind: "VaultPolicy", Name: "p2", Namespace: "team-b"},
			},
		},
	}

	mapFn := PoliciesReferencedByRole("VaultPolicy")
	got := mapFn(context.Background(), cr)
	if len(got) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(got))
	}
	keys := make([]string, len(got))
	for i, r := range got {
		keys[i] = r.Namespace + "/" + r.Name
	}
	sort.Strings(keys)
	if keys[0] != "team-a/p1" || keys[1] != "team-b/p2" {
		t.Errorf("expected team-a/p1 and team-b/p2, got %v", keys)
	}
}

// TestPoliciesReferencedByRole_DedupesDuplicateRefs pins that a role
// referencing the same policy twice (legal but pointless) only enqueues
// the policy once.
func TestPoliciesReferencedByRole_DedupesDuplicateRefs(t *testing.T) {
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "app"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p1"},
				{Kind: "VaultPolicy", Name: "p1"},                   // duplicate
				{Kind: "VaultPolicy", Name: "p1", Namespace: "app"}, // explicit-default duplicate
			},
		},
	}

	mapFn := PoliciesReferencedByRole("VaultPolicy")
	got := mapFn(context.Background(), role)
	if len(got) != 1 {
		t.Errorf("expected 1 request after dedup, got %d", len(got))
	}
}

// TestPoliciesReferencedByRole_UnknownObjectIsNoOp pins defensive
// behavior: a watch fired with a non-VaultRole/non-VaultClusterRole
// object (impossible in production but worth pinning) returns nil.
func TestPoliciesReferencedByRole_UnknownObjectIsNoOp(t *testing.T) {
	mapFn := PoliciesReferencedByRole("VaultPolicy")
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
	}
	got := mapFn(context.Background(), policy)
	if got != nil {
		t.Errorf("expected nil for unknown object kind, got %+v", got)
	}
}
