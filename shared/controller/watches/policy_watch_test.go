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
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// TestRoleRequestsForPolicy pins IMPROVEMENTS §27: when a VaultPolicy is
// created, the role reconciler watches only roles with an UNRESOLVED
// PolicyBinding referencing that policy. Roles that already resolved it
// (or never referenced it) are NOT enqueued — we don't want a policy
// create to storm every role in the cluster.
func TestRoleRequestsForPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	// Three roles exist in the cluster:
	// - waitingRole: unresolved binding to "my-policy" in ns "app"
	// - resolvedRole: already resolved binding to "my-policy" in ns "app"
	// - unrelatedRole: no reference to "my-policy"
	waitingRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "waiting", Namespace: "app"},
		Status: vaultv1alpha1.VaultRoleStatus{
			PolicyBindings: []vaultv1alpha1.PolicyBinding{
				{K8sRef: "VaultPolicy/app/my-policy", Resolved: false},
			},
		},
	}
	resolvedRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "resolved", Namespace: "app"},
		Status: vaultv1alpha1.VaultRoleStatus{
			PolicyBindings: []vaultv1alpha1.PolicyBinding{
				{K8sRef: "VaultPolicy/app/my-policy", Resolved: true},
			},
		},
	}
	unrelatedRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "app"},
		Status: vaultv1alpha1.VaultRoleStatus{
			PolicyBindings: []vaultv1alpha1.PolicyBinding{
				{K8sRef: "VaultPolicy/other/some-policy", Resolved: false},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(waitingRole, resolvedRole, unrelatedRole).
		Build()

	// Simulate the policy-created event by building the triggering object
	// the same way controller-runtime would pass it to the MapFunc.
	triggeringPolicy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "my-policy", Namespace: "app"},
	}

	mapFn := RoleRequestsForPolicy(c)
	requests := mapFn(context.Background(), triggeringPolicy)

	names := make([]string, 0, len(requests))
	for _, r := range requests {
		names = append(names, r.Namespace+"/"+r.Name)
	}
	sort.Strings(names)

	if len(names) != 1 || names[0] != "app/waiting" {
		t.Errorf("expected reconcile only for waiting role, got %v", names)
	}
}

// TestClusterRoleRequestsForPolicy mirrors the above for cluster-scoped roles.
func TestClusterRoleRequestsForPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	// Cluster role with an unresolved binding to a cluster policy.
	waitingCR := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "waiting-cr"},
		Status: vaultv1alpha1.VaultClusterRoleStatus{
			PolicyBindings: []vaultv1alpha1.PolicyBinding{
				{K8sRef: "VaultClusterPolicy/shared-policy", Resolved: false},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waitingCR).Build()

	triggeringClusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-policy"},
	}

	mapFn := ClusterRoleRequestsForPolicy(c)
	requests := mapFn(context.Background(), triggeringClusterPolicy)

	if len(requests) != 1 || requests[0].Name != "waiting-cr" {
		t.Errorf("expected reconcile only for waiting-cr, got %+v", requests)
	}
}

// TestPolicyCreatedOrUpdatedPredicate pins that Delete events are NOT
// enqueued — a policy delete should flow through the role's next scheduled
// reconcile, which re-runs PolicyExists and flips the PoliciesResolved
// condition.
func TestPolicyCreatedOrUpdatedPredicate(t *testing.T) {
	if !PolicyCreatedOrUpdatedPredicate.Create(event.CreateEvent{}) {
		t.Error("Create should enqueue")
	}
	if !PolicyCreatedOrUpdatedPredicate.Update(event.UpdateEvent{}) {
		t.Error("Update should enqueue")
	}
	if PolicyCreatedOrUpdatedPredicate.Delete(event.DeleteEvent{}) {
		t.Error("Delete should NOT enqueue — handled by next scheduled reconcile")
	}
	if PolicyCreatedOrUpdatedPredicate.Generic(event.GenericEvent{}) {
		t.Error("Generic should NOT enqueue")
	}
}
