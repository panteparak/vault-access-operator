/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
)

func newSchemeForUsedByRoles() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(s)
	return s
}

// TestComputeUsedByRoles_DiscoversBothRoleKinds pins IMPROVEMENTS Missing
// Features §B: a single VaultPolicy reconcile finds both namespaced
// VaultRoles AND cluster-scoped VaultClusterRoles that reference it.
// The result is sorted for deterministic Status output.
func TestComputeUsedByRoles_DiscoversBothRoleKinds(t *testing.T) {
	scheme := newSchemeForUsedByRoles()
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r-a", Namespace: "ns-1"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p1"}, // defaults to ns-1
			},
		},
	}
	clusterRole := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "cr-a"},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p1", Namespace: "ns-1"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(role, clusterRole).Build()

	h := &Handler{client: c}
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns-1"},
	}
	adapter := domain.NewVaultPolicyAdapter(policy)

	refs, truncated := h.computeUsedByRoles(context.Background(), adapter)
	if truncated {
		t.Error("did not expect truncation for 2 roles")
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d: %v", len(refs), refs)
	}
	// Lexicographic sort: VaultClusterRole/cr-a < VaultRole/ns-1/r-a
	if refs[0] != "VaultClusterRole/cr-a" || refs[1] != "VaultRole/ns-1/r-a" {
		t.Errorf("unexpected refs (or order): %v", refs)
	}
}

// TestComputeUsedByRoles_IgnoresNonReferencingRoles pins that roles
// referencing a different policy or different namespace are NOT
// surfaced — Status.UsedByRoles is precise to the policy under reconcile.
func TestComputeUsedByRoles_IgnoresNonReferencingRoles(t *testing.T) {
	scheme := newSchemeForUsedByRoles()
	wantRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "wanted", Namespace: "ns-1"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "target"},
			},
		},
	}
	wrongPolicyRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "wrong-policy", Namespace: "ns-1"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "other"},
			},
		},
	}
	wrongNsRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "wrong-ns", Namespace: "ns-2"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "target"}, // defaults to ns-2 != target's ns-1
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(wantRole, wrongPolicyRole, wrongNsRole).Build()

	h := &Handler{client: c}
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "ns-1"},
	}
	adapter := domain.NewVaultPolicyAdapter(policy)

	refs, _ := h.computeUsedByRoles(context.Background(), adapter)
	if len(refs) != 1 {
		t.Fatalf("expected exactly 1 ref, got %d: %v", len(refs), refs)
	}
	if refs[0] != "VaultRole/ns-1/wanted" {
		t.Errorf("expected VaultRole/ns-1/wanted, got %v", refs)
	}
}

// TestComputeUsedByRoles_TruncatesAtMaxItems pins that an unbounded set
// of references is capped at MaxUsedByRolesInStatus and truncated=true is
// returned, so the policy reconciler can set the matching condition.
func TestComputeUsedByRoles_TruncatesAtMaxItems(t *testing.T) {
	scheme := newSchemeForUsedByRoles()

	overflow := MaxUsedByRolesInStatus + 5
	roles := make([]*vaultv1alpha1.VaultRole, overflow)
	objs := make([]runtime.Object, overflow)
	for i := 0; i < overflow; i++ {
		roles[i] = &vaultv1alpha1.VaultRole{
			ObjectMeta: metav1.ObjectMeta{
				// Use a 0-padded name so lex sort matches numeric expectations.
				Name:      fmt.Sprintf("role-%04d", i),
				Namespace: "ns-1",
			},
			Spec: vaultv1alpha1.VaultRoleSpec{
				Policies: []vaultv1alpha1.PolicyReference{
					{Kind: "VaultPolicy", Name: "shared"},
				},
			},
		}
		objs[i] = roles[i]
	}
	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, o := range objs {
		builder = builder.WithObjects(o.(*vaultv1alpha1.VaultRole))
	}
	c := builder.Build()

	h := &Handler{client: c}
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "ns-1"},
	}
	adapter := domain.NewVaultPolicyAdapter(policy)

	refs, truncated := h.computeUsedByRoles(context.Background(), adapter)
	if !truncated {
		t.Fatal("expected truncation for overflow set")
	}
	if len(refs) != MaxUsedByRolesInStatus {
		t.Errorf("expected exactly %d refs after truncation, got %d",
			MaxUsedByRolesInStatus, len(refs))
	}
}

// TestComputeUsedByRoles_ClusterPolicyMatchesByName pins the
// VaultClusterPolicy code path: refs use namespace="" and only Name
// matters for matching.
func TestComputeUsedByRoles_ClusterPolicyMatchesByName(t *testing.T) {
	scheme := newSchemeForUsedByRoles()
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "any-ns"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultClusterPolicy", Name: "shared-cp"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(role).Build()

	h := &Handler{client: c}
	cp := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-cp"},
	}
	adapter := domain.NewVaultClusterPolicyAdapter(cp)

	refs, _ := h.computeUsedByRoles(context.Background(), adapter)
	if len(refs) != 1 || refs[0] != "VaultRole/any-ns/r" {
		t.Errorf("expected [VaultRole/any-ns/r], got %v", refs)
	}
}

// TestRoleReferencesPolicy_NamespaceDefaulting covers the helper directly
// — empty namespace on a VaultPolicy ref defaults to the role's
// namespace, but VaultClusterPolicy refs ignore namespace entirely.
func TestRoleReferencesPolicy_NamespaceDefaulting(t *testing.T) {
	cases := []struct {
		name          string
		refs          []vaultv1alpha1.PolicyReference
		roleNamespace string
		wantKind      string
		policyName    string
		policyNs      string
		wantMatched   bool
	}{
		{
			name:          "empty ns defaults to role ns",
			refs:          []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p"}},
			roleNamespace: "app",
			wantKind:      "VaultPolicy",
			policyName:    "p",
			policyNs:      "app",
			wantMatched:   true,
		},
		{
			name:          "explicit ns overrides default",
			refs:          []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p", Namespace: "shared"}},
			roleNamespace: "app",
			wantKind:      "VaultPolicy",
			policyName:    "p",
			policyNs:      "shared",
			wantMatched:   true,
		},
		{
			name:          "explicit ns mismatch -> no match",
			refs:          []vaultv1alpha1.PolicyReference{{Kind: "VaultPolicy", Name: "p", Namespace: "other"}},
			roleNamespace: "app",
			wantKind:      "VaultPolicy",
			policyName:    "p",
			policyNs:      "shared",
			wantMatched:   false,
		},
		{
			name:          "VaultClusterPolicy ignores namespace",
			refs:          []vaultv1alpha1.PolicyReference{{Kind: "VaultClusterPolicy", Name: "cp"}},
			roleNamespace: "app",
			wantKind:      "VaultClusterPolicy",
			policyName:    "cp",
			policyNs:      "", // cluster-scoped, no ns
			wantMatched:   true,
		},
		{
			name:          "wrong kind -> no match",
			refs:          []vaultv1alpha1.PolicyReference{{Kind: "VaultClusterPolicy", Name: "p"}},
			roleNamespace: "app",
			wantKind:      "VaultPolicy",
			policyName:    "p",
			policyNs:      "app",
			wantMatched:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := roleReferencesPolicy(tc.refs, tc.roleNamespace, tc.wantKind, tc.policyName, tc.policyNs)
			if got != tc.wantMatched {
				t.Errorf("roleReferencesPolicy = %v, want %v", got, tc.wantMatched)
			}
		})
	}
}

// TestStringSlicesEqual covers the no-op-write skip in refreshUsedByRoles.
func TestStringSlicesEqual(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{}, nil, true},
		{[]string{"a"}, []string{"a"}, true},
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a"}, []string{"b"}, false},
		{[]string{"a", "b"}, []string{"b", "a"}, false}, // order matters (sorted before comparison)
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{"a", "b"}, []string{"a"}, false},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			got := stringSlicesEqual(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("stringSlicesEqual(%v, %v) = %v, want %v",
					tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestRefreshUsedByRoles_PatchesLiveObject simulates the post-sync flow:
// the in-memory adapter's Status.UsedByRoles is empty; refreshUsedByRoles
// should patch the live object with the computed refs.
func TestRefreshUsedByRoles_PatchesLiveObject(t *testing.T) {
	scheme := newSchemeForUsedByRoles()
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
	}
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultPolicy{}).
		WithObjects(policy, role).Build()

	h := &Handler{client: c}
	adapter := domain.NewVaultPolicyAdapter(policy)
	h.refreshUsedByRoles(context.Background(), adapter)

	var got vaultv1alpha1.VaultPolicy
	if err := c.Get(context.Background(),
		client.ObjectKeyFromObject(policy), &got); err != nil {
		t.Fatalf("re-fetch failed: %v", err)
	}
	if len(got.Status.UsedByRoles) != 1 || got.Status.UsedByRoles[0] != "VaultRole/ns/r" {
		t.Errorf("expected Status.UsedByRoles=[VaultRole/ns/r], got %v",
			got.Status.UsedByRoles)
	}
}

// TestRefreshUsedByRoles_NoOpWhenUnchanged: if computed refs match the
// existing status, no patch is sent (avoids reconcile churn).
func TestRefreshUsedByRoles_NoOpWhenUnchanged(t *testing.T) {
	scheme := newSchemeForUsedByRoles()
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Status: vaultv1alpha1.VaultPolicyStatus{
			UsedByRoles: []string{"VaultRole/ns/r"}, // already up-to-date
		},
	}
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultPolicy{}).
		WithObjects(policy, role).Build()

	h := &Handler{client: c}
	adapter := domain.NewVaultPolicyAdapter(policy)
	// Should be a no-op — same membership.
	h.refreshUsedByRoles(context.Background(), adapter)

	var got vaultv1alpha1.VaultPolicy
	if err := c.Get(context.Background(),
		client.ObjectKeyFromObject(policy), &got); err != nil {
		t.Fatalf("re-fetch failed: %v", err)
	}
	if !strings.Contains(strings.Join(got.Status.UsedByRoles, ","), "r") {
		t.Errorf("status was unexpectedly mutated: %v", got.Status.UsedByRoles)
	}
}
