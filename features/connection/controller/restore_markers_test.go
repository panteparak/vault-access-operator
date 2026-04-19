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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// markerHarness counts MarkPolicyManaged / MarkRoleManaged invocations
// against a fake Vault HTTP server. The marker writes hit the KV v2
// data path under `secret/data/vault-access-operator/managed/`.
type markerHarness struct {
	server      *httptest.Server
	policyHits  int32
	roleHits    int32
	mu          sync.Mutex
	policyPaths []string
	rolePaths   []string
}

func newMarkerHarness(t *testing.T) *markerHarness {
	t.Helper()
	h := &markerHarness{}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			switch {
			case strings.Contains(path, "/secret/data/vault-access-operator/managed/policies/"):
				atomic.AddInt32(&h.policyHits, 1)
				h.mu.Lock()
				h.policyPaths = append(h.policyPaths, path)
				h.mu.Unlock()
			case strings.Contains(path, "/secret/data/vault-access-operator/managed/roles/"):
				atomic.AddInt32(&h.roleHits, 1)
				h.mu.Lock()
				h.rolePaths = append(h.rolePaths, path)
				h.mu.Unlock()
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			// Vault KV v2 read — return an empty data block so MarkXxxManaged
			// proceeds as if the marker doesn't yet exist.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data":     map[string]interface{}{},
					"metadata": map[string]interface{}{},
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(h.server.Close)
	return h
}

func (h *markerHarness) vaultClient(t *testing.T) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	return c
}

func newRestoreScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(s)
	return s
}

// TestRestoreManagedMarkers_WritesMarkerForEveryDependent pins
// IMPROVEMENTS Missing Features §G: with one VaultConnection annotated
// for restore, the handler walks every dependent CR (both kinds of
// policy + both kinds of role) and writes a managed marker for each.
func TestRestoreManagedMarkers_WritesMarkerForEveryDependent(t *testing.T) {
	scheme := newRestoreScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
	}
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: "c"},
	}
	clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cp"},
		Spec:       vaultv1alpha1.VaultClusterPolicySpec{ConnectionRef: "c"},
	}
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
		Spec:       vaultv1alpha1.VaultRoleSpec{ConnectionRef: "c"},
	}
	clusterRole := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "cr"},
		Spec:       vaultv1alpha1.VaultClusterRoleSpec{ConnectionRef: "c"},
	}

	c := newClientBuilderWithConnectionRefIndex(scheme).
		WithObjects(conn, policy, clusterPolicy, role, clusterRole).Build()

	harness := newMarkerHarness(t)
	h := &Handler{client: c}
	if err := h.restoreManagedMarkers(context.Background(), conn, harness.vaultClient(t)); err != nil {
		t.Fatalf("restoreManagedMarkers: %v", err)
	}

	if got := atomic.LoadInt32(&harness.policyHits); got != 2 {
		t.Errorf("expected 2 policy marker writes (1 namespaced + 1 cluster), got %d", got)
	}
	if got := atomic.LoadInt32(&harness.roleHits); got != 2 {
		t.Errorf("expected 2 role marker writes (1 namespaced + 1 cluster), got %d", got)
	}
}

// TestRestoreManagedMarkers_OnlyTouchesDependentsOfThisConnection pins
// the field-indexed query: a CR pointing at a different connection must
// NOT be re-marked.
func TestRestoreManagedMarkers_OnlyTouchesDependentsOfThisConnection(t *testing.T) {
	scheme := newRestoreScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
	}
	mine := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "mine", Namespace: "ns"},
		Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: "c"},
	}
	other := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "other-conn-policy", Namespace: "ns"},
		Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: "other-conn"},
	}

	c := newClientBuilderWithConnectionRefIndex(scheme).
		WithObjects(conn, mine, other).Build()

	harness := newMarkerHarness(t)
	h := &Handler{client: c}
	if err := h.restoreManagedMarkers(context.Background(), conn, harness.vaultClient(t)); err != nil {
		t.Fatalf("restoreManagedMarkers: %v", err)
	}

	if got := atomic.LoadInt32(&harness.policyHits); got != 1 {
		t.Errorf("expected exactly 1 marker write (only `mine`), got %d", got)
	}
	// Confirm the path identifies `mine`, not `other`.
	harness.mu.Lock()
	defer harness.mu.Unlock()
	if !strings.Contains(harness.policyPaths[0], "ns-mine") {
		t.Errorf("expected marker path for ns-mine, got %s", harness.policyPaths[0])
	}
}

// TestRestoreManagedMarkers_NoOpWhenNoDependents pins that an empty
// dependent list is not an error — no markers to write, no failure.
func TestRestoreManagedMarkers_NoOpWhenNoDependents(t *testing.T) {
	scheme := newRestoreScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "lonely"},
	}
	c := newClientBuilderWithConnectionRefIndex(scheme).
		WithObjects(conn).Build()

	harness := newMarkerHarness(t)
	h := &Handler{client: c}
	if err := h.restoreManagedMarkers(context.Background(), conn, harness.vaultClient(t)); err != nil {
		t.Errorf("expected no error for empty dependent set, got %v", err)
	}
	if got := atomic.LoadInt32(&harness.policyHits) + atomic.LoadInt32(&harness.roleHits); got != 0 {
		t.Errorf("expected 0 marker writes for empty dependent set, got %d", got)
	}
}

// TestRestoreManagedMarkers_PartialFailureContinuesAndReports pins that
// one bad write (e.g. Vault returns 500 for one resource) does NOT halt
// the loop — other resources are still re-marked, and the aggregated
// error names every failure so operators can investigate.
func TestRestoreManagedMarkers_PartialFailureContinuesAndReports(t *testing.T) {
	scheme := newRestoreScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "c"},
	}
	good := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "good", Namespace: "ns"},
		Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: "c"},
	}
	bad := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "explode", Namespace: "ns"},
		Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: "c"},
	}

	c := newClientBuilderWithConnectionRefIndex(scheme).
		WithObjects(conn, good, bad).Build()

	// Custom server: 500 on the `explode` policy marker, 204 elsewhere.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			if strings.Contains(r.URL.Path, "ns-explode") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// KV v2 read — empty data
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{},
			},
		})
	}))
	defer server.Close()

	vc, err := vault.NewClient(vault.ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}

	h := &Handler{client: c}
	err = h.restoreManagedMarkers(context.Background(), conn, vc)
	if err == nil {
		t.Fatal("expected aggregated error reporting the failed marker write")
	}
	if !strings.Contains(err.Error(), "ns/explode") {
		t.Errorf("aggregated error should name the failed resource; got %q", err.Error())
	}
}
