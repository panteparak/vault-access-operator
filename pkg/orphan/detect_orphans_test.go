/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package orphan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// vaultManagedHarness builds an httptest server that serves Vault KV v2
// metadata + data responses for the managed-marker tree. Used to drive
// the production `detectOrphanedPolicies` / `detectOrphanedRoles` paths
// against a real *vault.Client (instead of duplicating their logic in
// `*WithMock` test helpers).
//
// The harness understands the path layout used by `pkg/vault.listManaged`:
//   - LIST: GET secret/metadata/vault-access-operator/managed/{policies,roles}/?list=true
//   - GET:  GET secret/data/vault-access-operator/managed/{policies,roles}/<name>
//
// Add an entry to .policies / .roles before starting; the server returns
// keys for LIST and JSON ManagedResource bodies for GET.
type vaultManagedHarness struct {
	policies map[string]vault.ManagedResource
	roles    map[string]vault.ManagedResource
	server   *httptest.Server
}

func newVaultManagedHarness(t *testing.T) *vaultManagedHarness {
	t.Helper()
	h := &vaultManagedHarness{
		policies: map[string]vault.ManagedResource{},
		roles:    map[string]vault.ManagedResource{},
	}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// Vault SDK's ListWithContext sends GET with ?list=true.
		isList := r.URL.Query().Get("list") == "true"

		// Determine which managed map we're servicing from the path.
		var sourceMap map[string]vault.ManagedResource
		switch {
		case strings.Contains(path, "/managed/policies"):
			sourceMap = h.policies
		case strings.Contains(path, "/managed/roles"):
			sourceMap = h.roles
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if isList {
			keys := make([]string, 0, len(sourceMap))
			for k := range sourceMap {
				keys = append(keys, k)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": keys,
				},
			})
			return
		}

		// Single-key GET on the data path: secret/data/.../managed/<type>/<name>
		// Extract the trailing name segment.
		segs := strings.Split(strings.TrimRight(path, "/"), "/")
		if len(segs) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		name := segs[len(segs)-1]
		mr, ok := sourceMap[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// markManaged stores the ManagedResource as a JSON-encoded STRING
		// under the `metadata` key inside the KV v2 data wrapper. getManaged
		// then string-decodes it. Mirror that exact shape so the production
		// path's `data["metadata"].(string)` cast succeeds.
		mrJSON, _ := json.Marshal(mr)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"metadata": string(mrJSON),
				},
				"metadata": map[string]interface{}{},
			},
		})
	}))
	t.Cleanup(h.server.Close)
	return h
}

func (h *vaultManagedHarness) vaultClient(t *testing.T) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	return c
}

func newOrphanScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(s)
	return s
}

func newDetectOrphansController(t *testing.T, k8sObjs ...runtime.Object) *Controller {
	t.Helper()
	scheme := newOrphanScheme()
	objs := make([]runtime.Object, 0, len(k8sObjs))
	objs = append(objs, k8sObjs...)
	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, o := range objs {
		// fake.WithObjects expects client.Object; cast each.
		if co, ok := o.(interface{ DeepCopyObject() runtime.Object }); ok {
			_ = co
		}
	}
	// Use WithRuntimeObjects to accept untyped runtime.Object pointers.
	if len(objs) > 0 {
		builder = builder.WithRuntimeObjects(objs...)
	}
	return &Controller{
		k8sClient:   builder.Build(),
		clientCache: nil,
		interval:    time.Hour,
		log:         logr.Discard(),
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
	}
}

// TestDetectOrphanedPolicies_Production exercises the real
// `detectOrphanedPolicies` (not the mock variant) against a real
// `*vault.Client`. Pin: a managed marker pointing at a non-existent
// VaultPolicy CR is reported as orphan; one pointing at an existing
// CR is not.
func TestDetectOrphanedPolicies_Production(t *testing.T) {
	existing := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "alive", Namespace: "ns"},
	}
	c := newDetectOrphansController(t, existing)
	h := newVaultManagedHarness(t)
	h.policies = map[string]vault.ManagedResource{
		"ns-alive": {K8sResource: "ns/alive"},
		"ns-gone":  {K8sResource: "ns/gone-policy"},
	}

	orphans := c.detectOrphanedPolicies(context.Background(), h.vaultClient(t), "test-conn")

	if len(orphans) != 1 {
		t.Fatalf("expected exactly 1 orphan, got %d: %+v", len(orphans), orphans)
	}
	o := orphans[0]
	if o.VaultName != "ns-gone" {
		t.Errorf("expected VaultName=ns-gone, got %s", o.VaultName)
	}
	if o.K8sResource != "ns/gone-policy" {
		t.Errorf("expected K8sResource=ns/gone-policy, got %s", o.K8sResource)
	}
	if o.ResourceType != ResourceTypePolicy {
		t.Errorf("expected ResourceType=policy, got %s", o.ResourceType)
	}
	if o.ConnectionName != "test-conn" {
		t.Errorf("expected ConnectionName=test-conn, got %s", o.ConnectionName)
	}
}

// TestDetectOrphanedRoles_Production mirrors the policy test for roles.
func TestDetectOrphanedRoles_Production(t *testing.T) {
	existing := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "alive", Namespace: "ns"},
	}
	c := newDetectOrphansController(t, existing)
	h := newVaultManagedHarness(t)
	h.roles = map[string]vault.ManagedResource{
		"ns-alive": {K8sResource: "ns/alive"},
		"ns-gone":  {K8sResource: "ns/gone-role"},
	}

	orphans := c.detectOrphanedRoles(context.Background(), h.vaultClient(t), "test-conn")

	if len(orphans) != 1 {
		t.Fatalf("expected exactly 1 orphan, got %d: %+v", len(orphans), orphans)
	}
	if orphans[0].VaultName != "ns-gone" {
		t.Errorf("expected VaultName=ns-gone, got %s", orphans[0].VaultName)
	}
	if orphans[0].ResourceType != ResourceTypeRole {
		t.Errorf("expected ResourceType=role, got %s", orphans[0].ResourceType)
	}
}

// TestDetectOrphanedPolicies_NoneManaged: empty marker list returns no
// orphans without error — the orphan scanner shouldn't false-positive
// on a cluster with no managed resources.
func TestDetectOrphanedPolicies_NoneManaged(t *testing.T) {
	c := newDetectOrphansController(t)
	h := newVaultManagedHarness(t)
	// h.policies left empty.

	orphans := c.detectOrphanedPolicies(context.Background(), h.vaultClient(t), "conn")
	if len(orphans) != 0 {
		t.Errorf("expected 0 orphans for empty managed list, got %d", len(orphans))
	}
}

// TestDetectOrphanedPolicies_VaultListError: when Vault returns a
// transport error from ListManagedPolicies, the function returns nil
// (logged but non-fatal) so the next scan retries. Pins the swallow-
// and-continue contract.
func TestDetectOrphanedPolicies_VaultListError(t *testing.T) {
	c := newDetectOrphansController(t)

	// Server that 500s on every request.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	vc, err := vault.NewClient(vault.ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}

	orphans := c.detectOrphanedPolicies(context.Background(), vc, "conn")
	if orphans != nil {
		t.Errorf("expected nil orphans on Vault list error, got %+v", orphans)
	}
}

// TestDetectOrphanedPolicies_ClusterScopedResource pins that a
// managed-marker for a cluster-scoped K8s resource (no namespace
// prefix) routes to VaultClusterPolicy lookup, not VaultPolicy.
func TestDetectOrphanedPolicies_ClusterScopedResource(t *testing.T) {
	existing := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "alive-cluster"},
	}
	c := newDetectOrphansController(t, existing)
	h := newVaultManagedHarness(t)
	h.policies = map[string]vault.ManagedResource{
		"alive-cluster": {K8sResource: "alive-cluster"},
		"gone-cluster":  {K8sResource: "gone-cluster"},
	}

	orphans := c.detectOrphanedPolicies(context.Background(), h.vaultClient(t), "conn")
	if len(orphans) != 1 {
		t.Fatalf("expected 1 orphan, got %d", len(orphans))
	}
	if orphans[0].VaultName != "gone-cluster" {
		t.Errorf("expected gone-cluster, got %s", orphans[0].VaultName)
	}
}
