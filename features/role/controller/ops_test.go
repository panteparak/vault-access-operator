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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// These tests verify the discovery-pending annotation guard added to RoleOps
// (IMPROVEMENTS.md §4). Without the guard, a discovery-auto-created VaultRole
// would write its placeholder spec to Vault on first reconcile, unbinding every
// real ServiceAccount on the adopted role.

// emptyRolePayload is a minimal but syntactically-valid Vault role JSON that
// detectRoleDrift can unmarshal without error. Extracted to a constant so the
// single-line response write stays under the linter's line-length budget.
const emptyRolePayload = `{"data":{` +
	`"policies":[],` +
	`"bound_service_account_names":[],` +
	`"bound_service_account_namespaces":[]` +
	`}}`

// roleOpsTestHarness captures hits to write and readback paths. Any request to
// `POST/PUT /v1/auth/{path}/role/{name}` counts as a write; any `GET` to the
// same path counts as a readback attempt. The server also returns a credible
// empty role for read requests so detectRoleDrift can parse the response
// without erroring.
type roleOpsTestHarness struct {
	server   *httptest.Server
	writeHit int32
	readHit  int32
}

func newRoleOpsTestHarness(t *testing.T) *roleOpsTestHarness {
	t.Helper()
	h := &roleOpsTestHarness{}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			if strings.Contains(r.URL.Path, "/auth/") && strings.Contains(r.URL.Path, "/role/") {
				atomic.AddInt32(&h.writeHit, 1)
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			if strings.Contains(r.URL.Path, "/auth/") && strings.Contains(r.URL.Path, "/role/") {
				atomic.AddInt32(&h.readHit, 1)
			}
			// minimal valid role payload so detectRoleDrift's unmarshal succeeds
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(emptyRolePayload))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(h.server.Close)
	return h
}

func (h *roleOpsTestHarness) vaultClient(t *testing.T) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	return c
}

func newRoleAdapterWithAnnotations(annotations map[string]string) domain.RoleAdapter {
	r := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "my-role",
			Namespace:   "default",
			Generation:  1,
			Annotations: annotations,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "conn",
			ServiceAccounts: []string{"placeholder"},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultClusterPolicy", Name: "placeholder"},
			},
		},
	}
	return domain.NewVaultRoleAdapter(r)
}

// TestRoleOps_WriteToVault_SkipsDiscoveryPending is the primary regression test
// for §4: an auto-created VaultRole carrying AnnotationDiscoveryPending=true
// must never issue the PUT that would overwrite the adopted Vault role.
func TestRoleOps_WriteToVault_SkipsDiscoveryPending(t *testing.T) {
	h := newRoleOpsTestHarness(t)
	adapter := newRoleAdapterWithAnnotations(map[string]string{
		vaultv1alpha1.AnnotationDiscoveryPending: vaultv1alpha1.AnnotationValueTrue,
	})
	ops := &RoleOps{
		adapter:   adapter,
		vaultName: "test-vault-name",
		authPath:  vault.DefaultKubernetesAuthPath,
		roleData:  map[string]interface{}{"policies": []string{"p"}},
	}

	if err := ops.WriteToVault(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("WriteToVault with discovery-pending returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.writeHit); got != 0 {
		t.Errorf("expected 0 writes to Vault, got %d", got)
	}
}

// TestRoleOps_WriteToVault_WritesWhenAnnotationCleared is the counter-test:
// once a user removes the discovery-pending annotation, the write must resume.
func TestRoleOps_WriteToVault_WritesWhenAnnotationCleared(t *testing.T) {
	h := newRoleOpsTestHarness(t)
	// no annotations, no discovery-pending
	adapter := newRoleAdapterWithAnnotations(nil)
	ops := &RoleOps{
		adapter:   adapter,
		vaultName: "test-vault-name",
		authPath:  vault.DefaultKubernetesAuthPath,
		roleData:  map[string]interface{}{"policies": []string{"p"}},
	}

	if err := ops.WriteToVault(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("WriteToVault without discovery-pending returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.writeHit); got != 1 {
		t.Errorf("expected 1 write to Vault, got %d", got)
	}
}

// TestRoleOps_ReadbackVerify_SkipsDiscoveryPending ensures that skipping the
// write does not cascade into a ReadbackVerify drift report that would return
// TransientError and loop the reconciler forever.
func TestRoleOps_ReadbackVerify_SkipsDiscoveryPending(t *testing.T) {
	h := newRoleOpsTestHarness(t)
	adapter := newRoleAdapterWithAnnotations(map[string]string{
		vaultv1alpha1.AnnotationDiscoveryPending: vaultv1alpha1.AnnotationValueTrue,
	})
	// No handler needed — the skip check is evaluated before detectRoleDrift.
	ops := &RoleOps{adapter: adapter,
		vaultName: "test-vault-name", authPath: "kubernetes"}

	if err := ops.ReadbackVerify(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("ReadbackVerify with discovery-pending returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.readHit); got != 0 {
		t.Errorf("expected 0 readbacks against Vault, got %d", got)
	}
}

// TestRoleOps_ReadbackVerify_RunsWhenAnnotationCleared is the counter-test:
// without the annotation, ReadbackVerify must invoke detectRoleDrift, which
// means it must hit the role endpoint.
func TestRoleOps_ReadbackVerify_RunsWhenAnnotationCleared(t *testing.T) {
	h := newRoleOpsTestHarness(t)
	adapter := newRoleAdapterWithAnnotations(nil)
	handler := &Handler{} // detectRoleDrift is a method on Handler but relies only on the Vault client
	ops := &RoleOps{
		adapter:   adapter,
		vaultName: "test-vault-name",
		handler:   handler,
		authPath:  vault.DefaultKubernetesAuthPath,
		// roleData empty → drift.Comparator reports no drift because no expected
		// fields are set (CompareValuesIfExpected is a no-op for empty expected).
		roleData: map[string]interface{}{},
	}

	if err := ops.ReadbackVerify(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("ReadbackVerify returned unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(&h.readHit); got != 1 {
		t.Errorf("expected 1 readback against Vault, got %d", got)
	}
}
