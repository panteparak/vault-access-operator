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

type roleDryRunHarness struct {
	server     *httptest.Server
	writeHit   int32
	deleteHit  int32
	managedHit int32
}

func newRoleDryRunHarness(t *testing.T) *roleDryRunHarness {
	t.Helper()
	h := &roleDryRunHarness{}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			switch {
			case strings.Contains(path, "/auth/") && strings.Contains(path, "/role/"):
				atomic.AddInt32(&h.writeHit, 1)
			case strings.Contains(path, "/secret/metadata/vault-access-operator/managed/"):
				atomic.AddInt32(&h.managedHit, 1)
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if strings.Contains(path, "/auth/") && strings.Contains(path, "/role/") {
				atomic.AddInt32(&h.deleteHit, 1)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(h.server.Close)
	return h
}

func (h *roleDryRunHarness) vaultClient(t *testing.T) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	return c
}

func newDryRunRoleAdapter(annotations map[string]string) domain.RoleAdapter {
	r := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "r",
			Namespace:   "ns",
			Generation:  1,
			Annotations: annotations,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "conn",
			ServiceAccounts: []string{"sa-1"},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "p1"},
			},
		},
	}
	return domain.NewVaultRoleAdapter(r)
}

// TestRoleOps_WriteToVault_SkipsDryRun pins IMPROVEMENTS Missing
// Features §I: a role carrying `vault.platform.io/dry-run=true` must
// NOT write to Vault. The would-be role data stays in o.roleData for
// the workflow to surface in the DryRun status condition.
func TestRoleOps_WriteToVault_SkipsDryRun(t *testing.T) {
	h := newRoleDryRunHarness(t)
	adapter := newDryRunRoleAdapter(map[string]string{
		vaultv1alpha1.AnnotationDryRun: vaultv1alpha1.AnnotationValueTrue,
	})

	ops := &RoleOps{
		adapter:  adapter,
		authPath: "auth/kubernetes",
		roleData: map[string]interface{}{
			"bound_service_account_names":      []string{"sa-1"},
			"bound_service_account_namespaces": []string{"ns"},
			"policies":                         []string{"p1"},
		},
	}
	if err := ops.WriteToVault(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("WriteToVault returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.writeHit); got != 0 {
		t.Errorf("expected 0 Vault role writes under dry-run, got %d", got)
	}
}

// TestRoleOps_DeleteFromVault_SkipsDryRun pins delete-side dry-run.
func TestRoleOps_DeleteFromVault_SkipsDryRun(t *testing.T) {
	h := newRoleDryRunHarness(t)
	adapter := newDryRunRoleAdapter(map[string]string{
		vaultv1alpha1.AnnotationDryRun: vaultv1alpha1.AnnotationValueTrue,
	})

	ops := &RoleOps{adapter: adapter, authPath: "auth/kubernetes"}
	if err := ops.DeleteFromVault(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("DeleteFromVault returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.deleteHit); got != 0 {
		t.Errorf("expected 0 Vault role deletes under dry-run, got %d", got)
	}
}

// TestRoleOps_WriteToVault_NormalWhenAnnotationAbsent: positive control
// that the guard isn't accidentally always-on.
func TestRoleOps_WriteToVault_NormalWhenAnnotationAbsent(t *testing.T) {
	h := newRoleDryRunHarness(t)
	adapter := newDryRunRoleAdapter(nil)

	ops := &RoleOps{
		adapter:  adapter,
		authPath: "auth/kubernetes",
		roleData: map[string]interface{}{
			"bound_service_account_names":      []string{"sa-1"},
			"bound_service_account_namespaces": []string{"ns"},
			"policies":                         []string{"p1"},
		},
	}
	if err := ops.WriteToVault(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("WriteToVault returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.writeHit); got != 1 {
		t.Errorf("expected 1 Vault role write without dry-run, got %d", got)
	}
}
