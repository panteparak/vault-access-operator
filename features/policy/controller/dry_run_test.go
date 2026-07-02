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
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// dryRunHarness gives counters for write/delete attempts so we can pin
// "no Vault write happens when dry-run is set". Reuses the existing
// ops_test.go pattern but adds a delete counter.
type dryRunHarness struct {
	server     *httptest.Server
	writeHit   int32
	deleteHit  int32
	managedHit int32
}

func newDryRunHarness(t *testing.T) *dryRunHarness {
	t.Helper()
	h := &dryRunHarness{}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			switch {
			case strings.Contains(path, "/sys/policies/acl/"):
				atomic.AddInt32(&h.writeHit, 1)
			case strings.Contains(path, "/secret/data/vault-access-operator/managed/"):
				atomic.AddInt32(&h.managedHit, 1)
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if strings.Contains(path, "/sys/policies/acl/") {
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

func newDryRunPolicy(annotations map[string]string) domain.PolicyAdapter {
	p := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "p",
			Namespace:   "ns",
			Generation:  1,
			Annotations: annotations,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "conn",
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/data/foo", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
			},
		},
	}
	return domain.NewVaultPolicyAdapter(p)
}

// TestPolicyOps_WriteToVault_SkipsDryRun pins IMPROVEMENTS Missing
// Features §I: a policy carrying `vault.platform.io/dry-run=true`
// must NOT issue a Vault write. The would-be HCL stays in o.hcl
// for the workflow to surface in status.
func TestPolicyOps_WriteToVault_SkipsDryRun(t *testing.T) {
	h := newDryRunHarness(t)
	adapter := newDryRunPolicy(map[string]string{
		vaultv1alpha1.AnnotationDryRun: vaultv1alpha1.AnnotationValueTrue,
	})
	c, err := vault.NewClient(vault.ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}

	ops := &PolicyOps{
		adapter: adapter,
		hcl:     `path "ours" { capabilities = ["read"] }`,
	}
	if err := ops.WriteToVault(context.Background(), c); err != nil {
		t.Fatalf("WriteToVault returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.writeHit); got != 0 {
		t.Errorf("expected 0 Vault writes under dry-run, got %d", got)
	}
}

// TestPolicyOps_DeleteFromVault_SkipsDryRun pins that a delete on a
// dry-run policy is also skipped — useful for previewing "what would
// happen if I removed this CR?" without committing.
func TestPolicyOps_DeleteFromVault_SkipsDryRun(t *testing.T) {
	h := newDryRunHarness(t)
	adapter := newDryRunPolicy(map[string]string{
		vaultv1alpha1.AnnotationDryRun: vaultv1alpha1.AnnotationValueTrue,
	})
	c, err := vault.NewClient(vault.ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}

	ops := &PolicyOps{adapter: adapter}
	if err := ops.DeleteFromVault(context.Background(), c); err != nil {
		t.Fatalf("DeleteFromVault returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.deleteHit); got != 0 {
		t.Errorf("expected 0 Vault deletes under dry-run, got %d", got)
	}
}

// (TestPolicyOps_MarkManaged_SkipsDryRun removed with the marker mechanism —
// ownership now travels inside the policy document itself (ADR 0008), so
// dry-run's WriteToVault skip already covers it.)

// TestPolicyOps_WriteToVault_NormalWhenAnnotationAbsent: positive control
// — without the annotation, the write goes through.
func TestPolicyOps_WriteToVault_NormalWhenAnnotationAbsent(t *testing.T) {
	h := newDryRunHarness(t)
	adapter := newDryRunPolicy(nil) // no annotations
	c, err := vault.NewClient(vault.ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}

	ops := &PolicyOps{
		adapter: adapter,
		hcl:     `path "ours" { capabilities = ["read"] }`,
	}
	if err := ops.WriteToVault(context.Background(), c); err != nil {
		t.Fatalf("WriteToVault returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.writeHit); got != 1 {
		t.Errorf("expected 1 Vault write without dry-run, got %d", got)
	}
}

// TestPolicyOps_WriteToVault_DryRunFalsyValueWrites pins that the guard
// is strict equality with "true" — a value of "false" or "0" doesn't
// suppress the write. Avoids confusing UX where the user thinks they
// disabled dry-run by setting it to false.
func TestPolicyOps_WriteToVault_DryRunFalsyValueWrites(t *testing.T) {
	h := newDryRunHarness(t)
	adapter := newDryRunPolicy(map[string]string{
		vaultv1alpha1.AnnotationDryRun: "false",
	})
	c, err := vault.NewClient(vault.ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}

	ops := &PolicyOps{
		adapter: adapter,
		hcl:     `path "ours" { capabilities = ["read"] }`,
	}
	if err := ops.WriteToVault(context.Background(), c); err != nil {
		t.Fatalf("WriteToVault returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.writeHit); got != 1 {
		t.Errorf("`dry-run=false` should be treated as dry-run OFF (write should occur), got %d writes",
			got)
	}
}

// (TestIsDryRun moved to shared/controller/dryrun/dryrun_test.go after the
// helper was lifted into a shared package — the per-feature integration
// tests above still pin the per-op behavior end-to-end.)
