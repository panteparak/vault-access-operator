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

// These tests cover the discovery-pending skip guard on PolicyOps (IMPROVEMENTS.md §4).
// The raw-string check previously at policy/ops.go:108 is now a constant-driven
// comparison; additionally, ReadbackVerify gains the same skip to avoid an
// always-fail TransientError loop once the write is skipped.

type policyOpsTestHarness struct {
	server   *httptest.Server
	writeHit int32
	readHit  int32
}

func newPolicyOpsTestHarness(t *testing.T) *policyOpsTestHarness {
	t.Helper()
	h := &policyOpsTestHarness{}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			if strings.Contains(r.URL.Path, "/sys/policies/acl/") {
				atomic.AddInt32(&h.writeHit, 1)
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			if strings.Contains(r.URL.Path, "/sys/policies/acl/") {
				atomic.AddInt32(&h.readHit, 1)
			}
			w.Header().Set("Content-Type", "application/json")
			// Return placeholder HCL under Vault's `data.policy` key (the Go
			// SDK's GetPolicyWithContext reads from there). The value differs
			// from anything we'd generate — confirms the skip for the write
			// test and seeds the DetectDrift scenario with known-divergent text.
			_, _ = w.Write([]byte(`{"data":{"policy":"path \"different\" { capabilities = [\"read\"] }"}}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(h.server.Close)
	return h
}

func (h *policyOpsTestHarness) vaultClient(t *testing.T) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	return c
}

func newPolicyAdapterWithAnnotations(annotations map[string]string) domain.PolicyAdapter {
	p := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "my-policy",
			Namespace:   "default",
			Generation:  1,
			Annotations: annotations,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "conn",
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/data/placeholder", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
			},
		},
	}
	return domain.NewVaultPolicyAdapter(p)
}

// TestPolicyOps_WriteToVault_SkipsDiscoveryPending: guard already existed via
// raw-string; this test pins the behavior now that it references the constant.
func TestPolicyOps_WriteToVault_SkipsDiscoveryPending(t *testing.T) {
	h := newPolicyOpsTestHarness(t)
	adapter := newPolicyAdapterWithAnnotations(map[string]string{
		vaultv1alpha1.AnnotationDiscoveryPending: vaultv1alpha1.AnnotationValueTrue,
	})
	ops := &PolicyOps{
		adapter:   adapter,
		vaultName: "test-vault-name",
		hcl:       "path \"placeholder\" { capabilities = [\"read\"] }",
	}

	if err := ops.WriteToVault(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("WriteToVault with discovery-pending returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.writeHit); got != 0 {
		t.Errorf("expected 0 writes to Vault, got %d", got)
	}
}

func TestPolicyOps_WriteToVault_WritesWhenAnnotationCleared(t *testing.T) {
	h := newPolicyOpsTestHarness(t)
	adapter := newPolicyAdapterWithAnnotations(nil)
	ops := &PolicyOps{
		adapter:   adapter,
		vaultName: "test-vault-name",
		hcl:       "path \"ok\" { capabilities = [\"read\"] }",
	}

	if err := ops.WriteToVault(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("WriteToVault without discovery-pending returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.writeHit); got != 1 {
		t.Errorf("expected 1 write to Vault, got %d", got)
	}
}

// TestPolicyOps_ReadbackVerify_SkipsDiscoveryPending — new guard. Without it,
// ReadbackVerify would compare the placeholder HCL against the real policy in
// Vault, find a mismatch, and return TransientError every reconcile forever.
func TestPolicyOps_ReadbackVerify_SkipsDiscoveryPending(t *testing.T) {
	h := newPolicyOpsTestHarness(t)
	adapter := newPolicyAdapterWithAnnotations(map[string]string{
		vaultv1alpha1.AnnotationDiscoveryPending: vaultv1alpha1.AnnotationValueTrue,
	})
	ops := &PolicyOps{
		adapter:   adapter,
		vaultName: "test-vault-name",
		hcl:       "path \"placeholder\" { capabilities = [\"read\"] }",
	}

	if err := ops.ReadbackVerify(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("ReadbackVerify with discovery-pending returned error: %v", err)
	}
	if got := atomic.LoadInt32(&h.readHit); got != 0 {
		t.Errorf("expected 0 readbacks against Vault, got %d", got)
	}
}

// TestPolicyOps_ReadbackVerify_RunsWhenAnnotationCleared: without the annotation,
// the normal mismatch-detection path fires.
func TestPolicyOps_ReadbackVerify_RunsWhenAnnotationCleared(t *testing.T) {
	h := newPolicyOpsTestHarness(t)
	adapter := newPolicyAdapterWithAnnotations(nil)
	// Use a Handler so normalizeHCL works. We set hcl to match what the harness
	// returns to avoid a TransientError.
	handler := &Handler{}
	ops := &PolicyOps{
		adapter:   adapter,
		vaultName: "test-vault-name",
		handler:   handler,
		hcl:       `path "different" { capabilities = ["read"] }`,
	}

	if err := ops.ReadbackVerify(context.Background(), h.vaultClient(t)); err != nil {
		t.Fatalf("ReadbackVerify returned unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(&h.readHit); got != 1 {
		t.Errorf("expected 1 readback against Vault, got %d", got)
	}
}

// TestPolicyOps_DetectDrift_ProducesDiffPreview verifies IMPROVEMENTS §11:
// when Vault returns HCL different from what we expect, the drift summary
// now includes line-level +/- markers (field "rules"), not just the legacy
// "policy content differs". Operators reading the PolicyDrifted condition
// see what changed without manually diffing.
func TestPolicyOps_DetectDrift_ProducesDiffPreview(t *testing.T) {
	h := newPolicyOpsTestHarness(t)
	adapter := newPolicyAdapterWithAnnotations(nil)
	// Harness returns `path "different" { capabilities = ["read"] }` on GET.
	// Our expected HCL differs in both path and capabilities so the summary
	// preview exercises both `-` (Vault side) and `+` (expected side) markers.
	ops := &PolicyOps{
		adapter:   adapter,
		vaultName: "test-vault-name",
		handler:   &Handler{},
		hcl:       `path "ours" { capabilities = ["list"] }`,
	}

	drifted, summary := ops.DetectDrift(context.Background(), h.vaultClient(t))
	if !drifted {
		t.Fatalf("expected drift; got none (summary=%q)", summary)
	}
	if !strings.Contains(summary, "fields differ: rules") {
		t.Errorf("summary should include field label; got:\n%s", summary)
	}
	if !strings.Contains(summary, `- path "different"`) {
		t.Errorf("summary should include `-` preview of Vault side; got:\n%s", summary)
	}
	if !strings.Contains(summary, `+ path "ours"`) {
		t.Errorf("summary should include `+` preview of expected side; got:\n%s", summary)
	}
}

// TestPolicyOps_DetectDrift_NoDriftOnMatch: if normalized HCL matches, no
// drift and no summary — keeps the happy path unchanged by §11.
func TestPolicyOps_DetectDrift_NoDriftOnMatch(t *testing.T) {
	h := newPolicyOpsTestHarness(t)
	adapter := newPolicyAdapterWithAnnotations(nil)
	ops := &PolicyOps{
		adapter:   adapter,
		vaultName: "test-vault-name",
		handler:   &Handler{},
		// Match what the harness returns so normalizeHCL produces the same text.
		hcl: `path "different" { capabilities = ["read"] }`,
	}

	drifted, summary := ops.DetectDrift(context.Background(), h.vaultClient(t))
	if drifted {
		t.Errorf("expected no drift for matching HCL; got summary=%q", summary)
	}
	if summary != "" {
		t.Errorf("expected empty summary on match; got %q", summary)
	}
}
