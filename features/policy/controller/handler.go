/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/conflict"
	"github.com/panteparak/vault-access-operator/shared/controller/vaultclient"
	"github.com/panteparak/vault-access-operator/shared/controller/workflow"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// Kind labels for adoption + reconcile metrics. Constants because each label
// is referenced from multiple call sites (policy_reconciler.go,
// clusterpolicy_reconciler.go, this file).
const (
	kindLabelVaultPolicy        = "VaultPolicy"
	kindLabelVaultClusterPolicy = "VaultClusterPolicy"
)

// kindForMetric returns the K8s kind label used in adoption / reconcile metrics.
// VaultPolicy adapter wraps both namespaced + cluster variants; this helper
// keeps the policy-side metric labels consistent without leaking adapter
// internals into the metric call sites.
func kindForMetric(adapter domain.PolicyAdapter) string {
	if adapter.IsNamespaced() {
		return kindLabelVaultPolicy
	}
	return kindLabelVaultClusterPolicy
}

// Handler provides shared policy sync/cleanup logic.
// It works with PolicyAdapter to handle both VaultPolicy and VaultClusterPolicy.
type Handler struct {
	client          client.Client
	clientCache     *vault.ClientCache
	eventBus        *events.EventBus
	recorder        record.EventRecorder
	log             logr.Logger
	syncWorkflow    *workflow.SyncWorkflow
	cleanupWorkflow *workflow.CleanupWorkflow
}

// NewHandler creates a new policy Handler.
func NewHandler(
	c client.Client, cache *vault.ClientCache, bus *events.EventBus,
	log logr.Logger, recorder ...record.EventRecorder,
) *Handler {
	h := &Handler{
		client:      c,
		clientCache: cache,
		eventBus:    bus,
		log:         log,
	}
	if len(recorder) > 0 {
		h.recorder = recorder[0]
	}

	// Build vault client resolver using the shared vaultclient package
	resolver := func(ctx context.Context, connRef, resourceID string) (*vault.Client, error) {
		return vaultclient.Resolve(ctx, c, cache, connRef, resourceID)
	}

	h.syncWorkflow = workflow.NewSyncWorkflow(c, resolver, bus, log, h.recorder)
	h.cleanupWorkflow = workflow.NewCleanupWorkflow(c, cache.Get, bus, log)
	return h
}

// SetCleanupQueue replaces the handler's CleanupWorkflow with one that
// persists failed Vault deletes to the retry queue (IMPROVEMENTS §2).
// Expected to be called from cmd/main.go after NewHandler (and before
// SetupWithManager) — passing nil restores the no-queue workflow. The
// underlying cleanup.Controller drains the queue when a leader is elected.
func (h *Handler) SetCleanupQueue(q workflow.CleanupQueuer) {
	h.cleanupWorkflow = workflow.NewCleanupWorkflowWithQueue(
		h.client, h.clientCache.Get, h.eventBus, q, h.log,
	)
}

// SyncPolicy synchronizes a policy to Vault.
func (h *Handler) SyncPolicy(ctx context.Context, adapter domain.PolicyAdapter) error {
	ops := NewPolicyOps(adapter, h)
	return h.syncWorkflow.Execute(ctx, adapter, ops)
}

// CleanupPolicy removes a policy from Vault.
func (h *Handler) CleanupPolicy(ctx context.Context, adapter domain.PolicyAdapter) error {
	ops := NewPolicyOps(adapter, h)
	return h.cleanupWorkflow.Execute(ctx, adapter, ops)
}

// --- Helper methods used by PolicyOps ---

// validateNamespaceBoundary validates that paths contain namespace variable.
func (h *Handler) validateNamespaceBoundary(adapter domain.PolicyAdapter) error {
	for i, rule := range adapter.GetRules() {
		if !vault.ContainsNamespaceVariable(rule.Path) {
			return infraerrors.NewValidationError(
				fmt.Sprintf("rules[%d].path", i),
				rule.Path,
				"must contain {{namespace}} variable when enforceNamespaceBoundary is enabled",
			)
		}

		if vault.HasWildcardBeforeNamespace(rule.Path) {
			return infraerrors.NewValidationError(
				fmt.Sprintf("rules[%d].path", i),
				rule.Path,
				"has wildcard (*) before {{namespace}} variable, which could allow cross-namespace access",
			)
		}
	}
	return nil
}

// checkConflict checks for conflicts with existing Vault policies.
// Supports adoption via annotation (vault.platform.io/adopt: "true") or ConflictPolicy.
func (h *Handler) checkConflict(
	ctx context.Context,
	vaultClient *vault.Client,
	adapter domain.PolicyAdapter,
	vaultPolicyName string,
) error {
	log := logr.FromContextOrDiscard(ctx)

	exists, err := vaultClient.PolicyExists(ctx, vaultPolicyName)
	if err != nil {
		return infraerrors.NewTransientError("check policy existence", err)
	}

	if !exists {
		return nil
	}

	// Policy exists, check ownership
	managedBy, err := vaultClient.GetPolicyManagedBy(ctx, vaultPolicyName)
	if err != nil {
		// Can't determine ownership - check if adoption is allowed
		if h.shouldAdopt(adapter) {
			log.Info("adopting policy (ownership unknown)", "policyName", vaultPolicyName)
			metrics.IncrementAdoption(kindForMetric(adapter), adapter.GetNamespace(), true)
			return nil
		}
		return infraerrors.NewTransientError("check policy ownership", err)
	}

	k8sResource := adapter.GetK8sResourceIdentifier()

	// Same owner, no conflict
	if managedBy == k8sResource {
		return nil
	}

	// Different owner - cannot adopt
	if managedBy != "" {
		log.Info("WARN: policy already managed by another resource, adoption blocked",
			"policyName", vaultPolicyName,
			"managedBy", managedBy,
			"currentResource", k8sResource)
		return infraerrors.NewConflictError("policy", vaultPolicyName, fmt.Sprintf("already managed by %s", managedBy))
	}

	// Exists but not managed - check if adoption is allowed
	if h.shouldAdopt(adapter) {
		log.Info("adopting existing Vault policy", "policyName", vaultPolicyName)
		metrics.IncrementAdoption(kindForMetric(adapter), adapter.GetNamespace(), true)
		return nil
	}

	return infraerrors.NewConflictError(
		"policy", vaultPolicyName,
		"already exists in Vault and is not managed by this operator",
	)
}

// shouldAdopt delegates to the shared conflict.ShouldAdopt helper
// (IMPROVEMENTS §13). Kept as a thin method for call-site readability.
func (h *Handler) shouldAdopt(adapter domain.PolicyAdapter) bool {
	return conflict.ShouldAdopt(adapter)
}

// generatePolicyHCL generates HCL for the policy rules.
func (h *Handler) generatePolicyHCL(rules []vaultv1alpha1.PolicyRule, namespace, name string) string {
	vaultRules := make([]vault.PolicyRule, len(rules))

	for i, rule := range rules {
		caps := make([]string, len(rule.Capabilities))
		for j, cap := range rule.Capabilities {
			caps[j] = string(cap)
		}

		vaultRule := vault.PolicyRule{
			Path:         rule.Path,
			Capabilities: caps,
		}

		if rule.Parameters != nil {
			vaultRule.Parameters = &vault.PolicyParameters{
				Allowed:  rule.Parameters.Allowed,
				Denied:   rule.Parameters.Denied,
				Required: rule.Parameters.Required,
			}
		}

		vaultRules[i] = vaultRule
	}

	return vault.GeneratePolicyHCL(vaultRules, namespace, name)
}

// buildRuleDescriptions builds a map of resolved path -> description for rules that have descriptions.
func (h *Handler) buildRuleDescriptions(rules []vaultv1alpha1.PolicyRule, namespace, name string) map[string]string {
	descs := make(map[string]string)
	for _, rule := range rules {
		if rule.Description != "" {
			resolvedPath := vault.SubstituteVariables(rule.Path, namespace, name)
			descs[resolvedPath] = rule.Description
		}
	}
	if len(descs) == 0 {
		return nil
	}
	return descs
}

// calculateHash calculates SHA256 hash of content.
func (h *Handler) calculateHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// normalizeHCL normalizes HCL for drift comparison (IMPROVEMENTS §17).
// Previously this only trimmed per-line whitespace, so any comment added by
// a human in Vault (`# edited by ops on 2026-01-02`) or trailing whitespace
// divergence from generated HCL tripped drift on every reconcile.
//
// Current normalization:
//   - Strip line comments: `#...` and `//...`
//   - Strip block comments: `/* ... */` (non-nested — sufficient for policy HCL)
//   - Collapse runs of whitespace within a line to a single space
//   - Drop empty lines and lines that are pure whitespace
//
// What this does NOT normalize (deferred to a future fix that would pull in
// `github.com/hashicorp/hcl/v2` for a full AST walk):
//   - Rule reordering (two semantically identical policies with `path`
//     blocks in different order would still drift-compare unequal).
//   - Capability-list reordering within a rule.
//   - Quoting style (single vs double quotes — Vault emits double quotes
//     consistently, so this is already de-facto canonical).
//
// Those residual false positives are manageable: spec rules come through the
// `GeneratePolicyHCL` codepath which emits a deterministic textual form.
func (h *Handler) normalizeHCL(hcl string) string {
	hcl = stripBlockComments(hcl)
	lines := strings.Split(hcl, "\n")
	normalized := make([]string, 0, len(lines))
	for _, line := range lines {
		line = stripLineComment(line)
		line = collapseWhitespace(line)
		if line != "" {
			normalized = append(normalized, line)
		}
	}
	return strings.Join(normalized, "\n")
}

// stripBlockComments removes /* ... */ comment spans. Non-nested only —
// Vault policy HCL doesn't nest block comments in practice.
//
// IMPORTANT caveat: `/*` can legitimately appear inside a quoted path glob
// (e.g., `path "secret/*"`). This helper only strips a block when BOTH `/*`
// and a matching `*/` are present in the input. An unmatched `/*` is left
// alone so a path pattern like `secret/*` is not truncated. Perfect
// quote-aware parsing would need the full HCL tokenizer; this heuristic
// catches the user-reported pain (actual `/* ... */` comments) without the
// false-positive on paths.
func stripBlockComments(s string) string {
	for {
		start := strings.Index(s, "/*")
		if start == -1 {
			return s
		}
		end := strings.Index(s[start:], "*/")
		if end == -1 {
			// No closing `*/` — treat this `/*` as NOT a comment (it's
			// almost certainly part of a path glob like `secret/*`).
			return s
		}
		s = s[:start] + s[start+end+2:]
	}
}

// stripLineComment removes an end-of-line `#...` or `//...` comment, preserving
// the portion before the marker. Quoting is not parsed — HCL policy syntax
// doesn't put `#` or `//` inside strings in practice for our generated paths,
// so this is a safe heuristic.
func stripLineComment(line string) string {
	for i := 0; i < len(line)-1; i++ {
		if line[i] == '#' {
			return strings.TrimRight(line[:i], " \t")
		}
		if line[i] == '/' && line[i+1] == '/' {
			return strings.TrimRight(line[:i], " \t")
		}
	}
	if strings.HasSuffix(line, "#") {
		return strings.TrimRight(line[:len(line)-1], " \t")
	}
	return strings.TrimSpace(line)
}

// collapseWhitespace replaces runs of spaces/tabs with a single space and
// trims leading/trailing whitespace. Only touches horizontal whitespace;
// caller handles newlines by splitting before calling.
func collapseWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inWS := false
	started := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			inWS = true
			continue
		}
		if inWS && started {
			b.WriteByte(' ')
		}
		b.WriteByte(c)
		inWS = false
		started = true
	}
	return b.String()
}
