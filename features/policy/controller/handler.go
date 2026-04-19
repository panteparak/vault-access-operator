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
	"sort"
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

// MaxUsedByRolesInStatus caps the number of role refs surfaced in
// `Status.UsedByRoles` (IMPROVEMENTS §B). Mirrors the schema's
// MaxItems=200 to prevent etcd object size blow-up when one shared
// policy is referenced by thousands of roles. Overflow is signalled via
// the `UsedByRolesTruncated` condition.
const MaxUsedByRolesInStatus = 200

// ConditionTypeUsedByRolesTruncated marks that the policy is referenced
// by more roles than fit in the bounded Status.UsedByRoles list.
// Operators inspecting the policy see Status.UsedByRoles is incomplete
// and can list roles via field indexer for the full picture.
const ConditionTypeUsedByRolesTruncated = "UsedByRolesTruncated"

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

// SyncPolicy synchronizes a policy to Vault. After a successful sync,
// recomputes the reverse policy→role index (Status.UsedByRoles) via an
// additional status patch — this is independent of the main sync state
// transition, so a failure here is logged but doesn't fail the whole
// reconcile. IMPROVEMENTS Missing Features §B.
func (h *Handler) SyncPolicy(ctx context.Context, adapter domain.PolicyAdapter) error {
	ops := NewPolicyOps(adapter, h)
	if err := h.syncWorkflow.Execute(ctx, adapter, ops); err != nil {
		return err
	}
	h.refreshUsedByRoles(ctx, adapter)
	return nil
}

// refreshUsedByRoles patches Status.UsedByRoles with the current set of
// roles that reference this policy. Independent of the sync workflow's
// status update so it doesn't widen the workflow's transactional surface.
// Logs and swallows errors — the next reconcile will retry.
func (h *Handler) refreshUsedByRoles(ctx context.Context, adapter domain.PolicyAdapter) {
	log := logr.FromContextOrDiscard(ctx)
	refs, _ := h.computeUsedByRoles(ctx, adapter)

	current := adapter.GetUsedByRoles()
	if stringSlicesEqual(current, refs) {
		return // No change — skip the API write to avoid useless reconcile churn.
	}

	// Re-fetch the live object to avoid a stale-resourceVersion conflict
	// — the workflow's own Status().Update() runs immediately before this
	// helper, so the in-memory adapter is one revision behind.
	live := adapter.GetObject()
	key := client.ObjectKeyFromObject(live)
	if err := h.client.Get(ctx, key, live); err != nil {
		log.V(1).Info("failed to re-fetch policy for usedByRoles patch (non-fatal)",
			"error", err.Error())
		return
	}

	original := live.DeepCopyObject().(client.Object)
	// Re-bind the adapter to the freshly-fetched object so SetUsedByRoles
	// writes into the right Status.
	switch p := live.(type) {
	case *vaultv1alpha1.VaultPolicy:
		p.Status.UsedByRoles = refs
	case *vaultv1alpha1.VaultClusterPolicy:
		p.Status.UsedByRoles = refs
	default:
		return
	}

	if err := h.client.Status().Patch(ctx, live, client.MergeFrom(original)); err != nil {
		log.V(1).Info("failed to patch usedByRoles (non-fatal)", "error", err.Error())
	}
}

// stringSlicesEqual returns true if a and b have the same length and
// the same elements in the same order. Used to skip no-op status writes.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// computeUsedByRoles walks every VaultRole and VaultClusterRole in the
// cluster, collecting the K8s resource identifier of each one whose
// spec.policies references this policy. Used by ApplyActiveStatus to
// populate Status.UsedByRoles (IMPROVEMENTS Missing Features §B).
//
// The result is sorted (lexicographic) for determinism and capped at
// MaxUsedByRolesInStatus. The bool return indicates whether truncation
// occurred so the caller can set the matching condition.
//
// Cluster-wide list per reconcile is acceptable: VaultRole / VaultClusterRole
// counts are bounded in practice (typically <1000 per cluster), and policy
// reconciles are not hot-path. If this becomes a bottleneck, a field
// indexer on `spec.policies[].name` is the next step.
func (h *Handler) computeUsedByRoles(
	ctx context.Context, adapter domain.PolicyAdapter,
) (refs []string, truncated bool) {
	policyName := adapter.GetName()
	policyNamespace := adapter.GetNamespace()
	wantKind := kindLabelVaultPolicy
	if !adapter.IsNamespaced() {
		wantKind = kindLabelVaultClusterPolicy
	}

	collected := map[string]struct{}{}

	var roleList vaultv1alpha1.VaultRoleList
	if err := h.client.List(ctx, &roleList); err != nil {
		// Non-fatal: a transient list error just means we leave the
		// previous Status.UsedByRoles in place. The next reconcile
		// retries.
		logr.FromContextOrDiscard(ctx).V(1).Info(
			"failed to list VaultRoles for reverse index (non-fatal)",
			"error", err.Error(),
		)
		return adapter.GetUsedByRoles(), false
	}
	for i := range roleList.Items {
		r := &roleList.Items[i]
		if !roleReferencesPolicy(r.Spec.Policies, r.Namespace, wantKind, policyName, policyNamespace) {
			continue
		}
		collected["VaultRole/"+r.Namespace+"/"+r.Name] = struct{}{}
	}

	var crList vaultv1alpha1.VaultClusterRoleList
	if err := h.client.List(ctx, &crList); err != nil {
		logr.FromContextOrDiscard(ctx).V(1).Info(
			"failed to list VaultClusterRoles for reverse index (non-fatal)",
			"error", err.Error(),
		)
	} else {
		for i := range crList.Items {
			r := &crList.Items[i]
			// VaultClusterRole policy refs MUST carry an explicit namespace,
			// so the namespace-resolution logic in roleReferencesPolicy is
			// keyed off "" (no default fallback).
			if !roleReferencesPolicy(r.Spec.Policies, "", wantKind, policyName, policyNamespace) {
				continue
			}
			collected["VaultClusterRole/"+r.Name] = struct{}{}
		}
	}

	refs = make([]string, 0, len(collected))
	for k := range collected {
		refs = append(refs, k)
	}
	// Sort for deterministic Status output — diffing two reconciles'
	// Status.UsedByRoles should compare equal when set membership is.
	sort.Strings(refs)
	if len(refs) > MaxUsedByRolesInStatus {
		truncated = true
		refs = refs[:MaxUsedByRolesInStatus]
	}
	return refs, truncated
}

// roleReferencesPolicy returns true if any entry in `refs` matches the
// given policy. For VaultPolicy refs, an empty namespace defaults to
// `roleNamespace` (mirrors what the role reconciler does at sync time).
// For VaultClusterPolicy refs, namespace is always empty.
func roleReferencesPolicy(
	refs []vaultv1alpha1.PolicyReference,
	roleNamespace, wantKind, policyName, policyNamespace string,
) bool {
	for _, ref := range refs {
		if ref.Kind != wantKind || ref.Name != policyName {
			continue
		}
		if wantKind == kindLabelVaultClusterPolicy {
			return true
		}
		ns := ref.Namespace
		if ns == "" {
			ns = roleNamespace
		}
		if ns == policyNamespace {
			return true
		}
	}
	return false
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

// buildRuleDescriptions builds a map of resolved path -> description for
// rules that have descriptions. Returns an explicit empty map (not nil) when
// no rules have descriptions — markManaged distinguishes nil ("preserve
// existing") from empty-map ("clear"), and the policy reconciler always
// wants to clear-and-rewrite to match the current spec.
func (h *Handler) buildRuleDescriptions(rules []vaultv1alpha1.PolicyRule, namespace, name string) map[string]string {
	descs := make(map[string]string)
	for _, rule := range rules {
		if rule.Description != "" {
			resolvedPath := vault.SubstituteVariables(rule.Path, namespace, name)
			descs[resolvedPath] = rule.Description
		}
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
