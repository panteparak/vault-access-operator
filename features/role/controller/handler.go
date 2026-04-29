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
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/binding"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/controller/drift"
	"github.com/panteparak/vault-access-operator/shared/controller/hash"
	"github.com/panteparak/vault-access-operator/shared/controller/vaultclient"
	"github.com/panteparak/vault-access-operator/shared/controller/workflow"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// Handler provides shared role sync/cleanup logic.
// It works with RoleAdapter to handle both VaultRole and VaultClusterRole.
type Handler struct {
	client          client.Client
	clientCache     *vault.ClientCache
	eventBus        *events.EventBus
	recorder        record.EventRecorder
	log             logr.Logger
	syncWorkflow    *workflow.SyncWorkflow
	cleanupWorkflow *workflow.CleanupWorkflow
}

// NewHandler creates a new role Handler.
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
	resolver := func(ctx context.Context, connRef, resourceID string) (workflow.VaultOpsClient, error) {
		return vaultclient.Resolve(ctx, c, cache, connRef, resourceID)
	}
	cleanupGetter := func(connRef string) (workflow.VaultOpsClient, error) {
		return cache.Get(connRef)
	}

	h.syncWorkflow = workflow.NewSyncWorkflow(c, resolver, bus, log, h.recorder)
	h.cleanupWorkflow = workflow.NewCleanupWorkflow(c, cleanupGetter, bus, log)
	return h
}

// SyncRole synchronizes a role to Vault.
func (h *Handler) SyncRole(ctx context.Context, adapter domain.RoleAdapter) error {
	ops := NewRoleOps(adapter, h)
	return h.syncWorkflow.Execute(ctx, adapter, ops)
}

// CleanupRole removes a role from Vault.
func (h *Handler) CleanupRole(ctx context.Context, adapter domain.RoleAdapter) error {
	ops := NewRoleOps(adapter, h)
	return h.cleanupWorkflow.Execute(ctx, adapter, ops)
}

// --- Helper methods used by RoleOps ---

// checkConflict checks for conflicts with existing Vault roles.
// Supports adoption via annotation (vault.platform.io/adopt: "true") or ConflictPolicy.
func (h *Handler) checkConflict(
	ctx context.Context,
	vaultClient workflow.VaultOpsClient,
	adapter domain.RoleAdapter,
	authPath, vaultRoleName string,
) error {
	log := logr.FromContextOrDiscard(ctx)

	exists, err := vaultClient.KubernetesAuthRoleExists(ctx, authPath, vaultRoleName)
	if err != nil {
		return infraerrors.NewTransientError("check role existence", err)
	}

	if !exists {
		return nil
	}

	// Role exists, check ownership
	managedBy, err := vaultClient.GetRoleManagedBy(ctx, vaultRoleName)
	if err != nil {
		// Can't determine ownership - check if adoption is allowed
		if h.shouldAdopt(adapter) {
			log.Info("adopting role (ownership unknown)", "roleName", vaultRoleName)
			return nil
		}
		return infraerrors.NewTransientError("check role ownership", err)
	}

	k8sResource := adapter.GetK8sResourceIdentifier()

	// Same owner, no conflict
	if managedBy == k8sResource {
		return nil
	}

	// Different owner - cannot adopt
	if managedBy != "" {
		return infraerrors.NewConflictError("role", vaultRoleName, fmt.Sprintf("already managed by %s", managedBy))
	}

	// Exists but not managed - check if adoption is allowed
	if h.shouldAdopt(adapter) {
		log.Info("adopting existing Vault role", "roleName", vaultRoleName)
		return nil
	}

	return infraerrors.NewConflictError(
		"role",
		vaultRoleName,
		"already exists in Vault and is not managed by this operator",
	)
}

// shouldAdopt checks if the adapter should adopt an existing Vault resource.
// Adoption is allowed via annotation (takes precedence) or ConflictPolicy.
func (h *Handler) shouldAdopt(adapter domain.RoleAdapter) bool {
	// Check annotation first (takes precedence)
	annotations := adapter.GetAnnotations()
	if annotations[vaultv1alpha1.AnnotationAdopt] == vaultv1alpha1.AnnotationValueTrue {
		return true
	}

	// Fall back to ConflictPolicy
	return adapter.GetConflictPolicy() == vaultv1alpha1.ConflictPolicyAdopt
}

// detectRoleDrift compares the expected role data with the current Vault role.
// Returns whether drift was detected and a summary of differing fields.
// Uses the shared drift.Comparator for consistent field comparison.
func (h *Handler) detectRoleDrift(
	ctx context.Context,
	vaultClient workflow.VaultOpsClient,
	authPath, roleName string,
	expectedData map[string]interface{},
) (bool, string) {
	log := logr.FromContextOrDiscard(ctx)

	currentData, err := vaultClient.ReadKubernetesAuthRole(ctx, authPath, roleName)
	if err != nil {
		log.V(1).Info("failed to read role for drift detection (non-fatal)", "error", err)
		return false, ""
	}
	if currentData == nil {
		return false, ""
	}

	// Use shared drift comparator for consistent field comparison
	comparator := drift.NewComparator()

	// Compare string slice fields (order-independent)
	comparator.CompareStringSlices("policies", expectedData["policies"], currentData["policies"])
	comparator.CompareStringSlices("bound_service_account_names",
		expectedData["bound_service_account_names"], currentData["bound_service_account_names"])
	comparator.CompareStringSlices("bound_service_account_namespaces",
		expectedData["bound_service_account_namespaces"], currentData["bound_service_account_namespaces"])

	// Compare optional TTL fields (only if expected is set).
	// Vault normalizes Go duration strings (e.g. "30s") to integer seconds (30),
	// so we normalize expected values before comparison.
	expectedTTL := normalizeTTLToSeconds(expectedData["token_ttl"])
	expectedMaxTTL := normalizeTTLToSeconds(expectedData["token_max_ttl"])
	comparator.CompareValuesIfExpected("token_ttl", expectedTTL, currentData["token_ttl"])
	comparator.CompareValuesIfExpected("token_max_ttl", expectedMaxTTL, currentData["token_max_ttl"])

	result := comparator.Result()
	return result.HasDrift, result.Summary
}

// buildPolicyBindings creates PolicyBinding entries for tracking.
func (h *Handler) buildPolicyBindings(
	adapter domain.RoleAdapter, resolvedPolicies []string,
) []vaultv1alpha1.PolicyBinding {
	policyRefs := adapter.GetPolicies()
	bindings := make([]vaultv1alpha1.PolicyBinding, len(policyRefs))

	for i, ref := range policyRefs {
		vaultPolicyName := binding.VaultPolicyName(ref, adapter.GetNamespace())
		resolved := slices.Contains(resolvedPolicies, vaultPolicyName)
		bindings[i] = binding.NewPolicyBindingRef(ref, adapter.GetNamespace(), vaultPolicyName, resolved)
	}

	return bindings
}

// verifyPoliciesExistInVault checks that each resolved policy actually exists in Vault.
// Missing policies are reported as a warning condition and event, but do NOT block the sync.
// Vault allows binding non-existent policies; this is informational for the user.
func (h *Handler) verifyPoliciesExistInVault(
	ctx context.Context,
	vaultClient workflow.VaultOpsClient,
	adapter domain.RoleAdapter,
	policyNames []string,
) {
	log := logr.FromContextOrDiscard(ctx)
	var missing []string

	for _, name := range policyNames {
		exists, err := vaultClient.PolicyExists(ctx, name)
		if err != nil {
			log.V(1).Info("failed to check policy existence (non-fatal)", "policy", name, "error", err)
			continue
		}
		if !exists {
			missing = append(missing, name)
		}
	}

	gen := adapter.GetGeneration()
	conds := adapter.GetConditions()
	if len(missing) > 0 {
		msg := fmt.Sprintf("policies not found in Vault: %s", strings.Join(missing, ", "))
		conds = conditions.Set(conds, gen, "PoliciesResolved",
			metav1.ConditionFalse, vaultv1alpha1.ReasonPolicyNotInVault, msg)
		log.Info("warning: role references policies not yet in Vault", "missing", missing)
		if h.recorder != nil {
			h.recorder.Event(adapter.GetObject(), corev1.EventTypeWarning,
				"PolicyNotInVault", msg)
		}
	} else {
		conds = conditions.Set(conds, gen, "PoliciesResolved",
			metav1.ConditionTrue, "AllPoliciesExist", "All referenced policies exist in Vault")
	}
	adapter.SetConditions(conds)
}

// resolvePolicyNames resolves PolicyReferences to Vault policy names.
// VaultPolicy: namespace-name format
// VaultClusterPolicy: name only
func (h *Handler) resolvePolicyNames(_ context.Context, adapter domain.RoleAdapter) ([]string, error) {
	policies := adapter.GetPolicies()
	policyNames := make([]string, 0, len(policies))

	for _, policyRef := range policies {
		var policyName string

		switch policyRef.Kind {
		case vaultv1alpha1.PolicyKindNamespaced:
			namespace := policyRef.Namespace
			if namespace == "" && adapter.IsNamespaced() {
				namespace = adapter.GetNamespace()
			}
			if namespace == "" {
				return nil, infraerrors.NewValidationError(
					"policies",
					policyRef.Name,
					"namespace required for VaultPolicy reference in cluster-scoped role",
				)
			}
			policyName = namespace + "-" + policyRef.Name

		case vaultv1alpha1.PolicyKindCluster:
			policyName = policyRef.Name

		default:
			return nil, infraerrors.NewValidationError(
				"policies",
				string(policyRef.Kind),
				"invalid policy kind, must be VaultPolicy or VaultClusterPolicy",
			)
		}

		policyNames = append(policyNames, policyName)
	}

	return policyNames, nil
}

// buildRoleData constructs the data map for the Kubernetes auth role.
func (h *Handler) buildRoleData(
	adapter domain.RoleAdapter,
	policyNames []string,
	serviceAccountBindings []string,
) map[string]interface{} {
	// Extract namespaces and names from bindings
	var boundServiceAccountNames []string
	var boundServiceAccountNamespaces []string
	namespaceSet := make(map[string]bool)

	for _, saBinding := range serviceAccountBindings {
		parts := strings.SplitN(saBinding, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			// Adapters guarantee "namespace/name" format; log and skip malformed input
			continue
		}
		namespace, name := parts[0], parts[1]
		boundServiceAccountNames = append(boundServiceAccountNames, name)
		if !namespaceSet[namespace] {
			namespaceSet[namespace] = true
			boundServiceAccountNamespaces = append(boundServiceAccountNamespaces, namespace)
		}
	}

	// Sort for deterministic hashing — map iteration order for namespaceSet is random
	sort.Strings(boundServiceAccountNames)
	sort.Strings(boundServiceAccountNamespaces)

	data := map[string]interface{}{
		"bound_service_account_names":      boundServiceAccountNames,
		"bound_service_account_namespaces": boundServiceAccountNamespaces,
		"policies":                         policyNames,
	}

	// Add optional TTL settings
	if ttl := adapter.GetTokenTTL(); ttl != "" {
		data["token_ttl"] = ttl
	}
	if maxTTL := adapter.GetTokenMaxTTL(); maxTTL != "" {
		data["token_max_ttl"] = maxTTL
	}

	return data
}

// normalizeTTLToSeconds converts a Go duration string (e.g. "30s", "5m", "1h")
// to integer seconds matching Vault's internal normalization. If the value is
// not a parseable duration string (or is nil), it is returned unchanged.
func normalizeTTLToSeconds(val interface{}) interface{} {
	s, ok := val.(string)
	if !ok {
		return val
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return val
	}
	return int(d.Seconds())
}

// calculateSpecHash computes a deterministic SHA256 hash of the role data for change detection.
// Keys are sorted to ensure stable hashing across reconcile cycles.
func (h *Handler) calculateSpecHash(roleData map[string]interface{}) (string, error) {
	return hash.FromMapDeterministic(roleData)
}
