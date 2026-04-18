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
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/binding"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/controller/conflict"
	"github.com/panteparak/vault-access-operator/shared/controller/drift"
	"github.com/panteparak/vault-access-operator/shared/controller/hash"
	"github.com/panteparak/vault-access-operator/shared/controller/vaultclient"
	"github.com/panteparak/vault-access-operator/shared/controller/workflow"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// Kind labels used in adoption + reconcile metrics. Extracted as constants
// because they appear at multiple emission sites and the goconst linter (and
// future readers) prefer a single source of truth.
const (
	kindLabelVaultRole        = "VaultRole"
	kindLabelVaultClusterRole = "VaultClusterRole"
)

// roleKindForMetric returns the K8s kind label used in adoption / reconcile
// metrics. Mirrors policy's kindForMetric to keep the labels consistent.
func roleKindForMetric(adapter domain.RoleAdapter) string {
	if adapter.IsNamespaced() {
		return kindLabelVaultRole
	}
	return kindLabelVaultClusterRole
}

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
	resolver := func(ctx context.Context, connRef, resourceID string) (*vault.Client, error) {
		return vaultclient.Resolve(ctx, c, cache, connRef, resourceID)
	}

	h.syncWorkflow = workflow.NewSyncWorkflow(c, resolver, bus, log, h.recorder)
	h.cleanupWorkflow = workflow.NewCleanupWorkflow(c, cache.Get, bus, log)
	return h
}

// SetCleanupQueue replaces the handler's CleanupWorkflow with one that
// persists failed Vault deletes to the retry queue (IMPROVEMENTS §2).
// See policy.Handler.SetCleanupQueue for rationale.
func (h *Handler) SetCleanupQueue(q workflow.CleanupQueuer) {
	h.cleanupWorkflow = workflow.NewCleanupWorkflowWithQueue(
		h.client, h.clientCache.Get, h.eventBus, q, h.log,
	)
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
	vaultClient *vault.Client,
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
			metrics.IncrementAdoption(roleKindForMetric(adapter), adapter.GetNamespace(), true)
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
		metrics.IncrementAdoption(roleKindForMetric(adapter), adapter.GetNamespace(), true)
		return nil
	}

	return infraerrors.NewConflictError(
		"role",
		vaultRoleName,
		"already exists in Vault and is not managed by this operator",
	)
}

// shouldAdopt delegates to the shared conflict.ShouldAdopt helper
// (IMPROVEMENTS §13). Kept as a thin method for call-site readability.
func (h *Handler) shouldAdopt(adapter domain.RoleAdapter) bool {
	return conflict.ShouldAdopt(adapter)
}

// detectRoleDrift compares the expected role data with the current Vault role.
// Returns whether drift was detected and a summary of differing fields.
// Uses the shared drift.Comparator for consistent field comparison.
// Branches on the auth backend so JWT and k8s-auth roles compare only fields
// they each actually set.
func (h *Handler) detectRoleDrift(
	ctx context.Context,
	vaultClient *vault.Client,
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

	comparator := drift.NewComparator()

	switch vault.AuthBackendForPath(authPath) {
	case vault.AuthBackendJWT:
		compareJWTRoleFields(comparator, expectedData, currentData)
	default:
		compareKubernetesRoleFields(comparator, expectedData, currentData)
	}

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

// compareKubernetesRoleFields compares k8s-auth-specific role fields.
func compareKubernetesRoleFields(c *drift.Comparator, expected, current map[string]interface{}) {
	c.CompareStringSlices("policies", expected["policies"], current["policies"])
	c.CompareStringSlices("bound_service_account_names",
		expected["bound_service_account_names"], current["bound_service_account_names"])
	c.CompareStringSlices("bound_service_account_namespaces",
		expected["bound_service_account_namespaces"], current["bound_service_account_namespaces"])
}

// compareJWTRoleFields compares JWT-auth-specific role fields.
// Vault may return `token_policies` instead of `policies` for newer role versions,
// so we fall back to `token_policies` when `policies` is missing.
func compareJWTRoleFields(c *drift.Comparator, expected, current map[string]interface{}) {
	currentPolicies := current["policies"]
	if currentPolicies == nil {
		currentPolicies = current["token_policies"]
	}
	c.CompareStringSlices("policies", expected["policies"], currentPolicies)
	c.CompareStringSlices("bound_audiences",
		expected["bound_audiences"], current["bound_audiences"])
	c.CompareValuesIfExpected("role_type", expected["role_type"], current["role_type"])
	c.CompareValuesIfExpected("user_claim", expected["user_claim"], current["user_claim"])
	if _, hasClaims := expected["bound_claims"]; hasClaims {
		c.CompareValues("bound_claims", expected["bound_claims"], current["bound_claims"])
	} else {
		c.CompareValuesIfExpected("bound_subject",
			expected["bound_subject"], current["bound_subject"])
	}
}

// buildPolicyBindings creates PolicyBinding entries for tracking.
func (h *Handler) buildPolicyBindings(
	adapter domain.RoleAdapter, resolvedPolicies []string,
) []vaultv1alpha1.PolicyBinding {
	policyRefs := adapter.GetPolicies()
	bindings := make([]vaultv1alpha1.PolicyBinding, len(policyRefs))

	for i, ref := range policyRefs {
		vaultPolicyName := binding.VaultPolicyName(ref, adapter.GetNamespace())
		resolved := h.contains(resolvedPolicies, vaultPolicyName)
		bindings[i] = binding.NewPolicyBindingRef(ref, adapter.GetNamespace(), vaultPolicyName, resolved)
	}

	return bindings
}

// contains checks if a string slice contains a value.
func (h *Handler) contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// emitPolicyResolvedEvents fires a K8s event for each PolicyBinding that
// flipped from Resolved=false to Resolved=true between `previous` and
// `current`. No-op when the recorder is nil (unit tests) or when nothing
// transitioned. Matching is by the `K8sRef` field (e.g.
// `VaultPolicy/ns/name`) which is stable per binding and invariant of
// list order. Implements IMPROVEMENTS Missing Features §J.
func (h *Handler) emitPolicyResolvedEvents(
	adapter domain.RoleAdapter,
	previous, current []vaultv1alpha1.PolicyBinding,
) {
	if h.recorder == nil {
		return
	}
	// Build a lookup of previous Resolved status keyed by K8sRef. A missing
	// entry counts as previously-unresolved, so a brand-new binding that
	// lands already-resolved (e.g. policy existed before the role was
	// created) still fires its first-time resolved event.
	prior := make(map[string]bool, len(previous))
	for _, b := range previous {
		prior[b.K8sRef] = b.Resolved
	}
	for _, b := range current {
		if !b.Resolved {
			continue
		}
		if prior[b.K8sRef] {
			continue
		}
		h.recorder.Eventf(adapter.GetObject(), corev1.EventTypeNormal,
			eventReasonPolicyResolved,
			"Policy dependency %q is now resolved (Vault policy %q)",
			b.K8sRef, b.VaultPolicyPath,
		)
	}
}

// eventReasonPolicyResolved is the K8s event reason emitted when a
// previously-unresolved PolicyBinding becomes resolved. Names should be
// UpperCamelCase per k8s convention.
const eventReasonPolicyResolved = "PolicyResolved"

// verifyPoliciesExistInVault checks that each resolved policy actually exists in Vault.
// Missing policies are reported as a warning condition and event, but do NOT block the sync.
// Vault allows binding non-existent policies; this is informational for the user.
func (h *Handler) verifyPoliciesExistInVault(
	ctx context.Context,
	vaultClient *vault.Client,
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

// resolvePolicyNames resolves PolicyReferences to Vault policy names. The
// name-mapping switch used to live inline here, duplicating the logic in
// binding.VaultPolicyName (IMPROVEMENTS §20). Now we validate the kind and
// namespace inputs here, then delegate the actual mapping to the binding
// package — single source of truth for "given a PolicyReference, what's the
// Vault name?".
//
// Validation-vs-mapping split:
//   - binding.VaultPolicyName is a pure, error-less helper. It returns the
//     mapped name or falls back to ref.Name for unknown kinds.
//   - The validations below (unknown kind, missing namespace on cluster role)
//     are caller-specific policy that `binding` can't enforce without
//     coupling itself to the role feature.
func (h *Handler) resolvePolicyNames(_ context.Context, adapter domain.RoleAdapter) ([]string, error) {
	policies := adapter.GetPolicies()
	policyNames := make([]string, 0, len(policies))

	for _, policyRef := range policies {
		switch policyRef.Kind {
		case binding.KindVaultPolicy, binding.KindVaultClusterPolicy:
			// supported kinds
		default:
			return nil, infraerrors.NewValidationError(
				"policies",
				policyRef.Kind,
				"invalid policy kind, must be VaultPolicy or VaultClusterPolicy",
			)
		}

		// Compute the default namespace to pass to binding.VaultPolicyName.
		// For VaultClusterPolicy this is unused; for VaultPolicy it's the
		// role's own namespace when ref.Namespace is empty.
		defaultNs := ""
		if policyRef.Kind == binding.KindVaultPolicy {
			defaultNs = policyRef.Namespace
			if defaultNs == "" && adapter.IsNamespaced() {
				defaultNs = adapter.GetNamespace()
			}
			if defaultNs == "" {
				return nil, infraerrors.NewValidationError(
					"policies",
					policyRef.Name,
					"namespace required for VaultPolicy reference in cluster-scoped role",
				)
			}
		}

		policyNames = append(policyNames, binding.VaultPolicyName(policyRef, defaultNs))
	}

	return policyNames, nil
}

// buildRoleData constructs the data map for the Vault role write.
// Branches on the auth backend indicated by adapter.GetAuthPath().
//
// For k8s-auth mounts, the connection argument may be nil.
// For JWT mounts, the connection is consulted for default audiences and may
// still be nil — a cluster-default audience is used as fallback.
func (h *Handler) buildRoleData(
	adapter domain.RoleAdapter,
	policyNames []string,
	serviceAccountBindings []string,
	connection *vaultv1alpha1.VaultConnection,
) (map[string]interface{}, error) {
	backend := vault.AuthBackendForPath(adapter.GetAuthPath())
	switch backend {
	case vault.AuthBackendKubernetes:
		return h.buildKubernetesRoleData(adapter, policyNames, serviceAccountBindings), nil
	case vault.AuthBackendJWT:
		return h.buildJWTRoleData(adapter, policyNames, serviceAccountBindings, connection)
	default:
		return nil, infraerrors.NewValidationError(
			"authPath", adapter.GetAuthPath(),
			"unsupported auth backend: only auth/kubernetes and auth/jwt are implemented",
		)
	}
}

// buildKubernetesRoleData constructs the payload for a Kubernetes auth role.
func (h *Handler) buildKubernetesRoleData(
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

// defaultJWTAudience is used when no VaultConnection-level audiences are
// available — the operator's own in-cluster SA token issuer.
const defaultJWTAudience = "https://kubernetes.default.svc.cluster.local"

// buildJWTRoleData constructs the payload for a Vault JWT auth role.
// Derives role_type, user_claim and bound_subject from the spec when the
// optional jwt sub-object does not override them.
func (h *Handler) buildJWTRoleData(
	adapter domain.RoleAdapter,
	policyNames []string,
	serviceAccountBindings []string,
	connection *vaultv1alpha1.VaultConnection,
) (map[string]interface{}, error) {
	jwtSpec := adapter.GetJWT()
	if jwtSpec == nil {
		jwtSpec = &vaultv1alpha1.VaultRoleJWTSpec{}
	}

	roleType := jwtSpec.RoleType
	if roleType == "" {
		roleType = "jwt"
	}

	userClaim := jwtSpec.UserClaim
	if userClaim == "" {
		userClaim = "sub"
	}

	audiences := jwtSpec.BoundAudiences
	if len(audiences) == 0 {
		audiences = defaultJWTAudiences(connection)
	}

	data := map[string]interface{}{
		"role_type":       roleType,
		"user_claim":      userClaim,
		"bound_audiences": audiences,
		"policies":        policyNames,
	}

	if len(jwtSpec.BoundClaims) > 0 {
		// Cast map[string]string to map[string]interface{} for Vault API.
		claims := make(map[string]interface{}, len(jwtSpec.BoundClaims))
		for k, v := range jwtSpec.BoundClaims {
			claims[k] = v
		}
		data["bound_claims"] = claims
	} else {
		subject, err := resolveJWTBoundSubject(adapter, jwtSpec, serviceAccountBindings)
		if err != nil {
			return nil, err
		}
		data["bound_subject"] = subject
	}

	if ttl := adapter.GetTokenTTL(); ttl != "" {
		data["token_ttl"] = ttl
	}
	if maxTTL := adapter.GetTokenMaxTTL(); maxTTL != "" {
		data["token_max_ttl"] = maxTTL
	}

	return data, nil
}

// resolveJWTBoundSubject returns either the explicit override, or derives
// "system:serviceaccount:<ns>:<sa>" from the first service account binding.
// Rejects multi-SA specs that don't provide an explicit override — bound_subject
// only holds a single value.
func resolveJWTBoundSubject(
	adapter domain.RoleAdapter,
	jwtSpec *vaultv1alpha1.VaultRoleJWTSpec,
	serviceAccountBindings []string,
) (string, error) {
	if jwtSpec.BoundSubject != "" {
		return jwtSpec.BoundSubject, nil
	}
	if len(serviceAccountBindings) == 0 {
		return "", infraerrors.NewValidationError(
			"serviceAccounts", "",
			"at least one service account is required to derive jwt bound_subject",
		)
	}
	if len(serviceAccountBindings) > 1 {
		return "", infraerrors.NewValidationError(
			"serviceAccounts", fmt.Sprintf("%d entries", len(serviceAccountBindings)),
			"JWT VaultRole with more than one serviceAccount must set "+
				"spec.jwt.boundSubject or spec.jwt.boundClaims explicitly",
		)
	}
	parts := strings.SplitN(serviceAccountBindings[0], "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", infraerrors.NewValidationError(
			"serviceAccounts", serviceAccountBindings[0],
			"service account binding must be in namespace/name format",
		)
	}
	// Unused when the binding itself is well-formed — reference to silence linters
	// when adapter is otherwise unused here.
	_ = adapter
	return fmt.Sprintf("system:serviceaccount:%s:%s", parts[0], parts[1]), nil
}

// defaultJWTAudiences returns the fallback audiences for a JWT role when
// the spec does not set bound_audiences explicitly. Prefers the referenced
// VaultConnection's JWT auth audiences when available; otherwise falls back
// to the in-cluster SA token issuer.
func defaultJWTAudiences(connection *vaultv1alpha1.VaultConnection) []string {
	if connection != nil && connection.Spec.Auth.JWT != nil && len(connection.Spec.Auth.JWT.Audiences) > 0 {
		audiences := make([]string, len(connection.Spec.Auth.JWT.Audiences))
		copy(audiences, connection.Spec.Auth.JWT.Audiences)
		return audiences
	}
	return []string{defaultJWTAudience}
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
