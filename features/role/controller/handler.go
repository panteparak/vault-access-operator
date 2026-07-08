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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	"github.com/panteparak/vault-access-operator/shared/controller/syncerror"
	"github.com/panteparak/vault-access-operator/shared/controller/vaultclient"
	"github.com/panteparak/vault-access-operator/shared/controller/workflow"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
	"github.com/panteparak/vault-access-operator/shared/markers"
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
	resolver := func(ctx context.Context, connRef, resourceID string) (workflow.VaultOpsClient, error) {
		return vaultclient.Resolve(ctx, c, cache, connRef, resourceID)
	}
	cleanupGetter := func(connRef string) (workflow.VaultOpsClient, error) {
		return cache.Get(connRef)
	}

	h.syncWorkflow = workflow.NewSyncWorkflow(c, resolver, bus, log, h.recorder)
	h.cleanupWorkflow = workflow.NewCleanupWorkflow(c, cleanupGetter, bus, log).WithRecorder(h.recorder)
	return h
}

// SetCleanupQueue replaces the handler's CleanupWorkflow with one that
// persists failed Vault deletes to the retry queue (IMPROVEMENTS §2).
// See policy.Handler.SetCleanupQueue for rationale.
func (h *Handler) SetCleanupQueue(q workflow.CleanupQueuer) {
	cleanupGetter := func(connRef string) (workflow.VaultOpsClient, error) {
		return h.clientCache.Get(connRef)
	}
	h.cleanupWorkflow = workflow.NewCleanupWorkflowWithQueue(
		h.client, cleanupGetter, h.eventBus, q, h.log,
	).WithRecorder(h.recorder)
	// The sync workflow shares the queue: a failed delete of the old-named
	// object after a rename (ADR 0010) is replayed the same way.
	h.syncWorkflow.WithCleanupQueue(q)
}

// roleTarget is the resolved write destination for a role: which auth
// mount it lands on, its backend family, and the connection it came from.
// Roles carry no mount fields — the referenced VaultConnection is the sole
// source (VaultConnection.RoleMount).
type roleTarget struct {
	// conn is the resolved connection, used for JWT audience/claim
	// defaults. Nil on cleanup-fallback paths where the connection is gone.
	conn    *vaultv1alpha1.VaultConnection
	mount   string // bare mount name, e.g. "kubernetes", "jwt-gitlab"
	backend vaultv1alpha1.AuthBackendType
}

// resolveRoleTarget fetches the referenced VaultConnection and derives the
// role's target mount from it. Connection not found is a dependency error
// (ReasonConnectionNotReady — it may appear later); a connection whose auth
// method has no role-capable mount is a permanent validation error the user
// must fix on the connection.
func (h *Handler) resolveRoleTarget(
	ctx context.Context, adapter domain.RoleAdapter,
) (*roleTarget, error) {
	connRef := adapter.GetConnectionRef()
	conn := &vaultv1alpha1.VaultConnection{}
	if err := h.client.Get(ctx, client.ObjectKey{Name: connRef}, conn); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, infraerrors.NewDependencyError(
				adapter.GetK8sResourceIdentifier(), "VaultConnection", connRef, "not found")
		}
		return nil, infraerrors.NewTransientError("resolve connection for role mount", err)
	}
	mount, backend, err := conn.RoleMount()
	if err != nil {
		return nil, infraerrors.NewValidationError("connectionRef", connRef, err.Error())
	}
	return &roleTarget{conn: conn, mount: mount, backend: backend}, nil
}

// resolveCleanupTarget derives the mount to delete from, binding-first: the
// mount recorded in status at last sync wins, so a connection whose mount
// changed after the role synced still deletes from where the role was
// actually written. Falls back to the connection; a role that never synced
// under a mount-less connection yields an empty target (nothing to delete).
func (h *Handler) resolveCleanupTarget(
	ctx context.Context, adapter domain.RoleAdapter,
) *roleTarget {
	if recorded := adapter.GetBinding().AuthMount; recorded != "" {
		// AuthMountName normalizes legacy records that stored the
		// "auth/"-prefixed (or double-prefixed) form.
		return &roleTarget{mount: vault.AuthMountName(recorded)}
	}
	if target, err := h.resolveRoleTarget(ctx, adapter); err == nil {
		return target
	}
	return &roleTarget{}
}

// SyncRole synchronizes a role to Vault.
func (h *Handler) SyncRole(ctx context.Context, adapter domain.RoleAdapter) error {
	target, err := h.resolveRoleTarget(ctx, adapter)
	if err != nil {
		return syncerror.Handle(ctx, h.client, h.log, adapter, err, h.recorder)
	}
	return h.syncWorkflow.Execute(ctx, adapter, NewRoleOps(adapter, h, target))
}

// CleanupRole removes a role from Vault.
func (h *Handler) CleanupRole(ctx context.Context, adapter domain.RoleAdapter) error {
	ops := NewRoleOps(adapter, h, h.resolveCleanupTarget(ctx, adapter))
	return h.cleanupWorkflow.Execute(ctx, adapter, ops)
}

// --- Helper methods used by RoleOps ---

// checkConflict checks for conflicts with existing Vault roles.
//
// Roles carry their in-band ownership record in alias_metadata (ADR 0010,
// amending ADR 0008's "roles carry nothing"): a record naming this operator
// and CR proves the role is ours even when the CR's status memory is gone; a
// record naming someone else is a hard conflict regardless of adoption
// settings. A record-less role (hand-created or pre-ADR-0010) falls back to
// the old rules: CR status memory (LastAppliedHash) then adoption intent,
// backstopped by the one-cluster-per-auth-mount invariant.
func (h *Handler) checkConflict(
	ctx context.Context,
	vaultClient workflow.VaultOpsClient,
	adapter domain.RoleAdapter,
	authPath, vaultRoleName string,
) error {
	// Managed markers disabled: ownership tracking is off — proceed
	// (write-and-forget). Explicit adopt-intent is surfaced separately.
	if !markers.Enabled() {
		conflict.WarnAdoptIntentInert(h.recorder, adapter.GetObject(), adapter)
		return nil
	}

	log := logr.FromContextOrDiscard(ctx)

	data, err := vaultClient.ReadKubernetesAuthRole(ctx, authPath, vaultRoleName)
	if err != nil {
		return infraerrors.NewTransientError("check role existence", err)
	}

	if data == nil {
		return nil
	}

	if own, ok := vault.ParseAliasMetadata(data); ok {
		if own.SameOwner(vaultClient.AuthMount(), adapter.GetK8sResourceIdentifier()) {
			return nil
		}
		return infraerrors.NewConflictError(
			"role",
			vaultRoleName,
			fmt.Sprintf("already exists in Vault and is owned by %s", own.String()),
		)
	}

	// This CR has synced the role before — it's ours.
	if adapter.GetLastAppliedHash() != "" {
		return nil
	}

	// Role exists but this CR never created it - check if adoption is allowed
	if h.shouldAdopt(adapter) {
		log.Info("adopting existing Vault role", "roleName", vaultRoleName)
		metrics.IncrementAdoption(roleKindForMetric(adapter), adapter.GetNamespace(), true)
		return nil
	}

	return infraerrors.NewConflictError(
		"role",
		vaultRoleName,
		"already exists in Vault and is not tracked by this resource "+
			"(set ConflictPolicy: Adopt or the vault.platform.io/adopt "+
			"annotation to take it over)",
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
	vaultClient workflow.VaultOpsClient,
	backend vault.AuthBackend,
	authPath, roleName string,
	expectedData map[string]interface{},
) (bool, string) {
	log := logr.FromContextOrDiscard(ctx)

	currentData, err := vaultClient.ReadKubernetesAuthRole(ctx, authPath, roleName)
	if err != nil {
		// Bump from V(1) to Info — at default verbosity an operator
		// investigating "why is the policy reporting in-sync while
		// Vault is clearly broken" needs to find this. Mirrors the
		// PolicyOps.DetectDrift visibility fix.
		log.Info("skipping role drift detection — Vault read failed",
			"role", roleName,
			"error", err.Error(),
			"hint", "drift state preserved from last successful read; will retry on next reconcile",
		)
		return false, ""
	}
	if currentData == nil {
		return false, ""
	}

	comparator := drift.NewComparator()

	switch backend {
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
		c.CompareValuesIfExpected("bound_claims_type",
			expected["bound_claims_type"], current["bound_claims_type"])
	} else {
		c.CompareValuesIfExpected("bound_subject",
			expected["bound_subject"], current["bound_subject"])
	}
}

// buildPolicyBindings creates PolicyBinding entries for tracking, straight
// from the lookup resolution (ADR 0010): the Vault-side name comes from the
// referenced policy's recorded status, never re-derived.
func (h *Handler) buildPolicyBindings(resolution []resolvedPolicyRef) []vaultv1alpha1.PolicyBinding {
	bindings := make([]vaultv1alpha1.PolicyBinding, len(resolution))
	for i, r := range resolution {
		bindings[i] = binding.NewPolicyBindingRef(r.Ref, r.Namespace, r.VaultName, r.Resolved)
	}
	return bindings
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

// verifyPoliciesExistInVault checks the resolution: refs whose policy CR is
// missing or not yet synced are "pending" (ADR 0010 lookup model); resolved
// names are additionally checked for existence in Vault. Both classes are
// reported via the PoliciesResolved condition and a Warning event, but do
// NOT block the sync — Vault allows binding non-existent policies, and the
// role converges once the policy's status lands (watch-driven requeue).
func (h *Handler) verifyPoliciesExistInVault(
	ctx context.Context,
	vaultClient workflow.VaultOpsClient,
	adapter domain.RoleAdapter,
	resolution []resolvedPolicyRef,
) {
	log := logr.FromContextOrDiscard(ctx)
	var missing, pending []string

	for _, r := range resolution {
		if !r.Resolved {
			pending = append(pending, binding.PolicyK8sRef(string(r.Ref.Kind), r.Namespace, r.Ref.Name))
			continue
		}
		exists, err := vaultClient.PolicyExists(ctx, r.VaultName)
		if err != nil {
			log.V(1).Info("failed to check policy existence (non-fatal)", "policy", r.VaultName, "error", err)
			continue
		}
		if !exists {
			missing = append(missing, r.VaultName)
		}
	}

	gen := adapter.GetGeneration()
	conds := adapter.GetConditions()
	if len(missing) > 0 || len(pending) > 0 {
		var parts []string
		if len(pending) > 0 {
			parts = append(parts, "policies not yet synced: "+strings.Join(pending, ", "))
		}
		if len(missing) > 0 {
			parts = append(parts, "policies not found in Vault: "+strings.Join(missing, ", "))
		}
		msg := strings.Join(parts, "; ")
		conds = conditions.Set(conds, gen, "PoliciesResolved",
			metav1.ConditionFalse, vaultv1alpha1.ReasonPolicyNotInVault, msg)
		log.Info("warning: role has unresolved policy references",
			"pending", pending, "missing", missing)
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

// resolvedPolicyRef is one PolicyReference after lookup against the K8s API
// (ADR 0010): the referenced policy CR's RECORDED status.vaultName is the
// only truth about its Vault-side name — re-deriving it here would guess
// wrong whenever the policy's connection identity differs from the role's.
type resolvedPolicyRef struct {
	Ref       vaultv1alpha1.PolicyReference
	Namespace string // effective namespace (VaultPolicy refs only)
	VaultName string // recorded name; "" when the CR is missing or not yet synced
	Resolved  bool
}

// resolvePolicyNames validates each PolicyReference and looks up the
// referenced policy CR's recorded Vault name. A missing CR or empty status
// yields an unresolved entry (the binding machinery requeues the role when
// the policy's status lands); API errors other than NotFound are transient.
func (h *Handler) resolvePolicyNames(ctx context.Context, adapter domain.RoleAdapter) ([]resolvedPolicyRef, error) {
	policies := adapter.GetPolicies()
	resolution := make([]resolvedPolicyRef, 0, len(policies))

	for _, policyRef := range policies {
		switch string(policyRef.Kind) {
		case binding.KindVaultPolicy, binding.KindVaultClusterPolicy:
			// supported kinds
		default:
			return nil, infraerrors.NewValidationError(
				"policies",
				string(policyRef.Kind),
				"invalid policy kind, must be VaultPolicy or VaultClusterPolicy",
			)
		}

		// Effective namespace: for VaultPolicy it's the ref's namespace,
		// else the role's own; cluster-scoped roles must be explicit.
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

		vaultName := ""
		if policyRef.Name != "" {
			var err error
			vaultName, err = h.lookupPolicyVaultName(ctx, policyRef, defaultNs)
			if err != nil {
				return nil, err
			}
		}
		resolution = append(resolution, resolvedPolicyRef{
			Ref:       policyRef,
			Namespace: defaultNs,
			VaultName: vaultName,
			Resolved:  vaultName != "",
		})
	}

	return resolution, nil
}

// lookupPolicyVaultName fetches the referenced policy CR and returns its
// recorded status.vaultName ("" when the CR is absent or not yet synced).
func (h *Handler) lookupPolicyVaultName(
	ctx context.Context, ref vaultv1alpha1.PolicyReference, namespace string,
) (string, error) {
	if string(ref.Kind) == binding.KindVaultClusterPolicy {
		var p vaultv1alpha1.VaultClusterPolicy
		if err := h.client.Get(ctx, client.ObjectKey{Name: ref.Name}, &p); err != nil {
			if apierrors.IsNotFound(err) {
				return "", nil
			}
			return "", infraerrors.NewTransientError("resolve policy reference", err)
		}
		return p.Status.VaultName, nil
	}
	var p vaultv1alpha1.VaultPolicy
	if err := h.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, &p); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", infraerrors.NewTransientError("resolve policy reference", err)
	}
	return p.Status.VaultName, nil
}

// buildRoleData constructs the data map for the Vault role write, branching
// on the backend family resolved from the connection (roleTarget.backend).
//
// For k8s-auth mounts, the connection argument may be nil.
// For JWT mounts, the connection is consulted for default audiences and may
// still be nil — a cluster-default audience is used as fallback.
func (h *Handler) buildRoleData(
	adapter domain.RoleAdapter,
	backend vault.AuthBackend,
	policyNames []string,
	serviceAccountBindings []string,
	connection *vaultv1alpha1.VaultConnection,
) (map[string]interface{}, error) {
	switch backend {
	case vault.AuthBackendKubernetes:
		return h.buildKubernetesRoleData(adapter, policyNames, serviceAccountBindings), nil
	case vault.AuthBackendJWT:
		return h.buildJWTRoleData(adapter, policyNames, serviceAccountBindings, connection)
	default:
		// Unreachable through resolveRoleTarget (RoleMount only yields
		// kubernetes/jwt); kept as a guard for future backend families.
		return nil, infraerrors.NewValidationError(
			"connectionRef", adapter.GetConnectionRef(),
			fmt.Sprintf("unsupported auth backend %q: only kubernetes and jwt are implemented", backend),
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
		roleType = string(vault.AuthBackendJWT)
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

	if len(jwtSpec.BoundClaims) > 0 || len(jwtSpec.BoundClaimsList) > 0 {
		data["bound_claims"] = mergeBoundClaims(jwtSpec.BoundClaims, jwtSpec.BoundClaimsList)

		// Always emit bound_claims_type when bound_claims is set, defaulting
		// to "string". Vault treats this field as sticky: once switched to
		// "glob", a role write that omits it leaves the prior value in place.
		// Emitting explicitly on every write avoids that latent state.
		claimsType := jwtSpec.BoundClaimsType
		if claimsType == "" {
			claimsType = "string"
		}
		data["bound_claims_type"] = claimsType
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

// mergeBoundClaims combines BoundClaims (deprecated scalars) and
// BoundClaimsList (lists) into a single bound_claims payload. Lists win on
// key collision. All values are emitted as []interface{} because that is what
// Vault returns when reading the role back; emitting Go-native []string would
// cause the drift comparator's reflect.DeepEqual to flag false drift on every
// reconcile.
func mergeBoundClaims(scalars map[string]string, lists map[string][]string) map[string]interface{} {
	out := make(map[string]interface{}, len(scalars)+len(lists))
	for k, v := range scalars {
		out[k] = []interface{}{v}
	}
	for k, vs := range lists {
		list := make([]interface{}, len(vs))
		for i, v := range vs {
			list[i] = v
		}
		out[k] = list
	}
	return out
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
				"spec.jwt.boundSubject, spec.jwt.boundClaims, or spec.jwt.boundClaimsList explicitly",
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
