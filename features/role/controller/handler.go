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
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/binding"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/controller/driftmode"
	"github.com/panteparak/vault-access-operator/shared/controller/syncerror"
	"github.com/panteparak/vault-access-operator/shared/controller/vaultclient"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// Handler provides shared role sync/cleanup logic.
// It works with RoleAdapter to handle both VaultRole and VaultClusterRole.
type Handler struct {
	client      client.Client
	clientCache *vault.ClientCache
	eventBus    *events.EventBus
	log         logr.Logger
}

// NewHandler creates a new role Handler.
func NewHandler(c client.Client, cache *vault.ClientCache, bus *events.EventBus, log logr.Logger) *Handler {
	return &Handler{
		client:      c,
		clientCache: cache,
		eventBus:    bus,
		log:         log,
	}
}

// SyncRole synchronizes a role to Vault.
func (h *Handler) SyncRole(ctx context.Context, adapter domain.RoleAdapter) error {
	log := logr.FromContextOrDiscard(ctx)
	vaultRoleName := adapter.GetVaultRoleName()
	authPath := adapter.GetAuthPath()
	if authPath == "" {
		authPath = vault.DefaultKubernetesAuthPath
	}

	// Update last attempt time
	now := metav1.Now()
	adapter.SetLastAttemptAt(&now)

	// Resolve effective drift mode
	effectiveDriftMode := driftmode.Resolve(ctx, h.client, adapter.GetDriftMode(), adapter.GetConnectionRef())
	adapter.SetEffectiveDriftMode(effectiveDriftMode)

	// Set phase to Syncing if not already active
	phase := adapter.GetPhase()
	if phase != vaultv1alpha1.PhaseSyncing && phase != vaultv1alpha1.PhaseActive {
		adapter.SetPhase(vaultv1alpha1.PhaseSyncing)
		if err := h.client.Status().Update(ctx, adapter.GetObject()); err != nil {
			return fmt.Errorf("failed to update status to Syncing: %w", err)
		}
	}

	// Get Vault client
	vaultClient, err := h.getVaultClient(ctx, adapter)
	if err != nil {
		return h.handleSyncError(ctx, adapter, err)
	}

	// Check for conflicts (with adoption support)
	if err := h.checkConflict(ctx, vaultClient, adapter, authPath, vaultRoleName); err != nil {
		return h.handleSyncError(ctx, adapter, err)
	}

	// Resolve policy names from PolicyReferences
	policyNames, err := h.resolvePolicyNames(ctx, adapter)
	if err != nil {
		return h.handleSyncError(ctx, adapter, err)
	}

	// Get service account bindings
	serviceAccountBindings := adapter.GetServiceAccountBindings()
	log.Info("service account bindings from spec",
		"roleName", vaultRoleName,
		"bindings", serviceAccountBindings,
		"count", len(serviceAccountBindings))

	// Build Kubernetes auth role data
	roleData := h.buildRoleData(adapter, policyNames, serviceAccountBindings)

	// Calculate spec hash for distinguishing spec changes from Vault drift
	specHash := h.calculateSpecHash(roleData)

	// Drift detection logic based on effective drift mode
	driftDetected := false
	driftSummary := ""
	kind := "VaultRole"
	if !adapter.IsNamespaced() {
		kind = "VaultClusterRole"
	}

	if adapter.GetPhase() == vaultv1alpha1.PhaseActive && driftmode.ShouldDetect(effectiveDriftMode) {
		driftDetected, driftSummary = h.detectRoleDrift(ctx, vaultClient, authPath, vaultRoleName, roleData)
		if driftDetected {
			log.Info("drift detected in Vault role",
				"roleName", vaultRoleName, "summary", driftSummary, "mode", effectiveDriftMode)
		}

		// Update drift status
		adapter.SetDriftDetected(driftDetected)
		adapter.SetDriftSummary(driftSummary)
		adapter.SetLastDriftCheckAt(&now)

		// Record drift metric
		metrics.SetDriftDetected(kind, adapter.GetNamespace(), adapter.GetName(), driftDetected)
	} else if driftmode.IsIgnore(effectiveDriftMode) {
		log.V(1).Info("drift detection disabled", "roleName", vaultRoleName, "mode", effectiveDriftMode)
		adapter.SetDriftDetected(false)
		adapter.SetDriftSummary("")
	}

	// Handle drift mode behavior
	if driftDetected && driftmode.IsDetect(effectiveDriftMode) {
		// Detect mode: report drift but don't correct
		log.Info("drift detected (detect mode - not correcting)", "roleName", vaultRoleName)
		adapter.SetMessage("Drift detected: " + driftSummary)

		// Update status to show drift without correcting
		if err := h.client.Status().Update(ctx, adapter.GetObject()); err != nil {
			log.V(1).Info("failed to update drift status (non-fatal)", "error", err)
		}

		// Only skip sync if spec hash matches (true Vault-side drift)
		// If spec changed (hash differs), continue to sync the new spec
		lastHash := adapter.GetLastAppliedHash()
		log.Info("comparing spec hashes for drift handling",
			"roleName", vaultRoleName,
			"lastAppliedHash", lastHash,
			"currentSpecHash", specHash,
			"hashesMatch", lastHash == specHash)
		if lastHash == specHash {
			return nil
		}
		log.Info("spec changed, continuing sync despite drift", "roleName", vaultRoleName)
	}

	// Safety check for drift correction
	if driftDetected && driftmode.IsCorrect(effectiveDriftMode) {
		annotations := adapter.GetAnnotations()
		if annotations[vaultv1alpha1.AnnotationAllowDestructive] != "true" {
			log.Info("drift correction blocked - missing allow-destructive annotation",
				"roleName", vaultRoleName)
			adapter.SetPhase(vaultv1alpha1.PhaseConflict)
			adapter.SetMessage("Drift detected but vault.platform.io/allow-destructive annotation required")
			h.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
				vaultv1alpha1.ReasonConflict, "Drift correction requires allow-destructive annotation")

			if err := h.client.Status().Update(ctx, adapter.GetObject()); err != nil {
				return fmt.Errorf("failed to update conflict status: %w", err)
			}

			metrics.IncrementDestructiveBlocked(kind, adapter.GetNamespace())
			return nil
		}
		log.Info("correcting drift with destructive annotation", "roleName", vaultRoleName)
	}

	// Create/update the Kubernetes auth role
	if err := vaultClient.WriteKubernetesAuthRole(ctx, authPath, vaultRoleName, roleData); err != nil {
		return h.handleSyncError(ctx, adapter, infraerrors.NewTransientError("write role", err))
	}

	// Mark role as managed
	k8sResource := adapter.GetK8sResourceIdentifier()
	if err := vaultClient.MarkRoleManaged(ctx, vaultRoleName, k8sResource); err != nil {
		log.V(1).Info("failed to mark role as managed (non-fatal)", "error", err.Error())
	}

	// Update binding after successful sync
	roleBinding := binding.NewRoleBinding(authPath, vaultRoleName)
	adapter.SetBinding(roleBinding)

	// Build policy bindings
	policyBindings := h.buildPolicyBindings(adapter, policyNames)
	adapter.SetPolicyBindings(policyBindings)

	// Track drift correction if we fixed drift
	if driftDetected {
		adapter.SetDriftCorrectedAt(&now)
		metrics.IncrementDriftCorrected(kind, adapter.GetNamespace())
	}

	// Update status to Active
	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	adapter.SetVaultRoleName(vaultRoleName)
	adapter.SetManaged(true)
	adapter.SetBoundServiceAccounts(serviceAccountBindings)
	adapter.SetResolvedPolicies(policyNames)
	adapter.SetLastAppliedHash(specHash) // Store hash to detect future spec changes
	adapter.SetLastSyncedAt(&now)
	adapter.SetRetryCount(0)
	adapter.SetNextRetryAt(nil)
	adapter.SetMessage("")
	adapter.SetDriftDetected(false) // Clear drift flag after successful sync
	adapter.SetDriftSummary("")
	adapter.SetLastDriftCheckAt(&now)
	h.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Role synced to Vault")
	h.setCondition(adapter, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Role synced successfully")

	if err := h.client.Status().Update(ctx, adapter.GetObject()); err != nil {
		return fmt.Errorf("failed to update status to Active: %w", err)
	}

	// Publish RoleCreated event
	if h.eventBus != nil {
		resource := events.ResourceInfo{
			Name:           adapter.GetName(),
			Namespace:      adapter.GetNamespace(),
			ClusterScoped:  !adapter.IsNamespaced(),
			ConnectionName: adapter.GetConnectionRef(),
		}
		event := events.NewRoleCreated(vaultRoleName, authPath, resource, policyNames, serviceAccountBindings)
		h.eventBus.PublishAsync(ctx, event)
	}

	log.Info("role synced successfully", "roleName", vaultRoleName)
	return nil
}

// CleanupRole removes a role from Vault.
func (h *Handler) CleanupRole(ctx context.Context, adapter domain.RoleAdapter) error {
	log := logr.FromContextOrDiscard(ctx)
	vaultRoleName := adapter.GetVaultRoleName()
	authPath := adapter.GetAuthPath()
	if authPath == "" {
		authPath = vault.DefaultKubernetesAuthPath
	}

	// Update phase to Deleting
	adapter.SetPhase(vaultv1alpha1.PhaseDeleting)
	if err := h.client.Status().Update(ctx, adapter.GetObject()); err != nil {
		log.V(1).Info("failed to update status to Deleting (ignoring)", "error", err)
	}

	// Only delete from Vault if deletion policy is Delete
	deletionPolicy := adapter.GetDeletionPolicy()
	if deletionPolicy == vaultv1alpha1.DeletionPolicyDelete || deletionPolicy == "" {
		vaultClient, err := h.clientCache.Get(adapter.GetConnectionRef())
		if err != nil {
			log.Info("failed to get Vault client during deletion, continuing with finalizer removal")
		} else if vaultClient.IsAuthenticated() {
			if err := vaultClient.DeleteKubernetesAuthRole(ctx, authPath, vaultRoleName); err != nil {
				log.Error(err, "failed to delete role from Vault")
			} else {
				log.Info("deleted role from Vault", "roleName", vaultRoleName)
			}

			// Remove managed marker
			if err := vaultClient.RemoveRoleManaged(ctx, vaultRoleName); err != nil {
				log.V(1).Info("failed to remove managed marker (non-fatal)", "error", err.Error())
			}
		}
	} else {
		log.Info("DeletionPolicy is Retain, keeping role in Vault", "roleName", vaultRoleName)
	}

	// Publish RoleDeleted event
	if h.eventBus != nil {
		resource := events.ResourceInfo{
			Name:           adapter.GetName(),
			Namespace:      adapter.GetNamespace(),
			ClusterScoped:  !adapter.IsNamespaced(),
			ConnectionName: adapter.GetConnectionRef(),
		}
		h.eventBus.PublishAsync(ctx, events.NewRoleDeleted(vaultRoleName, authPath, resource))
	}

	log.Info("role cleanup completed", "roleName", vaultRoleName)
	return nil
}

// getVaultClient retrieves a Vault client for the role's connection.
func (h *Handler) getVaultClient(ctx context.Context, adapter domain.RoleAdapter) (*vault.Client, error) {
	return vaultclient.Resolve(ctx, h.client, h.clientCache,
		adapter.GetConnectionRef(), adapter.GetK8sResourceIdentifier())
}

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
	if annotations[vaultv1alpha1.AnnotationAdopt] == "true" {
		return true
	}

	// Fall back to ConflictPolicy
	return adapter.GetConflictPolicy() == vaultv1alpha1.ConflictPolicyAdopt
}

// detectRoleDrift compares the expected role data with the current Vault role.
// Returns whether drift was detected and a summary of differing fields.
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

	var diffs []string

	// Compare policies
	if !h.compareStringSlices(currentData["policies"], expectedData["policies"]) {
		diffs = append(diffs, "policies")
	}

	// Compare bound_service_account_names
	if !h.compareStringSlices(currentData["bound_service_account_names"], expectedData["bound_service_account_names"]) {
		diffs = append(diffs, "bound_service_account_names")
	}

	// Compare bound_service_account_namespaces
	currentNs := currentData["bound_service_account_namespaces"]
	expectedNs := expectedData["bound_service_account_namespaces"]
	if !h.compareStringSlices(currentNs, expectedNs) {
		diffs = append(diffs, "bound_service_account_namespaces")
	}

	// Compare token_ttl if set
	if expectedTTL, ok := expectedData["token_ttl"]; ok {
		if !h.compareValues(currentData["token_ttl"], expectedTTL) {
			diffs = append(diffs, "token_ttl")
		}
	}

	// Compare token_max_ttl if set
	if expectedMaxTTL, ok := expectedData["token_max_ttl"]; ok {
		if !h.compareValues(currentData["token_max_ttl"], expectedMaxTTL) {
			diffs = append(diffs, "token_max_ttl")
		}
	}

	if len(diffs) > 0 {
		return true, "fields differ: " + strings.Join(diffs, ", ")
	}
	return false, ""
}

// compareStringSlices compares two interface{} values as string slices.
func (h *Handler) compareStringSlices(a, b interface{}) bool {
	sliceA := h.toStringSlice(a)
	sliceB := h.toStringSlice(b)

	if len(sliceA) != len(sliceB) {
		return false
	}

	// Sort both slices for comparison
	sort.Strings(sliceA)
	sort.Strings(sliceB)

	for i := range sliceA {
		if sliceA[i] != sliceB[i] {
			return false
		}
	}
	return true
}

// toStringSlice converts an interface{} to []string.
func (h *Handler) toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		result := make([]string, len(val))
		for i, item := range val {
			if s, ok := item.(string); ok {
				result[i] = s
			}
		}
		return result
	default:
		return nil
	}
}

// compareValues compares two interface{} values.
func (h *Handler) compareValues(a, b interface{}) bool {
	// Handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Compare as strings for TTL values
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
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

// resolvePolicyNames resolves PolicyReferences to Vault policy names.
// VaultPolicy: namespace-name format
// VaultClusterPolicy: name only
func (h *Handler) resolvePolicyNames(_ context.Context, adapter domain.RoleAdapter) ([]string, error) {
	policies := adapter.GetPolicies()
	policyNames := make([]string, 0, len(policies))

	for _, policyRef := range policies {
		var policyName string

		switch policyRef.Kind {
		case "VaultPolicy":
			// For VaultPolicy, use namespace-name format
			namespace := policyRef.Namespace
			if namespace == "" && adapter.IsNamespaced() {
				// Default to the role's namespace if not specified
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

		case "VaultClusterPolicy":
			// For VaultClusterPolicy, use name only
			policyName = policyRef.Name

		default:
			return nil, infraerrors.NewValidationError(
				"policies",
				policyRef.Kind,
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
		// saBinding format is "namespace/name"
		var namespace, name string
		for i := 0; i < len(saBinding); i++ {
			if saBinding[i] == '/' {
				namespace = saBinding[:i]
				name = saBinding[i+1:]
				break
			}
		}
		if name != "" {
			boundServiceAccountNames = append(boundServiceAccountNames, name)
			if !namespaceSet[namespace] {
				namespaceSet[namespace] = true
				boundServiceAccountNamespaces = append(boundServiceAccountNamespaces, namespace)
			}
		}
	}

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

// handleSyncError updates status for errors.
func (h *Handler) handleSyncError(ctx context.Context, adapter domain.RoleAdapter, err error) error {
	return syncerror.Handle(ctx, h.client, h.log, adapter, err)
}

// setCondition sets or updates a condition on the adapter.
// nolint:unparam // status and reason kept for API consistency with conditions.Set signature.
func (h *Handler) setCondition(
	adapter domain.RoleAdapter,
	condType string,
	status metav1.ConditionStatus,
	reason, message string,
) {
	adapter.SetConditions(conditions.Set(
		adapter.GetConditions(), adapter.GetGeneration(),
		condType, status, reason, message,
	))
}

// calculateSpecHash computes a SHA256 hash of the role data for change detection.
// This distinguishes K8s spec changes from external Vault drift.
func (h *Handler) calculateSpecHash(roleData map[string]interface{}) string {
	data, err := json.Marshal(roleData)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
