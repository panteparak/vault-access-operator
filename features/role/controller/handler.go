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
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/binding"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/controller/drift"
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
	recorder    record.EventRecorder
	log         logr.Logger
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
	return h
}

// SyncRole synchronizes a role to Vault.
// nolint:gocyclo // Reconciliation logic naturally handles drift modes, conflicts, and bindings
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
		if err := h.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
			a.SetPhase(vaultv1alpha1.PhaseSyncing)
		}); err != nil {
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

	// Verify referenced policies exist in Vault (warning, not blocking)
	h.verifyPoliciesExistInVault(ctx, vaultClient, adapter, policyNames)

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

		// Set Drifted condition and emit events
		if driftDetected {
			h.setCondition(adapter, vaultv1alpha1.ConditionTypeDrifted, metav1.ConditionTrue,
				vaultv1alpha1.ReasonDriftDetected, driftSummary)
			if h.recorder != nil {
				h.recorder.Event(adapter.GetObject(), corev1.EventTypeWarning,
					"DriftDetected", "Drift detected: "+driftSummary)
			}
		} else {
			h.setCondition(adapter, vaultv1alpha1.ConditionTypeDrifted, metav1.ConditionFalse,
				vaultv1alpha1.ReasonNoDrift, "No drift detected")
		}

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

		// Update status to show drift without correcting (with retry for robustness)
		if err := h.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
			a.SetMessage("Drift detected: " + driftSummary)
			a.SetDriftDetected(driftDetected)
			a.SetDriftSummary(driftSummary)
			a.SetLastDriftCheckAt(&now)
		}); err != nil {
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
		if annotations[vaultv1alpha1.AnnotationAllowDestructive] != vaultv1alpha1.AnnotationValueTrue {
			log.Info("drift correction blocked - missing allow-destructive annotation",
				"roleName", vaultRoleName)

			if err := h.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
				a.SetPhase(vaultv1alpha1.PhaseConflict)
				a.SetMessage("Drift detected but vault.platform.io/allow-destructive annotation required")
				a.SetConditions(conditions.Set(
					a.GetConditions(), a.GetGeneration(),
					vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
					vaultv1alpha1.ReasonConflict, "Drift correction requires allow-destructive annotation",
				))
			}); err != nil {
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

	// Readback verification — confirm Vault persisted the correct content
	if hasDrift, summary := h.detectRoleDrift(ctx, vaultClient, authPath, vaultRoleName, roleData); hasDrift {
		return h.handleSyncError(ctx, adapter, infraerrors.NewTransientError(
			"readback verification", fmt.Errorf("role content mismatch after write: %s", summary)))
	}

	// Mark role as managed
	k8sResource := adapter.GetK8sResourceIdentifier()
	if err := vaultClient.MarkRoleManaged(ctx, vaultRoleName, k8sResource); err != nil {
		log.V(1).Info("failed to mark role as managed (non-fatal)", "error", err.Error())
	}

	// Build binding and policy bindings for status update
	roleBinding := binding.NewRoleBinding(authPath, vaultRoleName)
	policyBindings := h.buildPolicyBindings(adapter, policyNames)

	// Track drift correction if we fixed drift
	driftCorrectedAt := adapter.GetDriftCorrectedAt()
	if driftDetected {
		driftCorrectedAt = &now
		metrics.IncrementDriftCorrected(kind, adapter.GetNamespace())
	}

	// Update status to Active (with retry for robustness under concurrent access)
	// All status changes must be inside the callback to survive re-fetch
	if err := h.updateStatusWithRetry(ctx, adapter, func(a domain.RoleAdapter) {
		// Set binding after successful sync (must be inside callback)
		a.SetBinding(roleBinding)
		a.SetPolicyBindings(policyBindings)

		a.SetPhase(vaultv1alpha1.PhaseActive)
		a.SetVaultRoleName(vaultRoleName)
		a.SetManaged(true)
		a.SetBoundServiceAccounts(serviceAccountBindings)
		a.SetResolvedPolicies(policyNames)
		a.SetLastAppliedHash(specHash) // Store hash to detect future spec changes
		a.SetLastSyncedAt(&now)
		a.SetRetryCount(0)
		a.SetNextRetryAt(nil)
		a.SetMessage("")
		a.SetDriftDetected(false) // Clear drift flag after successful sync
		a.SetDriftSummary("")
		a.SetLastDriftCheckAt(&now)
		if driftCorrectedAt != nil {
			a.SetDriftCorrectedAt(driftCorrectedAt)
		}
		a.SetConditions(conditions.Set(
			a.GetConditions(), a.GetGeneration(),
			vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			vaultv1alpha1.ReasonSucceeded, "Role synced to Vault",
		))
		a.SetConditions(conditions.Set(
			a.GetConditions(), a.GetGeneration(),
			vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue,
			vaultv1alpha1.ReasonSucceeded, "Role synced successfully",
		))
		a.SetConditions(conditions.Set(
			a.GetConditions(), a.GetGeneration(),
			vaultv1alpha1.ConditionTypeDependencyReady, metav1.ConditionTrue,
			vaultv1alpha1.ReasonDependencyReady, "All dependencies ready",
		))
		a.SetConditions(conditions.Set(
			a.GetConditions(), a.GetGeneration(),
			vaultv1alpha1.ConditionTypeDrifted, metav1.ConditionFalse,
			vaultv1alpha1.ReasonNoDrift, "No drift detected",
		))
	}); err != nil {
		return fmt.Errorf("failed to update status to Active: %w", err)
	}

	// Emit drift corrected event if we fixed drift
	if driftDetected && h.recorder != nil {
		h.recorder.Event(adapter.GetObject(), corev1.EventTypeNormal,
			"DriftCorrected", "Drift was detected and corrected in Vault")
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

	// Track deletion start time
	if adapter.GetDeletionStartedAt() == nil {
		now := metav1.Now()
		adapter.SetDeletionStartedAt(&now)
	}

	// Update phase to Deleting (non-fatal if it fails)
	// Note: Not using retry here because this is an informational status update
	// and the error is ignored. Using retry would cause resource version conflicts
	// with the subsequent finalizer removal in the reconciler.
	adapter.SetPhase(vaultv1alpha1.PhaseDeleting)
	conds := conditions.Set(adapter.GetConditions(), adapter.GetGeneration(),
		vaultv1alpha1.ConditionTypeDeleting, metav1.ConditionTrue,
		vaultv1alpha1.ReasonDeletionInProgress, "Deletion in progress")
	adapter.SetConditions(conds)
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

// handleSyncError updates status for errors.
func (h *Handler) handleSyncError(ctx context.Context, adapter domain.RoleAdapter, err error) error {
	return syncerror.Handle(ctx, h.client, h.log, adapter, err, h.recorder)
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

// updateStatusWithRetry updates the status with retry on conflict.
// The applyStatus function is called with a fresh copy of the object to apply status changes.
// This prevents "the object has been modified" errors under concurrent updates.
func (h *Handler) updateStatusWithRetry(
	ctx context.Context,
	adapter domain.RoleAdapter,
	applyStatus func(domain.RoleAdapter),
) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// Re-fetch the object to get the latest resourceVersion
		obj := adapter.GetObject()
		key := client.ObjectKeyFromObject(obj)

		if adapter.IsNamespaced() {
			var role vaultv1alpha1.VaultRole
			if err := h.client.Get(ctx, key, &role); err != nil {
				return err
			}
			freshAdapter := domain.NewVaultRoleAdapter(&role)
			applyStatus(freshAdapter)
			return h.client.Status().Update(ctx, freshAdapter.GetObject())
		}

		var role vaultv1alpha1.VaultClusterRole
		if err := h.client.Get(ctx, key, &role); err != nil {
			return err
		}
		freshAdapter := domain.NewVaultClusterRoleAdapter(&role)
		applyStatus(freshAdapter)
		return h.client.Status().Update(ctx, freshAdapter.GetObject())
	})
}
