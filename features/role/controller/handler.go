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

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
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

	// Set phase to Syncing if not already active
	phase := adapter.GetPhase()
	if phase != vaultv1alpha1.PhaseSyncing && phase != vaultv1alpha1.PhaseActive {
		adapter.SetPhase(vaultv1alpha1.PhaseSyncing)
		if err := h.client.Status().Update(ctx, adapter); err != nil {
			return fmt.Errorf("failed to update status to Syncing: %w", err)
		}
	}

	// Get Vault client
	vaultClient, err := h.getVaultClient(ctx, adapter)
	if err != nil {
		return h.handleSyncError(ctx, adapter, err)
	}

	// Check for conflicts
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

	// Build Kubernetes auth role data
	roleData := h.buildRoleData(adapter, policyNames, serviceAccountBindings)

	// Create/update the Kubernetes auth role
	if err := vaultClient.WriteKubernetesAuthRole(ctx, authPath, vaultRoleName, roleData); err != nil {
		return h.handleSyncError(ctx, adapter, infraerrors.NewTransientError("write role", err))
	}

	// Mark role as managed
	k8sResource := adapter.GetK8sResourceIdentifier()
	if err := vaultClient.MarkRoleManaged(ctx, vaultRoleName, k8sResource); err != nil {
		log.V(1).Info("failed to mark role as managed (non-fatal)", "error", err.Error())
	}

	// Update status to Active
	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	adapter.SetVaultRoleName(vaultRoleName)
	adapter.SetManaged(true)
	adapter.SetBoundServiceAccounts(serviceAccountBindings)
	adapter.SetResolvedPolicies(policyNames)
	adapter.SetLastSyncedAt(&now)
	adapter.SetRetryCount(0)
	adapter.SetNextRetryAt(nil)
	adapter.SetMessage("")
	h.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Role synced to Vault")
	h.setCondition(adapter, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Role synced successfully")

	if err := h.client.Status().Update(ctx, adapter); err != nil {
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
	if err := h.client.Status().Update(ctx, adapter); err != nil {
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
	connRef := adapter.GetConnectionRef()

	// Check if connection exists and is active
	conn := &vaultv1alpha1.VaultConnection{}
	if err := h.client.Get(ctx, client.ObjectKey{Name: connRef}, conn); err != nil {
		return nil, infraerrors.NewDependencyError(
			adapter.GetK8sResourceIdentifier(),
			"VaultConnection",
			connRef,
			"not found",
		)
	}

	if conn.Status.Phase != vaultv1alpha1.PhaseActive {
		return nil, infraerrors.NewDependencyError(
			adapter.GetK8sResourceIdentifier(),
			"VaultConnection",
			connRef,
			fmt.Sprintf("not ready (phase: %s)", conn.Status.Phase),
		)
	}

	// Get client from cache
	vaultClient, err := h.clientCache.Get(connRef)
	if err != nil {
		return nil, infraerrors.NewDependencyError(
			adapter.GetK8sResourceIdentifier(),
			"VaultConnection",
			connRef,
			"client not in cache",
		)
	}

	return vaultClient, nil
}

// checkConflict checks for conflicts with existing Vault roles.
func (h *Handler) checkConflict(
	ctx context.Context,
	vaultClient *vault.Client,
	adapter domain.RoleAdapter,
	authPath, vaultRoleName string,
) error {
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
		// Can't determine ownership
		if adapter.GetConflictPolicy() == vaultv1alpha1.ConflictPolicyAdopt {
			return nil
		}
		return infraerrors.NewTransientError("check role ownership", err)
	}

	k8sResource := adapter.GetK8sResourceIdentifier()

	// Same owner, no conflict
	if managedBy == k8sResource {
		return nil
	}

	// Different owner
	if managedBy != "" {
		return infraerrors.NewConflictError("role", vaultRoleName, fmt.Sprintf("already managed by %s", managedBy))
	}

	// Exists but not managed - check conflict policy
	if adapter.GetConflictPolicy() == vaultv1alpha1.ConflictPolicyAdopt {
		return nil
	}

	return infraerrors.NewConflictError(
		"role",
		vaultRoleName,
		"already exists in Vault and is not managed by this operator",
	)
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

	for _, binding := range serviceAccountBindings {
		// binding format is "namespace/name"
		var namespace, name string
		for i := 0; i < len(binding); i++ {
			if binding[i] == '/' {
				namespace = binding[:i]
				name = binding[i+1:]
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
	// Determine phase based on error type
	if infraerrors.IsConflictError(err) {
		adapter.SetPhase(vaultv1alpha1.PhaseConflict)
		h.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			vaultv1alpha1.ReasonConflict, err.Error())
	} else if infraerrors.IsValidationError(err) {
		adapter.SetPhase(vaultv1alpha1.PhaseError)
		h.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			vaultv1alpha1.ReasonValidationFailed, err.Error())
	} else if infraerrors.IsDependencyError(err) {
		adapter.SetPhase(vaultv1alpha1.PhaseError)
		h.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			vaultv1alpha1.ReasonConnectionNotReady, err.Error())
	} else {
		adapter.SetPhase(vaultv1alpha1.PhaseError)
		h.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			vaultv1alpha1.ReasonFailed, err.Error())
	}

	adapter.SetMessage(err.Error())
	h.setCondition(adapter, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionFalse,
		vaultv1alpha1.ReasonFailed, err.Error())

	if updateErr := h.client.Status().Update(ctx, adapter); updateErr != nil {
		h.log.Error(updateErr, "failed to update error status")
	}

	return err
}

// setCondition sets or updates a condition.
func (h *Handler) setCondition(
	adapter domain.RoleAdapter,
	condType string,
	status metav1.ConditionStatus,
	reason, message string,
) {
	now := metav1.Now()
	condition := vaultv1alpha1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: adapter.GetGeneration(),
	}

	conditions := adapter.GetConditions()
	found := false
	for i, c := range conditions {
		if c.Type == condType {
			if c.Status != status {
				conditions[i] = condition
			} else {
				conditions[i].Reason = reason
				conditions[i].Message = message
				conditions[i].ObservedGeneration = adapter.GetGeneration()
			}
			found = true
			break
		}
	}

	if !found {
		conditions = append(conditions, condition)
	}
	adapter.SetConditions(conditions)
}
