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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

const (
	// defaultAuthPath is the default mount path for Kubernetes auth in Vault
	defaultAuthPath = "kubernetes"
)

// VaultClusterRoleReconciler reconciles a VaultClusterRole object
type VaultClusterRoleReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ClientCache *vault.ClientCache
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterroles/finalizers,verbs=update
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterpolicies,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *VaultClusterRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling VaultClusterRole", "name", req.Name)

	// Fetch the VaultClusterRole resource
	role := &vaultv1alpha1.VaultClusterRole{}
	if err := r.Get(ctx, req.NamespacedName, role); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("VaultClusterRole not found, ignoring", "name", req.Name)
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get VaultClusterRole")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !role.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, role)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(role, vaultv1alpha1.FinalizerName) {
		controllerutil.AddFinalizer(role, vaultv1alpha1.FinalizerName)
		if err := r.Update(ctx, role); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Update last attempt time
	now := metav1.Now()
	role.Status.LastAttemptAt = &now

	// Set phase to Syncing if not already in a terminal state
	if role.Status.Phase != vaultv1alpha1.PhaseSyncing && role.Status.Phase != vaultv1alpha1.PhaseActive {
		role.Status.Phase = vaultv1alpha1.PhaseSyncing
		if err := r.Status().Update(ctx, role); err != nil {
			log.Error(err, "Failed to update status to Syncing")
			return ctrl.Result{}, err
		}
	}

	// Get Vault client from cache
	vaultClient, err := r.ClientCache.Get(role.Spec.ConnectionRef)
	if err != nil {
		log.Error(err, "Failed to get Vault client from cache", "connectionRef", role.Spec.ConnectionRef)
		return r.updateStatusError(ctx, role, NewConnectionNotReadyError(role.Spec.ConnectionRef, "connection not found in cache"))
	}

	// Resolve policies from spec.Policies
	resolvedPolicies, err := r.resolvePolicies(ctx, vaultClient, role.Spec.Policies)
	if err != nil {
		log.Error(err, "Failed to resolve policies")
		return r.updateStatusError(ctx, role, err)
	}

	// Build service account bindings
	saNames, saNamespaces, boundSAs := r.buildServiceAccountBindings(role.Spec.ServiceAccounts)

	// Determine auth path
	authPath := role.Spec.AuthPath
	if authPath == "" {
		authPath = defaultAuthPath
	}
	authPathFull := fmt.Sprintf("auth/%s", authPath)

	// Role name is same as metadata.name for cluster-scoped resources
	roleName := role.Name

	// Check for conflicts with existing role
	existingRole, err := vaultClient.ReadKubernetesAuthRole(ctx, authPathFull, roleName)
	if err != nil {
		log.Error(err, "Failed to read existing Kubernetes auth role")
		return r.updateStatusError(ctx, role, NewTransientError("failed to read existing role", err))
	}

	if existingRole != nil {
		// Role exists - check if managed by us or handle conflict
		isManaged, err := vaultClient.IsRoleManaged(ctx, roleName)
		if err != nil {
			log.Error(err, "Failed to check if role is managed")
			return r.updateStatusError(ctx, role, NewTransientError("failed to check role ownership", err))
		}

		if !isManaged {
			// Role exists but not managed by us
			if role.Spec.ConflictPolicy == vaultv1alpha1.ConflictPolicyFail {
				conflictErr := NewConflictError("kubernetes-auth-role", roleName, "role already exists and is not managed by operator")
				log.Error(conflictErr, "Conflict detected")
				return r.updateStatusConflict(ctx, role, conflictErr)
			}
			// ConflictPolicy is Adopt - we'll take over management
			log.Info("Adopting existing role", "roleName", roleName)
		}
	}

	// Build role configuration
	roleConfig := map[string]interface{}{
		"bound_service_account_names":      saNames,
		"bound_service_account_namespaces": saNamespaces,
		"token_policies":                   resolvedPolicies,
	}

	// Add optional TTL settings
	if role.Spec.TokenTTL != "" {
		roleConfig["token_ttl"] = role.Spec.TokenTTL
	}
	if role.Spec.TokenMaxTTL != "" {
		roleConfig["token_max_ttl"] = role.Spec.TokenMaxTTL
	}

	// Create/update Kubernetes auth role in Vault
	if err := vaultClient.WriteKubernetesAuthRole(ctx, authPathFull, roleName, roleConfig); err != nil {
		log.Error(err, "Failed to write Kubernetes auth role to Vault")
		return r.updateStatusError(ctx, role, NewTransientError("failed to write role to Vault", err))
	}

	// Mark as managed
	k8sResource := role.Name // Cluster-scoped, so just the name
	if err := vaultClient.MarkRoleManaged(ctx, roleName, k8sResource); err != nil {
		log.Error(err, "Failed to mark role as managed")
		// Non-fatal error, continue
	}

	// Update status to Active
	role.Status.Phase = vaultv1alpha1.PhaseActive
	role.Status.VaultRoleName = roleName
	role.Status.Managed = true
	role.Status.BoundServiceAccounts = boundSAs
	role.Status.ResolvedPolicies = resolvedPolicies
	role.Status.LastSyncedAt = &now
	role.Status.RetryCount = 0
	role.Status.NextRetryAt = nil
	role.Status.Message = ""

	r.setCondition(role, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, "Role synced successfully")
	r.setCondition(role, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, "Role synced to Vault")
	r.setCondition(role, vaultv1alpha1.ConditionTypePoliciesResolved, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, fmt.Sprintf("Resolved %d policies", len(resolvedPolicies)))

	if err := r.Status().Update(ctx, role); err != nil {
		log.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}

	log.Info("VaultClusterRole reconciled successfully", "name", role.Name, "vaultRoleName", roleName, "policies", resolvedPolicies)
	return ctrl.Result{}, nil
}

// reconcileDelete handles the deletion of a VaultClusterRole
func (r *VaultClusterRoleReconciler) reconcileDelete(ctx context.Context, role *vaultv1alpha1.VaultClusterRole) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling VaultClusterRole deletion", "name", role.Name)

	// Update phase to Deleting
	role.Status.Phase = vaultv1alpha1.PhaseDeleting
	if err := r.Status().Update(ctx, role); err != nil {
		log.Error(err, "Failed to update status to Deleting")
		return ctrl.Result{}, err
	}

	// Only delete from Vault if DeletionPolicy is Delete
	if role.Spec.DeletionPolicy == vaultv1alpha1.DeletionPolicyDelete {
		vaultClient, err := r.ClientCache.Get(role.Spec.ConnectionRef)
		if err != nil {
			log.Error(err, "Failed to get Vault client for deletion", "connectionRef", role.Spec.ConnectionRef)
			// Continue with finalizer removal even if we can't connect to Vault
		} else {
			// Determine auth path
			authPath := role.Spec.AuthPath
			if authPath == "" {
				authPath = defaultAuthPath
			}
			authPathFull := fmt.Sprintf("auth/%s", authPath)

			roleName := role.Name

			// Delete the Kubernetes auth role from Vault
			if err := vaultClient.DeleteKubernetesAuthRole(ctx, authPathFull, roleName); err != nil {
				log.Error(err, "Failed to delete Kubernetes auth role from Vault")
				// Continue with finalizer removal
			} else {
				log.Info("Deleted Kubernetes auth role from Vault", "roleName", roleName)
			}

			// Remove the managed marker
			if err := vaultClient.RemoveRoleManaged(ctx, roleName); err != nil {
				log.Error(err, "Failed to remove role managed marker")
				// Continue with finalizer removal
			}
		}
	} else {
		log.Info("DeletionPolicy is Retain, not deleting role from Vault", "name", role.Name)
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(role, vaultv1alpha1.FinalizerName)
	if err := r.Update(ctx, role); err != nil {
		log.Error(err, "Failed to remove finalizer")
		return ctrl.Result{}, err
	}

	log.Info("VaultClusterRole finalizer removed", "name", role.Name)
	return ctrl.Result{}, nil
}

// resolvePolicies resolves PolicyReference list to actual Vault policy names
func (r *VaultClusterRoleReconciler) resolvePolicies(ctx context.Context, vaultClient *vault.Client, policyRefs []vaultv1alpha1.PolicyReference) ([]string, error) {
	log := logf.FromContext(ctx)
	resolvedPolicies := make([]string, 0, len(policyRefs))

	for _, ref := range policyRefs {
		var policyName string

		switch ref.Kind {
		case "VaultClusterPolicy":
			// For VaultClusterPolicy, use Name directly
			policyName = ref.Name

			// Optionally verify the policy exists in K8s
			clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{}
			if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, clusterPolicy); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, NewPolicyNotFoundError(ref.Kind, ref.Name, "")
				}
				return nil, fmt.Errorf("failed to get VaultClusterPolicy %s: %w", ref.Name, err)
			}

			// Use the VaultName from status if available (it should be the same as Name for cluster policies)
			if clusterPolicy.Status.VaultName != "" {
				policyName = clusterPolicy.Status.VaultName
			}

		case "VaultPolicy":
			// For VaultPolicy, use {namespace}-{name} format
			namespace := ref.Namespace
			if namespace == "" {
				return nil, NewValidationError("policies", fmt.Sprintf("namespace is required for VaultPolicy reference %s", ref.Name))
			}

			// Optionally verify the policy exists in K8s
			nsPolicy := &vaultv1alpha1.VaultPolicy{}
			if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, nsPolicy); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, NewPolicyNotFoundError(ref.Kind, ref.Name, namespace)
				}
				return nil, fmt.Errorf("failed to get VaultPolicy %s/%s: %w", namespace, ref.Name, err)
			}

			// Use the VaultName from status if available
			if nsPolicy.Status.VaultName != "" {
				policyName = nsPolicy.Status.VaultName
			} else {
				// Fallback to namespace-name format
				policyName = fmt.Sprintf("%s-%s", namespace, ref.Name)
			}

		default:
			return nil, NewValidationError("policies", fmt.Sprintf("unsupported policy kind: %s", ref.Kind))
		}

		// Verify the policy exists in Vault
		exists, err := vaultClient.PolicyExists(ctx, policyName)
		if err != nil {
			log.Error(err, "Failed to check if policy exists in Vault", "policyName", policyName)
			return nil, NewTransientError(fmt.Sprintf("failed to verify policy %s exists in Vault", policyName), err)
		}
		if !exists {
			return nil, NewPolicyNotFoundError(ref.Kind, ref.Name, ref.Namespace)
		}

		resolvedPolicies = append(resolvedPolicies, policyName)
	}

	return resolvedPolicies, nil
}

// buildServiceAccountBindings extracts service account names and namespaces from ServiceAccountRefs
func (r *VaultClusterRoleReconciler) buildServiceAccountBindings(saRefs []vaultv1alpha1.ServiceAccountRef) ([]string, []string, []string) {
	saNames := make([]string, 0, len(saRefs))
	saNamespaces := make([]string, 0, len(saRefs))
	boundSAs := make([]string, 0, len(saRefs))

	// Use maps to deduplicate
	nameSet := make(map[string]bool)
	namespaceSet := make(map[string]bool)

	for _, ref := range saRefs {
		// Add to name set
		if !nameSet[ref.Name] {
			nameSet[ref.Name] = true
			saNames = append(saNames, ref.Name)
		}

		// Add to namespace set
		if !namespaceSet[ref.Namespace] {
			namespaceSet[ref.Namespace] = true
			saNamespaces = append(saNamespaces, ref.Namespace)
		}

		// Always add the full reference for status
		boundSAs = append(boundSAs, fmt.Sprintf("%s/%s", ref.Namespace, ref.Name))
	}

	return saNames, saNamespaces, boundSAs
}

// updateStatusError updates the status with an error condition
func (r *VaultClusterRoleReconciler) updateStatusError(ctx context.Context, role *vaultv1alpha1.VaultClusterRole, err error) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	role.Status.Phase = vaultv1alpha1.PhaseError
	role.Status.Message = err.Error()

	// Determine the appropriate condition based on error type
	if IsPolicyNotFoundError(err) {
		r.setCondition(role, vaultv1alpha1.ConditionTypePoliciesResolved, metav1.ConditionFalse, vaultv1alpha1.ReasonPolicyNotFound, err.Error())
	} else if IsConnectionNotReadyError(err) {
		r.setCondition(role, vaultv1alpha1.ConditionTypeConnectionReady, metav1.ConditionFalse, vaultv1alpha1.ReasonConnectionNotReady, err.Error())
	}

	r.setCondition(role, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, err.Error())
	r.setCondition(role, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, err.Error())

	// Calculate retry
	retryConfig := DefaultRetryConfig()
	retryResult := ShouldRetry(err, role.Status.RetryCount, retryConfig)

	if retryResult.Requeue {
		role.Status.RetryCount = retryResult.RetryCount
		nextRetry := metav1.NewTime(time.Now().Add(retryResult.RequeueAfter))
		role.Status.NextRetryAt = &nextRetry
	}

	if updateErr := r.Status().Update(ctx, role); updateErr != nil {
		log.Error(updateErr, "Failed to update status with error")
		return ctrl.Result{}, updateErr
	}

	if retryResult.Requeue {
		return ctrl.Result{RequeueAfter: retryResult.RequeueAfter}, nil
	}

	return ctrl.Result{}, nil
}

// updateStatusConflict updates the status for a conflict condition
func (r *VaultClusterRoleReconciler) updateStatusConflict(ctx context.Context, role *vaultv1alpha1.VaultClusterRole, err *ConflictError) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	role.Status.Phase = vaultv1alpha1.PhaseConflict
	role.Status.Message = err.Error()

	r.setCondition(role, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonConflict, err.Error())
	r.setCondition(role, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionFalse, vaultv1alpha1.ReasonConflict, err.Error())

	if updateErr := r.Status().Update(ctx, role); updateErr != nil {
		log.Error(updateErr, "Failed to update status with conflict")
		return ctrl.Result{}, updateErr
	}

	// Conflicts are not retried - requires user intervention
	return ctrl.Result{}, nil
}

// setCondition updates or adds a condition to the role status
func (r *VaultClusterRoleReconciler) setCondition(role *vaultv1alpha1.VaultClusterRole, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := vaultv1alpha1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: role.Generation,
	}

	// Find and update existing condition or append new one
	found := false
	for i, c := range role.Status.Conditions {
		if c.Type == condType {
			if c.Status != status {
				role.Status.Conditions[i] = condition
			} else {
				// Only update message and reason if status hasn't changed
				role.Status.Conditions[i].Reason = reason
				role.Status.Conditions[i].Message = message
				role.Status.Conditions[i].ObservedGeneration = role.Generation
			}
			found = true
			break
		}
	}

	if !found {
		role.Status.Conditions = append(role.Status.Conditions, condition)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultClusterRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultClusterRole{}).
		Named("vaultclusterrole").
		Complete(r)
}
