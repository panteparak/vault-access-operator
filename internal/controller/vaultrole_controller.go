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
	// defaultVaultRoleSyncInterval is the default interval between reconciliations for VaultRole
	defaultVaultRoleSyncInterval = 5 * time.Minute
)

// VaultRoleReconciler reconciles a VaultRole object
type VaultRoleReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ClientCache *vault.ClientCache
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultroles/finalizers,verbs=update
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultconnections,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *VaultRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling VaultRole", "namespace", req.Namespace, "name", req.Name)

	// Fetch the VaultRole resource
	role := &vaultv1alpha1.VaultRole{}
	if err := r.Get(ctx, req.NamespacedName, role); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("VaultRole not found, may have been deleted", "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get VaultRole")
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

	// Update status to Syncing
	if role.Status.Phase != vaultv1alpha1.PhaseSyncing && role.Status.Phase != vaultv1alpha1.PhaseActive {
		role.Status.Phase = vaultv1alpha1.PhaseSyncing
		now := metav1.Now()
		role.Status.LastAttemptAt = &now
		if err := r.Status().Update(ctx, role); err != nil {
			log.Error(err, "Failed to update status to Syncing")
			return ctrl.Result{}, err
		}
	}

	// Get Vault client from cache
	vaultClient, err := r.ClientCache.Get(role.Spec.ConnectionRef)
	if err != nil {
		log.Error(err, "Failed to get Vault client from cache", "connectionRef", role.Spec.ConnectionRef)
		return r.updateStatusError(ctx, role, NewConnectionNotReadyError(role.Spec.ConnectionRef, "client not found in cache"))
	}

	// Resolve policies
	resolvedPolicies, err := r.resolvePolicies(ctx, role)
	if err != nil {
		log.Error(err, "Failed to resolve policies")
		return r.updateStatusError(ctx, role, err)
	}

	// Build service account bindings (all SAs in same namespace as resource)
	boundServiceAccounts := role.Spec.ServiceAccounts

	// Calculate the role name in Vault (namespace-name format)
	vaultRoleName := fmt.Sprintf("%s-%s", role.Namespace, role.Name)

	// Check for conflicts
	if err := r.checkForConflicts(ctx, vaultClient, role, vaultRoleName); err != nil {
		log.Error(err, "Conflict detected for role", "vaultRoleName", vaultRoleName)
		return r.updateStatusConflict(ctx, role, err)
	}

	// Build the auth path
	authPath := role.Spec.AuthPath
	if authPath == "" {
		authPath = "auth/kubernetes"
	}

	// Build role data for Vault
	roleData := map[string]interface{}{
		"bound_service_account_names":      boundServiceAccounts,
		"bound_service_account_namespaces": []string{role.Namespace},
		"policies":                         resolvedPolicies,
	}

	// Add optional TTL settings
	if role.Spec.TokenTTL != "" {
		roleData["token_ttl"] = role.Spec.TokenTTL
	}
	if role.Spec.TokenMaxTTL != "" {
		roleData["token_max_ttl"] = role.Spec.TokenMaxTTL
	}

	// Create/update Kubernetes auth role in Vault
	if err := vaultClient.WriteKubernetesAuthRole(ctx, authPath, vaultRoleName, roleData); err != nil {
		log.Error(err, "Failed to write Kubernetes auth role to Vault", "vaultRoleName", vaultRoleName)
		return r.updateStatusError(ctx, role, NewTransientError("failed to write role to Vault", err))
	}

	// Mark as managed
	k8sResource := fmt.Sprintf("%s/%s", role.Namespace, role.Name)
	if err := vaultClient.MarkRoleManaged(ctx, vaultRoleName, k8sResource); err != nil {
		log.Error(err, "Failed to mark role as managed", "vaultRoleName", vaultRoleName)
		// Non-fatal error, continue
	}

	// Update status to Active
	now := metav1.Now()
	role.Status.Phase = vaultv1alpha1.PhaseActive
	role.Status.VaultRoleName = vaultRoleName
	role.Status.BoundServiceAccounts = boundServiceAccounts
	role.Status.ResolvedPolicies = resolvedPolicies
	role.Status.Managed = true
	role.Status.LastSyncedAt = &now
	role.Status.RetryCount = 0
	role.Status.NextRetryAt = nil
	role.Status.Message = ""
	r.setCondition(role, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, "Role synced successfully")
	r.setCondition(role, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, "Role synced to Vault")
	r.setCondition(role, vaultv1alpha1.ConditionTypePoliciesResolved, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, fmt.Sprintf("Resolved %d policies", len(resolvedPolicies)))

	if err := r.Status().Update(ctx, role); err != nil {
		log.Error(err, "Failed to update status to Active")
		return ctrl.Result{}, err
	}

	log.Info("VaultRole reconciled successfully",
		"namespace", role.Namespace,
		"name", role.Name,
		"vaultRoleName", vaultRoleName,
		"policies", resolvedPolicies,
		"serviceAccounts", boundServiceAccounts)

	return ctrl.Result{RequeueAfter: defaultVaultRoleSyncInterval}, nil
}

// reconcileDelete handles the deletion of a VaultRole
func (r *VaultRoleReconciler) reconcileDelete(ctx context.Context, role *vaultv1alpha1.VaultRole) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling VaultRole deletion", "namespace", role.Namespace, "name", role.Name)

	// Update phase to Deleting
	role.Status.Phase = vaultv1alpha1.PhaseDeleting
	if err := r.Status().Update(ctx, role); err != nil {
		log.Error(err, "Failed to update status to Deleting")
		return ctrl.Result{}, err
	}

	// Check deletion policy
	if role.Spec.DeletionPolicy == vaultv1alpha1.DeletionPolicyDelete {
		// Get Vault client from cache
		vaultClient, err := r.ClientCache.Get(role.Spec.ConnectionRef)
		if err != nil {
			log.Error(err, "Failed to get Vault client from cache, skipping Vault cleanup", "connectionRef", role.Spec.ConnectionRef)
			// Continue to remove finalizer even if we can't connect to Vault
		} else {
			vaultRoleName := fmt.Sprintf("%s-%s", role.Namespace, role.Name)
			authPath := role.Spec.AuthPath
			if authPath == "" {
				authPath = "auth/kubernetes"
			}

			// Delete the role from Vault
			if err := vaultClient.DeleteKubernetesAuthRole(ctx, authPath, vaultRoleName); err != nil {
				log.Error(err, "Failed to delete Kubernetes auth role from Vault", "vaultRoleName", vaultRoleName)
				// Continue to remove finalizer even if deletion fails
			} else {
				log.Info("Deleted Kubernetes auth role from Vault", "vaultRoleName", vaultRoleName)
			}

			// Remove managed marker
			if err := vaultClient.RemoveRoleManaged(ctx, vaultRoleName); err != nil {
				log.Error(err, "Failed to remove managed marker for role", "vaultRoleName", vaultRoleName)
				// Non-fatal error
			}
		}
	} else {
		log.Info("DeletionPolicy is Retain, skipping Vault role deletion")
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(role, vaultv1alpha1.FinalizerName)
	if err := r.Update(ctx, role); err != nil {
		log.Error(err, "Failed to remove finalizer")
		return ctrl.Result{}, err
	}

	log.Info("VaultRole finalizer removed", "namespace", role.Namespace, "name", role.Name)
	return ctrl.Result{}, nil
}

// resolvePolicies resolves policy references to Vault policy names
func (r *VaultRoleReconciler) resolvePolicies(ctx context.Context, role *vaultv1alpha1.VaultRole) ([]string, error) {
	log := logf.FromContext(ctx)
	resolvedPolicies := make([]string, 0, len(role.Spec.Policies))

	for _, policyRef := range role.Spec.Policies {
		var vaultPolicyName string

		switch policyRef.Kind {
		case "VaultClusterPolicy":
			// VaultClusterPolicy uses Name directly
			clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{}
			if err := r.Get(ctx, types.NamespacedName{Name: policyRef.Name}, clusterPolicy); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, NewPolicyNotFoundError(policyRef.Kind, policyRef.Name, "")
				}
				return nil, fmt.Errorf("failed to get VaultClusterPolicy %q: %w", policyRef.Name, err)
			}
			vaultPolicyName = policyRef.Name
			log.V(1).Info("Resolved VaultClusterPolicy", "name", policyRef.Name, "vaultPolicyName", vaultPolicyName)

		case "VaultPolicy":
			// VaultPolicy: if no namespace in ref, default to resource's namespace
			namespace := policyRef.Namespace
			if namespace == "" {
				namespace = role.Namespace
			}

			policy := &vaultv1alpha1.VaultPolicy{}
			if err := r.Get(ctx, types.NamespacedName{Name: policyRef.Name, Namespace: namespace}, policy); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, NewPolicyNotFoundError(policyRef.Kind, policyRef.Name, namespace)
				}
				return nil, fmt.Errorf("failed to get VaultPolicy %s/%s: %w", namespace, policyRef.Name, err)
			}
			// Format as {namespace}-{name}
			vaultPolicyName = fmt.Sprintf("%s-%s", namespace, policyRef.Name)
			log.V(1).Info("Resolved VaultPolicy", "namespace", namespace, "name", policyRef.Name, "vaultPolicyName", vaultPolicyName)

		default:
			return nil, NewValidationError("policies", fmt.Sprintf("unsupported policy kind: %s", policyRef.Kind))
		}

		resolvedPolicies = append(resolvedPolicies, vaultPolicyName)
	}

	return resolvedPolicies, nil
}

// checkForConflicts checks if there are conflicts with existing Vault roles
func (r *VaultRoleReconciler) checkForConflicts(ctx context.Context, vaultClient *vault.Client, role *vaultv1alpha1.VaultRole, vaultRoleName string) error {
	log := logf.FromContext(ctx)

	authPath := role.Spec.AuthPath
	if authPath == "" {
		authPath = "auth/kubernetes"
	}

	// Check if role exists in Vault
	exists, err := vaultClient.KubernetesAuthRoleExists(ctx, authPath, vaultRoleName)
	if err != nil {
		return NewTransientError("failed to check if role exists", err)
	}

	if !exists {
		// No conflict, role doesn't exist
		return nil
	}

	// Check if it's managed by this operator
	managedBy, err := vaultClient.GetRoleManagedBy(ctx, vaultRoleName)
	if err != nil {
		log.Error(err, "Failed to check if role is managed", "vaultRoleName", vaultRoleName)
		// Continue with conflict check
	}

	k8sResource := fmt.Sprintf("%s/%s", role.Namespace, role.Name)

	// If managed by this exact resource, no conflict
	if managedBy == k8sResource {
		return nil
	}

	// If managed by another resource, it's a conflict
	if managedBy != "" {
		return NewConflictError("role", vaultRoleName, fmt.Sprintf("already managed by %s", managedBy))
	}

	// Role exists but not managed by operator
	switch role.Spec.ConflictPolicy {
	case vaultv1alpha1.ConflictPolicyAdopt:
		log.Info("Adopting existing unmanaged role", "vaultRoleName", vaultRoleName)
		return nil
	case vaultv1alpha1.ConflictPolicyFail:
		fallthrough
	default:
		return NewConflictError("role", vaultRoleName, "role exists but is not managed by this operator")
	}
}

// updateStatusError updates the status to reflect an error condition
func (r *VaultRoleReconciler) updateStatusError(ctx context.Context, role *vaultv1alpha1.VaultRole, err error) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	role.Status.Phase = vaultv1alpha1.PhaseError
	role.Status.Message = err.Error()

	// Update retry info
	retryConfig := DefaultRetryConfig()
	retryResult := ShouldRetry(err, role.Status.RetryCount, retryConfig)
	role.Status.RetryCount = retryResult.RetryCount

	if retryResult.Requeue {
		nextRetry := metav1.NewTime(time.Now().Add(retryResult.RequeueAfter))
		role.Status.NextRetryAt = &nextRetry
	}

	// Set conditions based on error type
	if IsConnectionNotReadyError(err) {
		r.setCondition(role, vaultv1alpha1.ConditionTypeConnectionReady, metav1.ConditionFalse, vaultv1alpha1.ReasonConnectionNotReady, err.Error())
	} else if IsPolicyNotFoundError(err) {
		r.setCondition(role, vaultv1alpha1.ConditionTypePoliciesResolved, metav1.ConditionFalse, vaultv1alpha1.ReasonPolicyNotFound, err.Error())
	} else if IsValidationError(err) {
		r.setCondition(role, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonValidationFailed, err.Error())
	} else {
		r.setCondition(role, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, err.Error())
	}

	r.setCondition(role, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, err.Error())

	if updateErr := r.Status().Update(ctx, role); updateErr != nil {
		log.Error(updateErr, "Failed to update error status")
		return ctrl.Result{}, updateErr
	}

	if retryResult.Requeue {
		log.Info("Will retry reconciliation", "after", retryResult.RequeueAfter, "retryCount", retryResult.RetryCount)
		return ctrl.Result{RequeueAfter: retryResult.RequeueAfter}, nil
	}

	return ctrl.Result{}, nil
}

// updateStatusConflict updates the status to reflect a conflict condition
func (r *VaultRoleReconciler) updateStatusConflict(ctx context.Context, role *vaultv1alpha1.VaultRole, err error) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	role.Status.Phase = vaultv1alpha1.PhaseConflict
	role.Status.Message = err.Error()

	r.setCondition(role, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonConflict, err.Error())
	r.setCondition(role, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionFalse, vaultv1alpha1.ReasonConflict, err.Error())

	if updateErr := r.Status().Update(ctx, role); updateErr != nil {
		log.Error(updateErr, "Failed to update conflict status")
		return ctrl.Result{}, updateErr
	}

	// Conflicts are not retried automatically
	return ctrl.Result{}, nil
}

// setCondition sets or updates a condition on the VaultRole
func (r *VaultRoleReconciler) setCondition(role *vaultv1alpha1.VaultRole, condType string, status metav1.ConditionStatus, reason, message string) {
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
func (r *VaultRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultRole{}).
		Named("vaultrole").
		Complete(r)
}
