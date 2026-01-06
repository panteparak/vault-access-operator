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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// VaultClusterPolicyReconciler reconciles a VaultClusterPolicy object
type VaultClusterPolicyReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ClientCache *vault.ClientCache
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultclusterpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultconnections,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *VaultClusterPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling VaultClusterPolicy", "name", req.Name)

	// Fetch the VaultClusterPolicy resource
	policy := &vaultv1alpha1.VaultClusterPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("VaultClusterPolicy not found, ignoring", "name", req.Name)
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get VaultClusterPolicy")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !policy.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, policy)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(policy, vaultv1alpha1.FinalizerName) {
		controllerutil.AddFinalizer(policy, vaultv1alpha1.FinalizerName)
		if err := r.Update(ctx, policy); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Update LastAttemptAt
	now := metav1.Now()
	policy.Status.LastAttemptAt = &now

	// Set phase to Syncing if not already in an active state
	if policy.Status.Phase == "" || policy.Status.Phase == vaultv1alpha1.PhasePending {
		policy.Status.Phase = vaultv1alpha1.PhaseSyncing
		if err := r.Status().Update(ctx, policy); err != nil {
			log.Error(err, "Failed to update status to Syncing")
			return ctrl.Result{}, err
		}
	}

	// Get Vault client from cache
	vaultClient, err := r.ClientCache.Get(policy.Spec.ConnectionRef)
	if err != nil {
		log.Error(err, "Failed to get Vault client from cache", "connectionRef", policy.Spec.ConnectionRef)
		connErr := NewConnectionNotReadyError(policy.Spec.ConnectionRef, "client not found in cache")
		return r.updateStatusError(ctx, policy, connErr)
	}

	// Check if the client is authenticated
	if !vaultClient.IsAuthenticated() {
		log.Error(nil, "Vault client not authenticated", "connectionRef", policy.Spec.ConnectionRef)
		connErr := NewConnectionNotReadyError(policy.Spec.ConnectionRef, "client not authenticated")
		return r.updateStatusError(ctx, policy, connErr)
	}

	// Vault policy name is the same as the Kubernetes resource name for cluster-scoped
	vaultPolicyName := policy.Name

	// Check for conflicts
	if err := r.checkConflict(ctx, vaultClient, policy, vaultPolicyName); err != nil {
		if IsConflictError(err) {
			return r.updateStatusConflict(ctx, policy, err)
		}
		return r.updateStatusError(ctx, policy, err)
	}

	// Convert API rules to vault.PolicyRule
	vaultRules := r.convertRules(policy.Spec.Rules)

	// Generate HCL from rules (empty namespace for cluster-scoped)
	hcl := vault.GeneratePolicyHCL(vaultRules, "", policy.Name)

	// Calculate hash of the HCL
	hash := r.calculateHash(hcl)

	// Check if policy needs to be updated
	if policy.Status.LastAppliedHash == hash && policy.Status.Phase == vaultv1alpha1.PhaseActive {
		log.Info("Policy already up to date", "name", policy.Name, "hash", hash)
		return ctrl.Result{}, nil
	}

	// Apply policy to Vault
	if err := vaultClient.WritePolicy(ctx, vaultPolicyName, hcl); err != nil {
		log.Error(err, "Failed to write policy to Vault", "name", vaultPolicyName)
		return r.updateStatusError(ctx, policy, NewTransientError("failed to write policy", err))
	}

	// Mark policy as managed
	k8sResource := policy.Name // cluster-scoped, no namespace
	if err := vaultClient.MarkPolicyManaged(ctx, vaultPolicyName, k8sResource); err != nil {
		log.Error(err, "Failed to mark policy as managed", "name", vaultPolicyName)
		// Non-fatal error, continue
	}

	// Update status to Active
	return r.updateStatusSuccess(ctx, policy, vaultPolicyName, hash)
}

// reconcileDelete handles the deletion of a VaultClusterPolicy
func (r *VaultClusterPolicyReconciler) reconcileDelete(ctx context.Context, policy *vaultv1alpha1.VaultClusterPolicy) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling VaultClusterPolicy deletion", "name", policy.Name)

	// Update phase to Deleting
	policy.Status.Phase = vaultv1alpha1.PhaseDeleting
	if err := r.Status().Update(ctx, policy); err != nil {
		log.Error(err, "Failed to update status to Deleting")
		return ctrl.Result{}, err
	}

	// Only delete from Vault if DeletionPolicy is Delete
	if policy.Spec.DeletionPolicy == vaultv1alpha1.DeletionPolicyDelete || policy.Spec.DeletionPolicy == "" {
		// Get Vault client from cache
		vaultClient, err := r.ClientCache.Get(policy.Spec.ConnectionRef)
		if err != nil {
			log.Info("Vault client not found, skipping Vault cleanup", "connectionRef", policy.Spec.ConnectionRef)
		} else if vaultClient.IsAuthenticated() {
			vaultPolicyName := policy.Name

			// Delete policy from Vault
			if err := vaultClient.DeletePolicy(ctx, vaultPolicyName); err != nil {
				log.Error(err, "Failed to delete policy from Vault", "name", vaultPolicyName)
				// Continue with finalizer removal even if Vault deletion fails
			}

			// Remove managed marker
			if err := vaultClient.RemovePolicyManaged(ctx, vaultPolicyName); err != nil {
				log.Error(err, "Failed to remove policy managed marker", "name", vaultPolicyName)
				// Continue with finalizer removal
			}

			log.Info("Deleted policy from Vault", "name", vaultPolicyName)
		}
	} else {
		log.Info("DeletionPolicy is Retain, skipping Vault policy deletion", "name", policy.Name)
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(policy, vaultv1alpha1.FinalizerName)
	if err := r.Update(ctx, policy); err != nil {
		log.Error(err, "Failed to remove finalizer")
		return ctrl.Result{}, err
	}

	log.Info("VaultClusterPolicy finalizer removed", "name", policy.Name)
	return ctrl.Result{}, nil
}

// checkConflict checks if the policy exists in Vault and handles conflict policy
func (r *VaultClusterPolicyReconciler) checkConflict(ctx context.Context, vaultClient *vault.Client, policy *vaultv1alpha1.VaultClusterPolicy, vaultPolicyName string) error {
	log := logf.FromContext(ctx)

	// Check if policy exists in Vault
	exists, err := vaultClient.PolicyExists(ctx, vaultPolicyName)
	if err != nil {
		return NewTransientError("failed to check policy existence", err)
	}

	if !exists {
		// No conflict, policy doesn't exist
		return nil
	}

	// Policy exists, check if it's managed by us
	managedBy, err := vaultClient.GetPolicyManagedBy(ctx, vaultPolicyName)
	if err != nil {
		log.Info("Failed to get policy managed by, assuming not managed", "error", err.Error())
		managedBy = ""
	}

	// If managed by the same resource, no conflict
	k8sResource := policy.Name
	if managedBy == k8sResource {
		return nil
	}

	// Policy exists and is not managed by us (or managed by a different resource)
	if managedBy != "" {
		// Managed by a different resource
		return NewConflictError("policy", vaultPolicyName, fmt.Sprintf("already managed by %s", managedBy))
	}

	// Policy exists but not managed by operator
	switch policy.Spec.ConflictPolicy {
	case vaultv1alpha1.ConflictPolicyAdopt:
		log.Info("Adopting existing policy", "name", vaultPolicyName)
		return nil
	case vaultv1alpha1.ConflictPolicyFail, "":
		return NewConflictError("policy", vaultPolicyName, "exists in Vault but not managed by operator")
	default:
		return NewConflictError("policy", vaultPolicyName, "exists in Vault but not managed by operator")
	}
}

// convertRules converts API PolicyRule to vault.PolicyRule
func (r *VaultClusterPolicyReconciler) convertRules(rules []vaultv1alpha1.PolicyRule) []vault.PolicyRule {
	vaultRules := make([]vault.PolicyRule, len(rules))
	for i, rule := range rules {
		vaultRule := vault.PolicyRule{
			Path:        rule.Path,
			Description: rule.Description,
		}

		// Convert capabilities
		vaultRule.Capabilities = make([]string, len(rule.Capabilities))
		for j, cap := range rule.Capabilities {
			vaultRule.Capabilities[j] = string(cap)
		}

		// Convert parameters if present
		if rule.Parameters != nil {
			vaultRule.Parameters = &vault.PolicyParameters{
				Allowed:  rule.Parameters.Allowed,
				Denied:   rule.Parameters.Denied,
				Required: rule.Parameters.Required,
			}
		}

		vaultRules[i] = vaultRule
	}
	return vaultRules
}

// calculateHash calculates SHA256 hash of the content
func (r *VaultClusterPolicyReconciler) calculateHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// updateStatusSuccess updates the status to reflect a successful reconciliation
func (r *VaultClusterPolicyReconciler) updateStatusSuccess(ctx context.Context, policy *vaultv1alpha1.VaultClusterPolicy, vaultName, hash string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	now := metav1.Now()
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.VaultName = vaultName
	policy.Status.Managed = true
	policy.Status.RulesCount = len(policy.Spec.Rules)
	policy.Status.LastAppliedHash = hash
	policy.Status.LastSyncedAt = &now
	policy.Status.LastAttemptAt = &now
	policy.Status.RetryCount = 0
	policy.Status.NextRetryAt = nil
	policy.Status.Message = ""

	r.setCondition(policy, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, "Policy synced to Vault")
	r.setCondition(policy, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, "Policy is in sync")

	if err := r.Status().Update(ctx, policy); err != nil {
		log.Error(err, "Failed to update status to Active")
		return ctrl.Result{}, err
	}

	log.Info("VaultClusterPolicy reconciled successfully", "name", policy.Name, "vaultName", vaultName, "hash", hash)
	return ctrl.Result{}, nil
}

// updateStatusError updates the status to reflect an error
func (r *VaultClusterPolicyReconciler) updateStatusError(ctx context.Context, policy *vaultv1alpha1.VaultClusterPolicy, err error) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	now := metav1.Now()
	policy.Status.Phase = vaultv1alpha1.PhaseError
	policy.Status.Message = err.Error()
	policy.Status.LastAttemptAt = &now

	// Calculate retry
	retryConfig := DefaultRetryConfig()
	retryResult := ShouldRetry(err, policy.Status.RetryCount, retryConfig)

	if retryResult.Requeue {
		policy.Status.RetryCount = retryResult.RetryCount
		nextRetry := metav1.NewTime(now.Add(retryResult.RequeueAfter))
		policy.Status.NextRetryAt = &nextRetry
	} else if retryResult.GiveUp {
		policy.Status.NextRetryAt = nil
	}

	r.setCondition(policy, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, err.Error())
	r.setCondition(policy, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, "Failed to sync policy")

	if updateErr := r.Status().Update(ctx, policy); updateErr != nil {
		log.Error(updateErr, "Failed to update error status")
		return ctrl.Result{}, updateErr
	}

	if retryResult.Requeue {
		log.Info("Will retry after error", "error", err.Error(), "retryCount", policy.Status.RetryCount, "requeueAfter", retryResult.RequeueAfter)
		return ctrl.Result{RequeueAfter: retryResult.RequeueAfter}, nil
	}

	log.Error(err, "Giving up on reconciliation", "retryCount", policy.Status.RetryCount)
	return ctrl.Result{}, nil
}

// updateStatusConflict updates the status to reflect a conflict
func (r *VaultClusterPolicyReconciler) updateStatusConflict(ctx context.Context, policy *vaultv1alpha1.VaultClusterPolicy, err error) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	now := metav1.Now()
	policy.Status.Phase = vaultv1alpha1.PhaseConflict
	policy.Status.Message = err.Error()
	policy.Status.LastAttemptAt = &now
	policy.Status.NextRetryAt = nil // Conflicts don't retry automatically

	r.setCondition(policy, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonConflict, err.Error())
	r.setCondition(policy, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionFalse, vaultv1alpha1.ReasonConflict, "Policy conflict detected")

	if updateErr := r.Status().Update(ctx, policy); updateErr != nil {
		log.Error(updateErr, "Failed to update conflict status")
		return ctrl.Result{}, updateErr
	}

	log.Info("Policy conflict detected", "name", policy.Name, "error", err.Error())
	return ctrl.Result{}, nil
}

// setCondition updates or adds a condition to the policy status
func (r *VaultClusterPolicyReconciler) setCondition(policy *vaultv1alpha1.VaultClusterPolicy, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := vaultv1alpha1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: policy.Generation,
	}

	// Find and update existing condition or append new one
	found := false
	for i, c := range policy.Status.Conditions {
		if c.Type == condType {
			if c.Status != status {
				policy.Status.Conditions[i] = condition
			} else {
				// Only update message and reason if status hasn't changed
				policy.Status.Conditions[i].Reason = reason
				policy.Status.Conditions[i].Message = message
				policy.Status.Conditions[i].ObservedGeneration = policy.Generation
			}
			found = true
			break
		}
	}

	if !found {
		policy.Status.Conditions = append(policy.Status.Conditions, condition)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultClusterPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultClusterPolicy{}).
		Named("vaultclusterpolicy").
		Complete(r)
}
