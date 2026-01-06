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
	"time"

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

// VaultPolicyReconciler reconciles a VaultPolicy object
type VaultPolicyReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ClientCache *vault.ClientCache
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultconnections,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *VaultPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling VaultPolicy", "namespace", req.Namespace, "name", req.Name)

	// Fetch the VaultPolicy resource
	policy := &vaultv1alpha1.VaultPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("VaultPolicy not found, likely deleted", "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get VaultPolicy")
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

	// Update last attempt time
	now := metav1.Now()
	policy.Status.LastAttemptAt = &now

	// Set phase to Syncing
	if policy.Status.Phase != vaultv1alpha1.PhaseSyncing && policy.Status.Phase != vaultv1alpha1.PhaseActive {
		policy.Status.Phase = vaultv1alpha1.PhaseSyncing
		if err := r.Status().Update(ctx, policy); err != nil {
			log.Error(err, "Failed to update status to Syncing")
			return ctrl.Result{}, err
		}
	}

	// Get Vault client from cache
	vaultClient, err := r.getVaultClient(ctx, policy)
	if err != nil {
		log.Error(err, "Failed to get Vault client")
		return r.updateStatusError(ctx, policy, err)
	}

	// Validate namespace boundary if enforced
	if policy.Spec.IsEnforceNamespaceBoundary() {
		if err := r.validateNamespaceBoundary(policy); err != nil {
			log.Error(err, "Namespace boundary validation failed")
			return r.updateStatusError(ctx, policy, err)
		}
	}

	// Generate the Vault policy name: {namespace}-{name}
	vaultPolicyName := r.getVaultPolicyName(policy)

	// Check for conflicts
	if err := r.checkConflict(ctx, vaultClient, policy, vaultPolicyName); err != nil {
		log.Error(err, "Conflict detected")
		return r.updateStatusError(ctx, policy, err)
	}

	// Generate HCL with variable substitution
	hcl := r.generatePolicyHCL(policy)

	// Calculate hash of the policy
	specHash := r.calculateSpecHash(policy)

	// Check if we need to update (hash comparison)
	if policy.Status.LastAppliedHash == specHash && policy.Status.Phase == vaultv1alpha1.PhaseActive {
		log.Info("VaultPolicy unchanged, skipping update", "name", vaultPolicyName)
		return ctrl.Result{}, nil
	}

	// Apply policy to Vault
	if err := vaultClient.WritePolicy(ctx, vaultPolicyName, hcl); err != nil {
		log.Error(err, "Failed to write policy to Vault", "policyName", vaultPolicyName)
		return r.updateStatusError(ctx, policy, NewTransientError("failed to write policy to Vault", err))
	}

	// Mark policy as managed
	k8sResource := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	if err := vaultClient.MarkPolicyManaged(ctx, vaultPolicyName, k8sResource); err != nil {
		log.Error(err, "Failed to mark policy as managed", "policyName", vaultPolicyName)
		// Non-fatal error, continue
	}

	// Update status to Active
	policy.Status.Phase = vaultv1alpha1.PhaseActive
	policy.Status.VaultName = vaultPolicyName
	policy.Status.Managed = true
	policy.Status.RulesCount = len(policy.Spec.Rules)
	policy.Status.LastAppliedHash = specHash
	policy.Status.LastSyncedAt = &now
	policy.Status.RetryCount = 0
	policy.Status.NextRetryAt = nil
	policy.Status.Message = ""
	r.setCondition(policy, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, "Policy synced to Vault")
	r.setCondition(policy, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, "Policy synced successfully")

	if err := r.Status().Update(ctx, policy); err != nil {
		log.Error(err, "Failed to update status to Active")
		return ctrl.Result{}, err
	}

	log.Info("VaultPolicy reconciled successfully", "namespace", policy.Namespace, "name", policy.Name, "vaultName", vaultPolicyName)
	return ctrl.Result{}, nil
}

// reconcileDelete handles the deletion of a VaultPolicy
func (r *VaultPolicyReconciler) reconcileDelete(ctx context.Context, policy *vaultv1alpha1.VaultPolicy) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling VaultPolicy deletion", "namespace", policy.Namespace, "name", policy.Name)

	// Update phase to Deleting
	policy.Status.Phase = vaultv1alpha1.PhaseDeleting
	if err := r.Status().Update(ctx, policy); err != nil {
		log.Error(err, "Failed to update status to Deleting")
		return ctrl.Result{}, err
	}

	// Only delete from Vault if deletion policy is Delete
	if policy.Spec.DeletionPolicy == vaultv1alpha1.DeletionPolicyDelete || policy.Spec.DeletionPolicy == "" {
		vaultClient, err := r.getVaultClient(ctx, policy)
		if err != nil {
			// If we can't get the client, log and continue with finalizer removal
			log.Error(err, "Failed to get Vault client during deletion, continuing with finalizer removal")
		} else {
			vaultPolicyName := r.getVaultPolicyName(policy)

			// Delete policy from Vault
			if err := vaultClient.DeletePolicy(ctx, vaultPolicyName); err != nil {
				log.Error(err, "Failed to delete policy from Vault", "policyName", vaultPolicyName)
				// Continue with finalizer removal even if deletion fails
			} else {
				log.Info("Deleted policy from Vault", "policyName", vaultPolicyName)
			}

			// Remove managed marker
			if err := vaultClient.RemovePolicyManaged(ctx, vaultPolicyName); err != nil {
				log.Error(err, "Failed to remove managed marker", "policyName", vaultPolicyName)
				// Non-fatal, continue
			}
		}
	} else {
		log.Info("DeletionPolicy is Retain, keeping policy in Vault", "vaultName", policy.Status.VaultName)
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(policy, vaultv1alpha1.FinalizerName)
	if err := r.Update(ctx, policy); err != nil {
		log.Error(err, "Failed to remove finalizer")
		return ctrl.Result{}, err
	}

	log.Info("VaultPolicy finalizer removed", "namespace", policy.Namespace, "name", policy.Name)
	return ctrl.Result{}, nil
}

// getVaultClient retrieves the Vault client from the cache
func (r *VaultPolicyReconciler) getVaultClient(ctx context.Context, policy *vaultv1alpha1.VaultPolicy) (*vault.Client, error) {
	// Check if connection exists
	conn := &vaultv1alpha1.VaultConnection{}
	if err := r.Get(ctx, client.ObjectKey{Name: policy.Spec.ConnectionRef}, conn); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, NewConnectionNotReadyError(policy.Spec.ConnectionRef, "VaultConnection not found")
		}
		return nil, NewTransientError("failed to get VaultConnection", err)
	}

	// Check if connection is active
	if conn.Status.Phase != vaultv1alpha1.PhaseActive {
		return nil, NewConnectionNotReadyError(policy.Spec.ConnectionRef, fmt.Sprintf("VaultConnection is in %s phase", conn.Status.Phase))
	}

	// Get client from cache
	vaultClient, err := r.ClientCache.Get(policy.Spec.ConnectionRef)
	if err != nil {
		return nil, NewConnectionNotReadyError(policy.Spec.ConnectionRef, "Vault client not found in cache")
	}

	return vaultClient, nil
}

// validateNamespaceBoundary validates that all paths contain the {{namespace}} variable
func (r *VaultPolicyReconciler) validateNamespaceBoundary(policy *vaultv1alpha1.VaultPolicy) error {
	for i, rule := range policy.Spec.Rules {
		// Check if path contains namespace variable
		if !vault.ContainsNamespaceVariable(rule.Path) {
			return NewValidationError(
				fmt.Sprintf("rules[%d].path", i),
				fmt.Sprintf("path %q must contain {{namespace}} variable when enforceNamespaceBoundary is enabled", rule.Path),
			)
		}

		// Check if wildcard appears before namespace (security risk)
		if vault.HasWildcardBeforeNamespace(rule.Path) {
			return NewValidationError(
				fmt.Sprintf("rules[%d].path", i),
				fmt.Sprintf("path %q has wildcard (*) before {{namespace}} variable, which could allow cross-namespace access", rule.Path),
			)
		}
	}

	return nil
}

// getVaultPolicyName returns the Vault policy name in {namespace}-{name} format
func (r *VaultPolicyReconciler) getVaultPolicyName(policy *vaultv1alpha1.VaultPolicy) string {
	return fmt.Sprintf("%s-%s", policy.Namespace, policy.Name)
}

// checkConflict checks for conflicts with existing Vault policies
func (r *VaultPolicyReconciler) checkConflict(ctx context.Context, vaultClient *vault.Client, policy *vaultv1alpha1.VaultPolicy, vaultPolicyName string) error {
	// Check if policy exists in Vault
	exists, err := vaultClient.PolicyExists(ctx, vaultPolicyName)
	if err != nil {
		return NewTransientError("failed to check if policy exists in Vault", err)
	}

	if !exists {
		// No conflict, policy doesn't exist
		return nil
	}

	// Policy exists, check if it's managed by us
	managedBy, err := vaultClient.GetPolicyManagedBy(ctx, vaultPolicyName)
	if err != nil {
		// Can't determine if managed, treat as potential conflict based on policy
		if policy.Spec.ConflictPolicy == vaultv1alpha1.ConflictPolicyAdopt {
			return nil // Adopt policy allows taking over
		}
		return NewTransientError("failed to check policy management status", err)
	}

	k8sResource := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)

	// If managed by the same K8s resource, no conflict
	if managedBy == k8sResource {
		return nil
	}

	// If managed by a different resource, conflict
	if managedBy != "" {
		return NewConflictError("policy", vaultPolicyName, fmt.Sprintf("already managed by %s", managedBy))
	}

	// Policy exists but not managed
	if policy.Spec.ConflictPolicy == vaultv1alpha1.ConflictPolicyAdopt {
		return nil // Adopt policy allows taking over unmanaged policies
	}

	return NewConflictError("policy", vaultPolicyName, "policy already exists in Vault and conflictPolicy is Fail")
}

// generatePolicyHCL generates the HCL policy document with variable substitution
func (r *VaultPolicyReconciler) generatePolicyHCL(policy *vaultv1alpha1.VaultPolicy) string {
	rules := make([]vault.PolicyRule, len(policy.Spec.Rules))

	for i, rule := range policy.Spec.Rules {
		caps := make([]string, len(rule.Capabilities))
		for j, cap := range rule.Capabilities {
			caps[j] = string(cap)
		}

		vaultRule := vault.PolicyRule{
			Path:         rule.Path,
			Capabilities: caps,
			Description:  rule.Description,
		}

		if rule.Parameters != nil {
			vaultRule.Parameters = &vault.PolicyParameters{
				Allowed:  rule.Parameters.Allowed,
				Denied:   rule.Parameters.Denied,
				Required: rule.Parameters.Required,
			}
		}

		rules[i] = vaultRule
	}

	// Generate HCL with namespace and name substitution
	return vault.GeneratePolicyHCL(rules, policy.Namespace, policy.Name)
}

// calculateSpecHash calculates a hash of the policy spec for change detection
func (r *VaultPolicyReconciler) calculateSpecHash(policy *vaultv1alpha1.VaultPolicy) string {
	// Create a copy of spec for hashing (exclude fields that shouldn't trigger updates)
	specForHash := struct {
		ConnectionRef            string                     `json:"connectionRef"`
		Rules                    []vaultv1alpha1.PolicyRule `json:"rules"`
		EnforceNamespaceBoundary *bool                      `json:"enforceNamespaceBoundary,omitempty"`
	}{
		ConnectionRef:            policy.Spec.ConnectionRef,
		Rules:                    policy.Spec.Rules,
		EnforceNamespaceBoundary: policy.Spec.EnforceNamespaceBoundary,
	}

	data, _ := json.Marshal(specForHash)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// updateStatusError updates the status with error information
func (r *VaultPolicyReconciler) updateStatusError(ctx context.Context, policy *vaultv1alpha1.VaultPolicy, err error) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Determine phase based on error type
	if IsConflictError(err) {
		policy.Status.Phase = vaultv1alpha1.PhaseConflict
	} else {
		policy.Status.Phase = vaultv1alpha1.PhaseError
	}

	policy.Status.Message = err.Error()

	// Set appropriate conditions
	if IsValidationError(err) {
		r.setCondition(policy, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonValidationFailed, err.Error())
	} else if IsConflictError(err) {
		r.setCondition(policy, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonConflict, err.Error())
	} else if IsConnectionNotReadyError(err) {
		r.setCondition(policy, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonConnectionNotReady, err.Error())
	} else {
		r.setCondition(policy, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, err.Error())
	}
	r.setCondition(policy, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, err.Error())

	// Calculate retry if applicable
	retryConfig := DefaultRetryConfig()
	retryResult := ShouldRetry(err, policy.Status.RetryCount, retryConfig)

	if retryResult.Requeue {
		policy.Status.RetryCount = retryResult.RetryCount
		nextRetry := metav1.NewTime(time.Now().Add(retryResult.RequeueAfter))
		policy.Status.NextRetryAt = &nextRetry
	} else {
		policy.Status.NextRetryAt = nil
	}

	if updateErr := r.Status().Update(ctx, policy); updateErr != nil {
		log.Error(updateErr, "Failed to update error status")
		return ctrl.Result{}, updateErr
	}

	if retryResult.Requeue {
		return ctrl.Result{RequeueAfter: retryResult.RequeueAfter}, nil
	}

	// If not retryable, return nil error to avoid controller requeuing
	return ctrl.Result{}, nil
}

// setCondition sets or updates a condition on the policy status
func (r *VaultPolicyReconciler) setCondition(policy *vaultv1alpha1.VaultPolicy, condType string, status metav1.ConditionStatus, reason, message string) {
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
func (r *VaultPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultPolicy{}).
		Named("vaultpolicy").
		Complete(r)
}
