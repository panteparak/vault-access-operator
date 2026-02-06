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

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/controller/syncerror"
	"github.com/panteparak/vault-access-operator/shared/controller/vaultclient"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// Handler provides shared policy sync/cleanup logic.
// It works with PolicyAdapter to handle both VaultPolicy and VaultClusterPolicy.
type Handler struct {
	client      client.Client
	clientCache *vault.ClientCache
	eventBus    *events.EventBus
	log         logr.Logger
}

// NewHandler creates a new policy Handler.
func NewHandler(c client.Client, cache *vault.ClientCache, bus *events.EventBus, log logr.Logger) *Handler {
	return &Handler{
		client:      c,
		clientCache: cache,
		eventBus:    bus,
		log:         log,
	}
}

// SyncPolicy synchronizes a policy to Vault.
func (h *Handler) SyncPolicy(ctx context.Context, adapter domain.PolicyAdapter) error {
	log := logr.FromContextOrDiscard(ctx)
	vaultPolicyName := adapter.GetVaultPolicyName()

	// Update last attempt time
	now := metav1.Now()
	adapter.SetLastAttemptAt(&now)

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

	// Validate namespace boundary if enforced (namespaced policies only)
	if adapter.IsEnforceNamespaceBoundary() {
		if err := h.validateNamespaceBoundary(adapter); err != nil {
			return h.handleSyncError(ctx, adapter, err)
		}
	}

	// Check for conflicts
	if err := h.checkConflict(ctx, vaultClient, adapter, vaultPolicyName); err != nil {
		return h.handleSyncError(ctx, adapter, err)
	}

	// Generate HCL with variable substitution
	namespace := ""
	if adapter.IsNamespaced() {
		namespace = adapter.GetNamespace()
	}
	hcl := h.generatePolicyHCL(adapter.GetRules(), namespace, adapter.GetName())

	// Calculate hash for change detection
	specHash := h.calculateHash(hcl)

	// Skip update if unchanged
	if adapter.GetLastAppliedHash() == specHash && adapter.GetPhase() == vaultv1alpha1.PhaseActive {
		log.V(1).Info("policy unchanged, skipping update", "policyName", vaultPolicyName)
		return nil
	}

	// Write policy to Vault
	if err := vaultClient.WritePolicy(ctx, vaultPolicyName, hcl); err != nil {
		return h.handleSyncError(ctx, adapter, infraerrors.NewTransientError("write policy", err))
	}

	// Mark as managed
	k8sResource := adapter.GetK8sResourceIdentifier()
	if err := vaultClient.MarkPolicyManaged(ctx, vaultPolicyName, k8sResource); err != nil {
		log.V(1).Info("failed to mark policy as managed (non-fatal)", "error", err.Error())
	}

	// Update status to Active
	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	adapter.SetVaultName(vaultPolicyName)
	adapter.SetManaged(true)
	adapter.SetRulesCount(len(adapter.GetRules()))
	adapter.SetLastAppliedHash(specHash)
	adapter.SetLastSyncedAt(&now)
	adapter.SetRetryCount(0)
	adapter.SetNextRetryAt(nil)
	adapter.SetMessage("")
	h.setCondition(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Policy synced to Vault")
	h.setCondition(adapter, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Policy synced successfully")

	if err := h.client.Status().Update(ctx, adapter.GetObject()); err != nil {
		return fmt.Errorf("failed to update status to Active: %w", err)
	}

	// Publish event
	if h.eventBus != nil {
		resource := events.ResourceInfo{
			Name:           adapter.GetName(),
			Namespace:      adapter.GetNamespace(),
			ClusterScoped:  !adapter.IsNamespaced(),
			ConnectionName: adapter.GetConnectionRef(),
		}
		h.eventBus.PublishAsync(ctx, events.NewPolicyCreated(vaultPolicyName, resource))
	}

	log.Info("policy synced successfully", "policyName", vaultPolicyName)
	return nil
}

// CleanupPolicy removes a policy from Vault.
func (h *Handler) CleanupPolicy(ctx context.Context, adapter domain.PolicyAdapter) error {
	log := logr.FromContextOrDiscard(ctx)
	vaultPolicyName := adapter.GetVaultPolicyName()

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
			if err := vaultClient.DeletePolicy(ctx, vaultPolicyName); err != nil {
				log.Error(err, "failed to delete policy from Vault")
			} else {
				log.Info("deleted policy from Vault", "policyName", vaultPolicyName)
			}

			// Remove managed marker
			if err := vaultClient.RemovePolicyManaged(ctx, vaultPolicyName); err != nil {
				log.V(1).Info("failed to remove managed marker (non-fatal)", "error", err.Error())
			}
		}
	} else {
		log.Info("DeletionPolicy is Retain, keeping policy in Vault", "policyName", vaultPolicyName)
	}

	// Publish event
	if h.eventBus != nil {
		resource := events.ResourceInfo{
			Name:           adapter.GetName(),
			Namespace:      adapter.GetNamespace(),
			ClusterScoped:  !adapter.IsNamespaced(),
			ConnectionName: adapter.GetConnectionRef(),
		}
		h.eventBus.PublishAsync(ctx, events.NewPolicyDeleted(vaultPolicyName, resource))
	}

	log.Info("policy cleanup completed", "policyName", vaultPolicyName)
	return nil
}

// getVaultClient retrieves a Vault client for the policy's connection.
func (h *Handler) getVaultClient(ctx context.Context, adapter domain.PolicyAdapter) (*vault.Client, error) {
	return vaultclient.Resolve(ctx, h.client, h.clientCache,
		adapter.GetConnectionRef(), adapter.GetK8sResourceIdentifier())
}

// validateNamespaceBoundary validates that paths contain namespace variable.
func (h *Handler) validateNamespaceBoundary(adapter domain.PolicyAdapter) error {
	for i, rule := range adapter.GetRules() {
		if !vault.ContainsNamespaceVariable(rule.Path) {
			return infraerrors.NewValidationError(
				fmt.Sprintf("rules[%d].path", i),
				rule.Path,
				"must contain {{namespace}} variable when enforceNamespaceBoundary is enabled",
			)
		}

		if vault.HasWildcardBeforeNamespace(rule.Path) {
			return infraerrors.NewValidationError(
				fmt.Sprintf("rules[%d].path", i),
				rule.Path,
				"has wildcard (*) before {{namespace}} variable, which could allow cross-namespace access",
			)
		}
	}
	return nil
}

// checkConflict checks for conflicts with existing Vault policies.
func (h *Handler) checkConflict(
	ctx context.Context,
	vaultClient *vault.Client,
	adapter domain.PolicyAdapter,
	vaultPolicyName string,
) error {
	exists, err := vaultClient.PolicyExists(ctx, vaultPolicyName)
	if err != nil {
		return infraerrors.NewTransientError("check policy existence", err)
	}

	if !exists {
		return nil
	}

	// Policy exists, check ownership
	managedBy, err := vaultClient.GetPolicyManagedBy(ctx, vaultPolicyName)
	if err != nil {
		// Can't determine ownership
		if adapter.GetConflictPolicy() == vaultv1alpha1.ConflictPolicyAdopt {
			return nil
		}
		return infraerrors.NewTransientError("check policy ownership", err)
	}

	k8sResource := adapter.GetK8sResourceIdentifier()

	// Same owner, no conflict
	if managedBy == k8sResource {
		return nil
	}

	// Different owner
	if managedBy != "" {
		return infraerrors.NewConflictError("policy", vaultPolicyName, fmt.Sprintf("already managed by %s", managedBy))
	}

	// Exists but not managed - check conflict policy
	if adapter.GetConflictPolicy() == vaultv1alpha1.ConflictPolicyAdopt {
		return nil
	}

	return infraerrors.NewConflictError(
		"policy", vaultPolicyName,
		"already exists in Vault and is not managed by this operator",
	)
}

// generatePolicyHCL generates HCL for the policy rules.
func (h *Handler) generatePolicyHCL(rules []vaultv1alpha1.PolicyRule, namespace, name string) string {
	vaultRules := make([]vault.PolicyRule, len(rules))

	for i, rule := range rules {
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

		vaultRules[i] = vaultRule
	}

	return vault.GeneratePolicyHCL(vaultRules, namespace, name)
}

// calculateHash calculates SHA256 hash of content.
func (h *Handler) calculateHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// handleSyncError updates status for errors.
func (h *Handler) handleSyncError(ctx context.Context, adapter domain.PolicyAdapter, err error) error {
	return syncerror.Handle(ctx, h.client, h.log, adapter, err)
}

// setCondition sets or updates a condition on the adapter.
func (h *Handler) setCondition(
	adapter domain.PolicyAdapter,
	condType string,
	status metav1.ConditionStatus,
	reason, message string,
) {
	adapter.SetConditions(conditions.Set(
		adapter.GetConditions(), adapter.GetGeneration(),
		condType, status, reason, message,
	))
}
