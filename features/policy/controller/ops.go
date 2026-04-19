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

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/binding"
	"github.com/panteparak/vault-access-operator/shared/controller/drift"
	"github.com/panteparak/vault-access-operator/shared/controller/dryrun"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// PolicyOps implements workflow.ResourceOps for policy resources.
// It holds the adapter and handler reference, and captures the generated HCL
// between PrepareContent and WriteToVault/DetectDrift calls.
type PolicyOps struct {
	adapter   domain.PolicyAdapter
	handler   *Handler
	namespace string // resolved namespace for HCL generation
	hcl       string // generated HCL content (set by PrepareContent)
}

// NewPolicyOps creates a new PolicyOps for a sync/cleanup operation.
func NewPolicyOps(adapter domain.PolicyAdapter, handler *Handler) *PolicyOps {
	namespace := ""
	if adapter.IsNamespaced() {
		namespace = adapter.GetNamespace()
	}
	return &PolicyOps{
		adapter:   adapter,
		handler:   handler,
		namespace: namespace,
	}
}

func (o *PolicyOps) ResourceKind() string {
	if o.adapter.IsNamespaced() {
		return "VaultPolicy"
	}
	return "VaultClusterPolicy"
}

func (o *PolicyOps) VaultResourceName() string {
	return o.adapter.GetVaultPolicyName()
}

// AuthPath returns the empty string — policies don't live under a Vault auth
// mount. Part of the workflow.ResourceOps interface for cleanup-queue wiring.
func (o *PolicyOps) AuthPath() string { return "" }

// Validate checks namespace boundary enforcement for namespaced policies.
func (o *PolicyOps) Validate() error {
	if o.adapter.IsEnforceNamespaceBoundary() {
		return o.handler.validateNamespaceBoundary(o.adapter)
	}
	return nil
}

// CheckConflict checks for conflicts with existing Vault policies.
func (o *PolicyOps) CheckConflict(ctx context.Context, vaultClient *vault.Client) error {
	return o.handler.checkConflict(ctx, vaultClient, o.adapter, o.adapter.GetVaultPolicyName())
}

// PrepareContent generates HCL and returns the spec hash.
func (o *PolicyOps) PrepareContent(_ context.Context, _ *vault.Client) (string, error) {
	o.hcl = o.handler.generatePolicyHCL(
		o.adapter.GetRules(), o.namespace, o.adapter.GetName())
	return o.handler.calculateHash(o.hcl), nil
}

// DetectDrift compares expected vs actual HCL content in Vault. When drift
// is detected the summary now includes a compact line-level diff preview
// (IMPROVEMENTS §11) so operators seeing the PolicyDrifted condition know
// *what* changed, not just that something changed.
func (o *PolicyOps) DetectDrift(ctx context.Context, vaultClient *vault.Client) (bool, string) {
	log := logr.FromContextOrDiscard(ctx)
	currentHCL, err := vaultClient.ReadPolicy(ctx, o.adapter.GetVaultPolicyName())
	if err != nil {
		log.V(1).Info("failed to read policy for drift detection (non-fatal)", "error", err)
		return false, ""
	}
	normalizedCurrent := o.handler.normalizeHCL(currentHCL)
	normalizedExpected := o.handler.normalizeHCL(o.hcl)
	comparator := drift.NewComparator()
	comparator.CompareMultilineText("rules", normalizedExpected, normalizedCurrent)
	result := comparator.Result()
	return result.HasDrift, result.Summary
}

// WriteToVault writes the generated HCL to Vault. Skipped under either:
//   - `AnnotationDiscoveryPending=true` — prevents auto-created discovery
//     CRs from overwriting the adopted Vault policy with placeholder rules.
//   - `AnnotationDryRun=true` — the user wants to preview what would be
//     written without committing. The would-be HCL is surfaced via the
//     DryRun status condition by the workflow's post-sync path.
//     IMPROVEMENTS Missing Features §I.
func (o *PolicyOps) WriteToVault(ctx context.Context, vaultClient *vault.Client) error {
	log := logr.FromContextOrDiscard(ctx)
	if o.adapter.GetAnnotations()[vaultv1alpha1.AnnotationDiscoveryPending] == vaultv1alpha1.AnnotationValueTrue {
		log.Info("skipping write for discovery-pending policy",
			"policy", o.adapter.GetVaultPolicyName())
		return nil
	}
	if dryrun.IsActive(o.adapter) {
		log.Info("skipping WritePolicy due to dry-run annotation",
			"policy", o.adapter.GetVaultPolicyName(),
			"hclBytes", len(o.hcl),
		)
		return nil
	}
	return vaultClient.WritePolicy(ctx, o.adapter.GetVaultPolicyName(), o.hcl)
}

// ReadbackVerify reads back the policy from Vault and verifies content matches.
// Skipped when the discovery-pending annotation is set — WriteToVault is also skipped
// in that case, so the Vault state is by design unrelated to the placeholder spec and
// a comparison would always report mismatch.
func (o *PolicyOps) ReadbackVerify(ctx context.Context, vaultClient *vault.Client) error {
	log := logr.FromContextOrDiscard(ctx)
	if o.adapter.GetAnnotations()[vaultv1alpha1.AnnotationDiscoveryPending] == vaultv1alpha1.AnnotationValueTrue {
		log.V(1).Info("skipping readback for discovery-pending policy",
			"policy", o.adapter.GetVaultPolicyName())
		return nil
	}
	readbackHCL, readErr := vaultClient.ReadPolicy(ctx, o.adapter.GetVaultPolicyName())
	if readErr != nil {
		log.V(1).Info("post-write readback failed (non-fatal)", "error", readErr)
		return nil
	}
	if o.handler.normalizeHCL(readbackHCL) != o.handler.normalizeHCL(o.hcl) {
		return infraerrors.NewTransientError(
			"readback verification", fmt.Errorf("policy content mismatch after write"))
	}
	return nil
}

// MarkManaged marks the policy as managed with rule descriptions. Skipped
// under dry-run since it would side-effect Vault's KV store.
func (o *PolicyOps) MarkManaged(ctx context.Context, vaultClient *vault.Client) error {
	if dryrun.IsActive(o.adapter) {
		logr.FromContextOrDiscard(ctx).V(1).Info(
			"skipping MarkManaged due to dry-run annotation",
			"policy", o.adapter.GetVaultPolicyName())
		return nil
	}
	k8sResource := o.adapter.GetK8sResourceIdentifier()
	descriptions := o.handler.buildRuleDescriptions(
		o.adapter.GetRules(), o.namespace, o.adapter.GetName())
	return vaultClient.MarkPolicyManaged(ctx, o.adapter.GetVaultPolicyName(), k8sResource, descriptions)
}

// DeleteFromVault deletes the policy from Vault. Skipped under dry-run.
func (o *PolicyOps) DeleteFromVault(ctx context.Context, vaultClient *vault.Client) error {
	if dryrun.IsActive(o.adapter) {
		logr.FromContextOrDiscard(ctx).Info(
			"skipping DeletePolicy due to dry-run annotation",
			"policy", o.adapter.GetVaultPolicyName())
		return nil
	}
	return vaultClient.DeletePolicy(ctx, o.adapter.GetVaultPolicyName())
}

// RemoveManaged removes the managed marker for this policy. Skipped under
// dry-run since the managed marker is itself a Vault-side side effect.
func (o *PolicyOps) RemoveManaged(ctx context.Context, vaultClient *vault.Client) error {
	if dryrun.IsActive(o.adapter) {
		return nil
	}
	return vaultClient.RemovePolicyManaged(ctx, o.adapter.GetVaultPolicyName())
}

// ApplyActiveStatus sets policy-specific status fields.
func (o *PolicyOps) ApplyActiveStatus(_ string, _ *metav1.Time) {
	o.adapter.SetVaultName(o.adapter.GetVaultPolicyName())
	o.adapter.SetRulesCount(len(o.adapter.GetRules()))
}

// ApplyBindings sets the policy binding after sync.
func (o *PolicyOps) ApplyBindings() {
	policyBinding := binding.NewPolicyBinding(o.adapter.GetVaultPolicyName())
	o.adapter.SetBinding(policyBinding)
}

// PublishSyncEvent publishes a PolicyCreated event.
func (o *PolicyOps) PublishSyncEvent(ctx context.Context, bus *events.EventBus) {
	resource := events.ResourceInfo{
		Name:           o.adapter.GetName(),
		Namespace:      o.adapter.GetNamespace(),
		ClusterScoped:  !o.adapter.IsNamespaced(),
		ConnectionName: o.adapter.GetConnectionRef(),
	}
	bus.PublishAsync(ctx, events.NewPolicyCreated(o.adapter.GetVaultPolicyName(), resource))
}

// PublishDeleteEvent publishes a PolicyDeleted event.
func (o *PolicyOps) PublishDeleteEvent(ctx context.Context, bus *events.EventBus) {
	resource := events.ResourceInfo{
		Name:           o.adapter.GetName(),
		Namespace:      o.adapter.GetNamespace(),
		ClusterScoped:  !o.adapter.IsNamespaced(),
		ConnectionName: o.adapter.GetConnectionRef(),
	}
	bus.PublishAsync(ctx, events.NewPolicyDeleted(o.adapter.GetVaultPolicyName(), resource))
}
