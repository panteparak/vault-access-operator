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
	"github.com/panteparak/vault-access-operator/shared/controller/binding"
	"github.com/panteparak/vault-access-operator/shared/controller/workflow"
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
		return string(vaultv1alpha1.PolicyKindNamespaced)
	}
	return string(vaultv1alpha1.PolicyKindCluster)
}

func (o *PolicyOps) VaultResourceName() string {
	return o.adapter.GetVaultPolicyName()
}

// Validate checks namespace boundary enforcement for namespaced policies.
func (o *PolicyOps) Validate() error {
	if o.adapter.IsEnforceNamespaceBoundary() {
		return o.handler.validateNamespaceBoundary(o.adapter)
	}
	return nil
}

// CheckConflict checks for conflicts with existing Vault policies.
func (o *PolicyOps) CheckConflict(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	return o.handler.checkConflict(ctx, vaultClient, o.adapter, o.adapter.GetVaultPolicyName())
}

// PrepareContent generates HCL and returns the spec hash.
func (o *PolicyOps) PrepareContent(_ context.Context, _ workflow.VaultOpsClient) (string, error) {
	o.hcl = o.handler.generatePolicyHCL(
		o.adapter.GetRules(), o.namespace, o.adapter.GetName())
	return o.handler.calculateHash(o.hcl), nil
}

// DetectDrift compares expected vs actual HCL content in Vault.
func (o *PolicyOps) DetectDrift(ctx context.Context, vaultClient workflow.VaultOpsClient) (bool, string) {
	log := logr.FromContextOrDiscard(ctx)
	currentHCL, err := vaultClient.ReadPolicy(ctx, o.adapter.GetVaultPolicyName())
	if err != nil {
		log.V(1).Info("failed to read policy for drift detection (non-fatal)", "error", err)
		return false, ""
	}
	normalizedCurrent := o.handler.normalizeHCL(currentHCL)
	normalizedExpected := o.handler.normalizeHCL(o.hcl)
	if normalizedCurrent != normalizedExpected {
		return true, "policy content differs"
	}
	return false, ""
}

// WriteToVault writes the generated HCL to Vault.
// Skips the write if the discovery-pending annotation is set — this prevents
// auto-created discovery CRs from overwriting adopted Vault policies with placeholder rules.
func (o *PolicyOps) WriteToVault(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	annotations := o.adapter.GetAnnotations()
	if annotations["vault.platform.io/discovery-pending"] == "true" {
		logr.FromContextOrDiscard(ctx).Info("skipping write for discovery-pending policy",
			"policy", o.adapter.GetVaultPolicyName())
		return nil
	}
	return vaultClient.WritePolicy(ctx, o.adapter.GetVaultPolicyName(), o.hcl)
}

// ReadbackVerify reads back the policy from Vault and verifies content matches.
func (o *PolicyOps) ReadbackVerify(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	log := logr.FromContextOrDiscard(ctx)
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

// MarkManaged marks the policy as managed with rule descriptions.
func (o *PolicyOps) MarkManaged(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	k8sResource := o.adapter.GetK8sResourceIdentifier()
	descriptions := o.handler.buildRuleDescriptions(
		o.adapter.GetRules(), o.namespace, o.adapter.GetName())
	return vaultClient.MarkPolicyManaged(ctx, o.adapter.GetVaultPolicyName(), k8sResource, descriptions)
}

// DeleteFromVault deletes the policy from Vault.
func (o *PolicyOps) DeleteFromVault(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	return vaultClient.DeletePolicy(ctx, o.adapter.GetVaultPolicyName())
}

// RemoveManaged removes the managed marker for this policy.
func (o *PolicyOps) RemoveManaged(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
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
