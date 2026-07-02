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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/binding"
	"github.com/panteparak/vault-access-operator/shared/controller/drift"
	"github.com/panteparak/vault-access-operator/shared/controller/dryrun"
	"github.com/panteparak/vault-access-operator/shared/controller/workflow"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
	"github.com/panteparak/vault-access-operator/shared/naming"
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
func (o *PolicyOps) CheckConflict(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	return o.handler.checkConflict(ctx, vaultClient, o.adapter, o.adapter.GetVaultPolicyName())
}

// PrepareContent generates the policy document — the in-band ownership
// header (ADR 0008) followed by the HCL body — and returns the spec hash.
// The header carries stable identity only (no timestamps), so an unchanged
// spec hashes identically across reconciles.
func (o *PolicyOps) PrepareContent(_ context.Context, vaultClient workflow.VaultOpsClient) (string, error) {
	body := o.handler.generatePolicyHCL(
		o.adapter.GetRules(), o.namespace, o.adapter.GetName())
	o.hcl = vault.OwnershipHeader(o.ownership(vaultClient)) + "\n" + body
	return o.handler.calculateHash(o.hcl), nil
}

// ownership builds this policy's in-band ownership record. The operator
// identity is the resolved connection's auth mount (ADR 0008).
func (o *PolicyOps) ownership(vaultClient workflow.VaultOpsClient) vault.Ownership {
	return vault.Ownership{
		ManagedBy:   vault.KVManagedByValue,
		AuthMount:   vaultClient.AuthMount(),
		Cluster:     naming.Cluster(),
		K8sResource: o.adapter.GetK8sResourceIdentifier(),
		K8sKind:     o.ResourceKind(),
	}
}

// DetectDrift compares expected vs actual HCL content in Vault. When drift
// is detected the summary now includes a compact line-level diff preview
// (IMPROVEMENTS §11) so operators seeing the PolicyDrifted condition know
// *what* changed, not just that something changed.
//
// Vault read failures are non-fatal (we'd rather skip drift detection
// than fail the reconcile during a transient Vault outage), but logged
// at Info level so operators investigating "why are we showing as in-sync
// when Vault is clearly broken" can find the cause without bumping
// verbosity. Previously logged at V(1) which is suppressed by default.
func (o *PolicyOps) DetectDrift(ctx context.Context, vaultClient workflow.VaultOpsClient) (bool, string) {
	log := logr.FromContextOrDiscard(ctx)
	currentHCL, err := vaultClient.ReadPolicy(ctx, o.adapter.GetVaultPolicyName())
	if err != nil {
		log.Info("skipping drift detection — Vault read failed",
			"policy", o.adapter.GetVaultPolicyName(),
			"error", err.Error(),
			"hint", "drift state preserved from last successful read; will retry on next reconcile",
		)
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
func (o *PolicyOps) WriteToVault(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
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
func (o *PolicyOps) ReadbackVerify(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
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

// DeleteFromVault deletes the policy from Vault. Skipped under dry-run.
//
// Ownership gate (ADR 0008): before the destructive delete, the live policy's
// in-band header is re-read; if it names a different operator instance or CR
// (possible when two clusters derive colliding names on a shared Vault), the
// delete is skipped with a Warning event instead of destroying the other
// owner's policy. A header-less policy (adopted / pre-ADR-0008) is deleted
// as instructed by DeletionPolicy. Read failures fall through to the delete —
// its own error handling enqueues a retry, whereas skipping here would remove
// the finalizer and leak the policy silently.
func (o *PolicyOps) DeleteFromVault(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	log := logr.FromContextOrDiscard(ctx)
	name := o.adapter.GetVaultPolicyName()
	if dryrun.IsActive(o.adapter) {
		log.Info("skipping DeletePolicy due to dry-run annotation", "policy", name)
		return nil
	}
	if own, err := vaultClient.GetPolicyOwnership(ctx, name); err == nil && own != nil &&
		!own.SameOwner(vaultClient.AuthMount(), o.adapter.GetK8sResourceIdentifier()) {
		log.Info("skipping DeletePolicy — Vault policy is owned by someone else",
			"policy", name, "owner", own.String())
		if o.handler.recorder != nil {
			o.handler.recorder.Eventf(o.adapter.GetObject(), corev1.EventTypeWarning,
				"ForeignPolicyNotDeleted",
				"Vault policy %q was not deleted: it is owned by %s", name, own.String())
		}
		return nil
	}
	return vaultClient.DeletePolicy(ctx, name)
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
