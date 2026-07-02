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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/binding"
	"github.com/panteparak/vault-access-operator/shared/controller/dryrun"
	"github.com/panteparak/vault-access-operator/shared/controller/workflow"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
	"github.com/panteparak/vault-access-operator/shared/markers"
)

// RoleOps implements workflow.ResourceOps for role resources.
// It holds the adapter and handler reference, and captures the resolved data
// between PrepareContent and WriteToVault/DetectDrift calls.
type RoleOps struct {
	adapter                domain.RoleAdapter
	handler                *Handler
	authPath               string
	policyNames            []string
	serviceAccountBindings []string
	roleData               map[string]interface{}
}

// NewRoleOps creates a new RoleOps for a sync/cleanup operation.
func NewRoleOps(adapter domain.RoleAdapter, handler *Handler) *RoleOps {
	// Normalize once at construction so every downstream consumer
	// (Vault SDK calls, log/metric labels, drift detection) sees the
	// same canonical form. Bare "kubernetes" → "auth/kubernetes",
	// empty → "auth/kubernetes". Both forms appear in user-facing CRD
	// docs and existing fixtures, but Vault's actual mount paths are
	// always under /v1/auth/<name>/.
	authPath := vault.NormalizeAuthPath(adapter.GetAuthPath())
	return &RoleOps{
		adapter:  adapter,
		handler:  handler,
		authPath: authPath,
	}
}

func (o *RoleOps) ResourceKind() string {
	if o.adapter.IsNamespaced() {
		return vaultv1alpha1.RoleKindNamespaced
	}
	return vaultv1alpha1.RoleKindCluster
}

func (o *RoleOps) VaultResourceName() string {
	return o.adapter.GetVaultRoleName()
}

// AuthPath returns the Vault auth mount that owns this role. Consumed by the
// cleanup retry queue so a failed delete can be replayed against the correct
// mount — see IMPROVEMENTS §2.
func (o *RoleOps) AuthPath() string { return o.authPath }

// Validate performs no pre-sync validation for roles.
func (o *RoleOps) Validate() error {
	return nil
}

// CheckConflict checks for conflicts with existing Vault roles.
func (o *RoleOps) CheckConflict(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	return o.handler.checkConflict(ctx, vaultClient, o.adapter, o.authPath, o.adapter.GetVaultRoleName())
}

// PrepareContent resolves policies, verifies them, builds role data, and returns the spec hash.
func (o *RoleOps) PrepareContent(ctx context.Context, vaultClient workflow.VaultOpsClient) (string, error) {
	// Resolve policy names from PolicyReferences
	policyNames, err := o.handler.resolvePolicyNames(ctx, o.adapter)
	if err != nil {
		return "", err
	}
	o.policyNames = policyNames

	// Verify referenced policies exist in Vault (warning, not blocking)
	o.handler.verifyPoliciesExistInVault(ctx, vaultClient, o.adapter, policyNames)

	// Get service account bindings
	o.serviceAccountBindings = o.adapter.GetServiceAccountBindings()

	// Build auth-backend-specific role data. Connection is best-effort —
	// the workflow has already verified it's Active; a transient fetch
	// failure here falls back to cluster-default values.
	connection := o.resolveConnection(ctx)
	roleData, err := o.handler.buildRoleData(o.adapter, policyNames, o.serviceAccountBindings, connection)
	if err != nil {
		return "", err
	}
	o.roleData = roleData

	// Calculate spec hash
	return o.handler.calculateSpecHash(o.roleData)
}

// resolveConnection fetches the referenced VaultConnection from the API
// server. Returns nil if the reference is empty or the fetch fails —
// defaulting will then fall back to cluster-default values.
//
// Distinguishes IsNotFound (silent — the connection genuinely doesn't
// exist; the dependency check elsewhere will surface this) from other
// errors (logged at V(1) so operators investigating "why am I getting
// the default audience instead of the one I configured?" can find the
// transient failure cause).
func (o *RoleOps) resolveConnection(ctx context.Context) *vaultv1alpha1.VaultConnection {
	connRef := o.adapter.GetConnectionRef()
	if connRef == "" {
		return nil
	}
	conn := &vaultv1alpha1.VaultConnection{}
	err := o.handler.client.Get(ctx, client.ObjectKey{Name: connRef}, conn)
	if err == nil {
		return conn
	}
	if !apierrors.IsNotFound(err) {
		logr.FromContextOrDiscard(ctx).V(1).Info(
			"failed to load VaultConnection for JWT defaults; using cluster-default audience",
			"connection", connRef, "error", err.Error(),
		)
	}
	return nil
}

// authBackend resolves the role's auth backend family, honoring an explicit
// spec.authType and falling back to inference from the auth path name.
func (o *RoleOps) authBackend() vault.AuthBackend {
	return vault.ResolveAuthBackend(string(o.adapter.GetAuthType()), o.authPath)
}

// DetectDrift compares expected vs actual role data in Vault.
func (o *RoleOps) DetectDrift(ctx context.Context, vaultClient workflow.VaultOpsClient) (bool, string) {
	return o.handler.detectRoleDrift(
		ctx, vaultClient, o.authBackend(), o.authPath, o.adapter.GetVaultRoleName(), o.roleData,
	)
}

// WriteToVault creates/updates the Kubernetes auth role in Vault. Skipped under:
//   - `AnnotationDiscoveryPending=true` — prevents auto-created discovery
//     CRs from overwriting the adopted Vault role with placeholder values.
//   - `AnnotationDryRun=true` — preview mode (IMPROVEMENTS Missing
//     Features §I). The would-be role data is in `o.roleData` and is
//     surfaced via the DryRun status condition.
func (o *RoleOps) WriteToVault(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	log := logr.FromContextOrDiscard(ctx)
	if o.adapter.GetAnnotations()[vaultv1alpha1.AnnotationDiscoveryPending] == vaultv1alpha1.AnnotationValueTrue {
		log.Info("skipping write for discovery-pending role",
			"role", o.adapter.GetVaultRoleName())
		return nil
	}
	if dryrun.IsActive(o.adapter) {
		log.Info("skipping WriteKubernetesAuthRole due to dry-run annotation",
			"role", o.adapter.GetVaultRoleName(),
			"authPath", o.authPath,
		)
		return nil
	}
	return vaultClient.WriteKubernetesAuthRole(ctx, o.authPath, o.adapter.GetVaultRoleName(), o.roleData)
}

// ReadbackVerify reads back the role and checks for drift.
// Skipped when the discovery-pending annotation is set — WriteToVault is also skipped
// in that case, so comparing real Vault state against the placeholder spec would always
// report drift and return TransientError, looping the reconciler forever.
func (o *RoleOps) ReadbackVerify(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	if o.adapter.GetAnnotations()[vaultv1alpha1.AnnotationDiscoveryPending] == vaultv1alpha1.AnnotationValueTrue {
		logr.FromContextOrDiscard(ctx).V(1).Info("skipping readback for discovery-pending role",
			"role", o.adapter.GetVaultRoleName())
		return nil
	}
	hasDrift, summary := o.handler.detectRoleDrift(
		ctx, vaultClient, o.authBackend(), o.authPath, o.adapter.GetVaultRoleName(), o.roleData,
	)
	if hasDrift {
		return infraerrors.NewTransientError(
			"readback verification", fmt.Errorf("role content mismatch after write: %s", summary))
	}
	return nil
}

// MarkManaged records operator ownership of the role. No-op when managed
// markers are disabled, or under dry-run (a Vault-side write).
func (o *RoleOps) MarkManaged(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	if !markers.Enabled() {
		return nil
	}
	if dryrun.IsActive(o.adapter) {
		logr.FromContextOrDiscard(ctx).V(1).Info(
			"skipping role MarkManaged due to dry-run annotation",
			"role", o.adapter.GetVaultRoleName())
		return nil
	}
	return vaultClient.MarkManaged(ctx, o.markerID(), o.adapter.GetK8sResourceIdentifier())
}

// DeleteFromVault deletes the Kubernetes auth role from Vault. Skipped under
// dry-run; status condition surfaces what would have been deleted.
func (o *RoleOps) DeleteFromVault(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	if dryrun.IsActive(o.adapter) {
		logr.FromContextOrDiscard(ctx).Info(
			"skipping DeleteKubernetesAuthRole due to dry-run annotation",
			"role", o.adapter.GetVaultRoleName())
		return nil
	}
	return vaultClient.DeleteKubernetesAuthRole(ctx, o.authPath, o.adapter.GetVaultRoleName())
}

// RemoveManaged removes the role's ownership marker. No-op when managed markers
// are disabled, or under dry-run.
func (o *RoleOps) RemoveManaged(ctx context.Context, vaultClient workflow.VaultOpsClient) error {
	if !markers.Enabled() || dryrun.IsActive(o.adapter) {
		return nil
	}
	return vaultClient.RemoveManaged(ctx, o.markerID())
}

// markerID builds the managed-marker identity for this role, including the bare
// auth-mount segment. Namespace is "" for cluster-scoped roles (encoded as the
// _cluster sentinel in the path).
func (o *RoleOps) markerID() vault.MarkerID {
	return vault.MarkerID{
		Kind:      vault.MarkerRole,
		Mount:     vault.AuthMountName(o.authPath),
		Namespace: o.adapter.GetNamespace(),
		Name:      o.adapter.GetName(),
	}
}

// ApplyActiveStatus sets role-specific status fields.
func (o *RoleOps) ApplyActiveStatus(_ string, _ *metav1.Time) {
	o.adapter.SetVaultRoleName(o.adapter.GetVaultRoleName())
	o.adapter.SetBoundServiceAccounts(o.serviceAccountBindings)
	o.adapter.SetResolvedPolicies(o.policyNames)
}

// ApplyBindings sets the role binding and policy bindings after sync.
// Also emits a K8s event for every PolicyBinding that transitioned from
// unresolved to resolved in this reconcile — IMPROVEMENTS Missing
// Features §J. Operators inspecting `kubectl describe vaultrole X` now
// see the moment each dependency was satisfied, not just the pre-existing
// "PolicyNotFound" warning events.
func (o *RoleOps) ApplyBindings() {
	roleBinding := binding.NewRoleBinding(o.authPath, o.adapter.GetVaultRoleName())
	o.adapter.SetBinding(roleBinding)

	previous := o.adapter.GetPolicyBindings()
	policyBindings := o.handler.buildPolicyBindings(o.adapter, o.policyNames)
	o.adapter.SetPolicyBindings(policyBindings)

	o.handler.emitPolicyResolvedEvents(o.adapter, previous, policyBindings)
}

// PublishSyncEvent publishes a RoleCreated event.
func (o *RoleOps) PublishSyncEvent(ctx context.Context, bus *events.EventBus) {
	resource := events.ResourceInfo{
		Name:           o.adapter.GetName(),
		Namespace:      o.adapter.GetNamespace(),
		ClusterScoped:  !o.adapter.IsNamespaced(),
		ConnectionName: o.adapter.GetConnectionRef(),
	}
	event := events.NewRoleCreated(
		o.adapter.GetVaultRoleName(), o.authPath, resource,
		o.policyNames, o.serviceAccountBindings,
	)
	bus.PublishAsync(ctx, event)
}

// PublishDeleteEvent publishes a RoleDeleted event.
func (o *RoleOps) PublishDeleteEvent(ctx context.Context, bus *events.EventBus) {
	resource := events.ResourceInfo{
		Name:           o.adapter.GetName(),
		Namespace:      o.adapter.GetNamespace(),
		ClusterScoped:  !o.adapter.IsNamespaced(),
		ConnectionName: o.adapter.GetConnectionRef(),
	}
	bus.PublishAsync(ctx, events.NewRoleDeleted(o.adapter.GetVaultRoleName(), o.authPath, resource))
}
