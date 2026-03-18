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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/binding"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
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
	authPath := adapter.GetAuthPath()
	if authPath == "" {
		authPath = vault.DefaultKubernetesAuthPath
	}
	return &RoleOps{
		adapter:  adapter,
		handler:  handler,
		authPath: authPath,
	}
}

func (o *RoleOps) ResourceKind() string {
	if o.adapter.IsNamespaced() {
		return "VaultRole"
	}
	return "VaultClusterRole"
}

func (o *RoleOps) VaultResourceName() string {
	return o.adapter.GetVaultRoleName()
}

// Validate performs no pre-sync validation for roles.
func (o *RoleOps) Validate() error {
	return nil
}

// CheckConflict checks for conflicts with existing Vault roles.
func (o *RoleOps) CheckConflict(ctx context.Context, vaultClient *vault.Client) error {
	return o.handler.checkConflict(ctx, vaultClient, o.adapter, o.authPath, o.adapter.GetVaultRoleName())
}

// PrepareContent resolves policies, verifies them, builds role data, and returns the spec hash.
func (o *RoleOps) PrepareContent(ctx context.Context, vaultClient *vault.Client) (string, error) {
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

	// Build Kubernetes auth role data
	o.roleData = o.handler.buildRoleData(o.adapter, policyNames, o.serviceAccountBindings)

	// Calculate spec hash
	return o.handler.calculateSpecHash(o.roleData), nil
}

// DetectDrift compares expected vs actual role data in Vault.
func (o *RoleOps) DetectDrift(ctx context.Context, vaultClient *vault.Client) (bool, string) {
	return o.handler.detectRoleDrift(ctx, vaultClient, o.authPath, o.adapter.GetVaultRoleName(), o.roleData)
}

// WriteToVault creates/updates the Kubernetes auth role in Vault.
func (o *RoleOps) WriteToVault(ctx context.Context, vaultClient *vault.Client) error {
	return vaultClient.WriteKubernetesAuthRole(ctx, o.authPath, o.adapter.GetVaultRoleName(), o.roleData)
}

// ReadbackVerify reads back the role and checks for drift.
func (o *RoleOps) ReadbackVerify(ctx context.Context, vaultClient *vault.Client) error {
	hasDrift, summary := o.handler.detectRoleDrift(
		ctx, vaultClient, o.authPath, o.adapter.GetVaultRoleName(), o.roleData,
	)
	if hasDrift {
		return infraerrors.NewTransientError(
			"readback verification", fmt.Errorf("role content mismatch after write: %s", summary))
	}
	return nil
}

// MarkManaged marks the role as managed by this operator.
func (o *RoleOps) MarkManaged(ctx context.Context, vaultClient *vault.Client) error {
	k8sResource := o.adapter.GetK8sResourceIdentifier()
	return vaultClient.MarkRoleManaged(ctx, o.adapter.GetVaultRoleName(), k8sResource)
}

// DeleteFromVault deletes the Kubernetes auth role from Vault.
func (o *RoleOps) DeleteFromVault(ctx context.Context, vaultClient *vault.Client) error {
	return vaultClient.DeleteKubernetesAuthRole(ctx, o.authPath, o.adapter.GetVaultRoleName())
}

// RemoveManaged removes the managed marker for this role.
func (o *RoleOps) RemoveManaged(ctx context.Context, vaultClient *vault.Client) error {
	return vaultClient.RemoveRoleManaged(ctx, o.adapter.GetVaultRoleName())
}

// ApplyActiveStatus sets role-specific status fields.
func (o *RoleOps) ApplyActiveStatus(_ string, _ *metav1.Time) {
	o.adapter.SetVaultRoleName(o.adapter.GetVaultRoleName())
	o.adapter.SetBoundServiceAccounts(o.serviceAccountBindings)
	o.adapter.SetResolvedPolicies(o.policyNames)
}

// ApplyBindings sets the role binding and policy bindings after sync.
func (o *RoleOps) ApplyBindings() {
	roleBinding := binding.NewRoleBinding(o.authPath, o.adapter.GetVaultRoleName())
	o.adapter.SetBinding(roleBinding)

	policyBindings := o.handler.buildPolicyBindings(o.adapter, o.policyNames)
	o.adapter.SetPolicyBindings(policyBindings)
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
