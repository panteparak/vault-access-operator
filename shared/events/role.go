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

package events

// Role event type constants.
const (
	RoleCreatedType = "role.created"
	RoleUpdatedType = "role.updated"
	RoleDeletedType = "role.deleted"
)

// RoleCreated is published when a VaultRole or VaultClusterRole is created in Vault.
type RoleCreated struct {
	BaseEvent
	// RoleName is the name of the role in Vault
	RoleName string
	// AuthPath is the Vault auth path where the role was created
	AuthPath string
	// Resource contains K8s resource metadata
	Resource ResourceInfo
	// Policies is the list of policy names attached to this role
	Policies []string
	// BoundServiceAccounts is the list of service account names bound to this role
	BoundServiceAccounts []string
}

// Type returns the event type identifier.
func (e RoleCreated) Type() string {
	return RoleCreatedType
}

// NewRoleCreated creates a RoleCreated event.
func NewRoleCreated(roleName, authPath string, resource ResourceInfo, policies, serviceAccounts []string) RoleCreated {
	return RoleCreated{
		BaseEvent:            NewBaseEvent(RoleCreatedType),
		RoleName:             roleName,
		AuthPath:             authPath,
		Resource:             resource,
		Policies:             policies,
		BoundServiceAccounts: serviceAccounts,
	}
}

// RoleUpdated is published when a role's configuration changes.
type RoleUpdated struct {
	BaseEvent
	// RoleName is the name of the role in Vault
	RoleName string
	// AuthPath is the Vault auth path where the role exists
	AuthPath string
	// Resource contains K8s resource metadata
	Resource ResourceInfo
	// Policies is the updated list of policy names
	Policies []string
	// BoundServiceAccounts is the updated list of service account names
	BoundServiceAccounts []string
	// PoliciesChanged indicates if the policies were modified
	PoliciesChanged bool
	// BindingsChanged indicates if the service account bindings were modified
	BindingsChanged bool
}

// Type returns the event type identifier.
func (e RoleUpdated) Type() string {
	return RoleUpdatedType
}

// NewRoleUpdated creates a RoleUpdated event.
func NewRoleUpdated(
	roleName, authPath string,
	resource ResourceInfo,
	policies, serviceAccounts []string,
	policiesChanged, bindingsChanged bool,
) RoleUpdated {
	return RoleUpdated{
		BaseEvent:            NewBaseEvent(RoleUpdatedType),
		RoleName:             roleName,
		AuthPath:             authPath,
		Resource:             resource,
		Policies:             policies,
		BoundServiceAccounts: serviceAccounts,
		PoliciesChanged:      policiesChanged,
		BindingsChanged:      bindingsChanged,
	}
}

// RoleDeleted is published when a role is removed from Vault.
type RoleDeleted struct {
	BaseEvent
	// RoleName is the name of the role that was in Vault
	RoleName string
	// AuthPath is the Vault auth path where the role existed
	AuthPath string
	// Resource contains K8s resource metadata
	Resource ResourceInfo
}

// Type returns the event type identifier.
func (e RoleDeleted) Type() string {
	return RoleDeletedType
}

// NewRoleDeleted creates a RoleDeleted event.
func NewRoleDeleted(roleName, authPath string, resource ResourceInfo) RoleDeleted {
	return RoleDeleted{
		BaseEvent: NewBaseEvent(RoleDeletedType),
		RoleName:  roleName,
		AuthPath:  authPath,
		Resource:  resource,
	}
}
