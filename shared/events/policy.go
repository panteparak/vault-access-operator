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

// Policy event type constants.
const (
	PolicyCreatedType = "policy.created"
	PolicyUpdatedType = "policy.updated"
	PolicyDeletedType = "policy.deleted"
)

// PolicyCreated is published when a VaultPolicy or VaultClusterPolicy is created in Vault.
// The Role feature can subscribe to update resolved policy names.
type PolicyCreated struct {
	BaseEvent
	// PolicyName is the name of the policy in Vault
	PolicyName string
	// Resource contains K8s resource metadata
	Resource ResourceInfo
}

// Type returns the event type identifier.
func (e PolicyCreated) Type() string {
	return PolicyCreatedType
}

// NewPolicyCreated creates a PolicyCreated event.
func NewPolicyCreated(policyName string, resource ResourceInfo) PolicyCreated {
	return PolicyCreated{
		BaseEvent:  NewBaseEvent(PolicyCreatedType),
		PolicyName: policyName,
		Resource:   resource,
	}
}

// PolicyUpdated is published when a policy is modified in Vault.
// Roles referencing this policy may need to refresh their configuration.
type PolicyUpdated struct {
	BaseEvent
	// PolicyName is the name of the policy in Vault
	PolicyName string
	// Resource contains K8s resource metadata
	Resource ResourceInfo
	// RulesChanged indicates if the policy rules were modified
	RulesChanged bool
}

// Type returns the event type identifier.
func (e PolicyUpdated) Type() string {
	return PolicyUpdatedType
}

// NewPolicyUpdated creates a PolicyUpdated event.
func NewPolicyUpdated(policyName string, resource ResourceInfo, rulesChanged bool) PolicyUpdated {
	return PolicyUpdated{
		BaseEvent:    NewBaseEvent(PolicyUpdatedType),
		PolicyName:   policyName,
		Resource:     resource,
		RulesChanged: rulesChanged,
	}
}

// PolicyDeleted is published when a policy is removed from Vault.
// Roles referencing this policy need to be re-reconciled to update their status.
type PolicyDeleted struct {
	BaseEvent
	// PolicyName is the name of the policy that was in Vault
	PolicyName string
	// Resource contains K8s resource metadata
	Resource ResourceInfo
}

// Type returns the event type identifier.
func (e PolicyDeleted) Type() string {
	return PolicyDeletedType
}

// NewPolicyDeleted creates a PolicyDeleted event.
func NewPolicyDeleted(policyName string, resource ResourceInfo) PolicyDeleted {
	return PolicyDeleted{
		BaseEvent:  NewBaseEvent(PolicyDeletedType),
		PolicyName: policyName,
		Resource:   resource,
	}
}
