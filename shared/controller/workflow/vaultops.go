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

package workflow

import (
	"context"

	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// Compile-time guarantee that *vault.Client satisfies VaultOpsClient.
// Lives here (rather than in each feature handler) so changes to the
// interface surface are caught at the single source of truth.
var _ VaultOpsClient = (*vault.Client)(nil)

// VaultOpsClient is the narrow interface that policy and role ResourceOps
// implementations require from a Vault client. *vault.Client satisfies it
// implicitly via Go structural typing; tests supply in-memory fakes.
//
// This is the union of policy-side and role-side needs. Feature-specific ops
// only invoke a subset — the compiler prevents one feature from depending on
// another feature's methods at a site where they don't belong.
type VaultOpsClient interface {
	// --- Lifecycle check (used by CleanupWorkflow) ---
	IsAuthenticated() bool

	// --- Policy operations ---
	PolicyExists(ctx context.Context, name string) (bool, error)
	ReadPolicy(ctx context.Context, name string) (string, error)
	WritePolicy(ctx context.Context, name, hcl string) error
	DeletePolicy(ctx context.Context, name string) error

	// --- Kubernetes auth role operations ---
	KubernetesAuthRoleExists(ctx context.Context, authPath, roleName string) (bool, error)
	ReadKubernetesAuthRole(ctx context.Context, authPath, roleName string) (map[string]interface{}, error)
	WriteKubernetesAuthRole(ctx context.Context, authPath, roleName string, data map[string]interface{}) error
	DeleteKubernetesAuthRole(ctx context.Context, authPath, roleName string) error

	// --- In-band ownership (ADR 0008) ---
	// AuthMount is the operator identity — the auth mount this client logged
	// in through ("" for static token auth). GetPolicyOwnership reads a
	// policy's ownership comment header ((nil, nil) when the policy is absent
	// or not operator-managed).
	AuthMount() string
	GetPolicyOwnership(ctx context.Context, name string) (*vault.Ownership, error)
}
