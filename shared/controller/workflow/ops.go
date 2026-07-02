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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/panteparak/vault-access-operator/shared/events"
)

// ResourceOps defines the resource-specific operations that vary between
// policy and role sync. The workflow calls these at the appropriate points
// in the orchestration flow.
type ResourceOps interface {
	// ResourceKind returns "VaultPolicy", "VaultClusterPolicy", "VaultRole", or "VaultClusterRole".
	ResourceKind() string

	// VaultResourceName returns the Vault-side name (e.g., "default-my-policy").
	VaultResourceName() string

	// AuthPath returns the Vault auth mount for roles (e.g., "auth/kubernetes")
	// and the empty string for resources that don't live under an auth mount
	// (policies). Used by the cleanup retry queue to remember which mount to
	// hit when a failed delete is replayed — see IMPROVEMENTS §2.
	AuthPath() string

	// --- Pre-sync operations ---

	// Validate performs resource-specific pre-sync validation (e.g., namespace boundary).
	// Return nil to skip validation. Errors are fatal.
	Validate() error

	// CheckConflict checks for conflicts with existing Vault resources.
	// Supports adoption via annotation or ConflictPolicy.
	CheckConflict(ctx context.Context, vaultClient VaultOpsClient) error

	// PrepareContent generates the resource content and returns a spec hash.
	// For policies: generates HCL. For roles: resolves policies + builds role data.
	PrepareContent(ctx context.Context, vaultClient VaultOpsClient) (specHash string, err error)

	// --- Vault operations ---

	// DetectDrift compares expected vs actual state in Vault.
	// Returns (false, "") if detection fails or is inconclusive.
	DetectDrift(ctx context.Context, vaultClient VaultOpsClient) (detected bool, summary string)

	// WriteToVault writes the prepared content to Vault. Fatal.
	WriteToVault(ctx context.Context, vaultClient VaultOpsClient) error

	// ReadbackVerify reads back from Vault and returns error if content mismatches.
	// Read failures are non-fatal (return nil); content mismatches are fatal.
	ReadbackVerify(ctx context.Context, vaultClient VaultOpsClient) error

	// DeleteFromVault removes the resource from Vault. Best-effort during
	// cleanup. Implementations verify in-band ownership before destructive
	// writes where the object family supports it (ADR 0008).
	DeleteFromVault(ctx context.Context, vaultClient VaultOpsClient) error

	// --- Status/binding updates ---

	// ApplyActiveStatus sets resource-specific status fields for Active phase.
	// Common fields (phase, hash, conditions) are set by the workflow.
	ApplyActiveStatus(specHash string, now *metav1.Time)

	// ApplyBindings sets resource-specific bindings after successful sync.
	ApplyBindings()

	// --- Event publishing ---

	// PublishSyncEvent publishes the sync completion event via the event bus.
	PublishSyncEvent(ctx context.Context, bus *events.EventBus)

	// PublishDeleteEvent publishes the deletion event via the event bus.
	PublishDeleteEvent(ctx context.Context, bus *events.EventBus)
}
