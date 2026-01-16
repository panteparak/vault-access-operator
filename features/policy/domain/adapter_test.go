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

package domain

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// Helper function to create a bool pointer
func boolPtr(b bool) *bool {
	return &b
}

// =============================================================================
// VaultPolicyAdapter Tests
// =============================================================================

func TestVaultPolicyAdapter_GetVaultPolicyName(t *testing.T) {
	tests := []struct {
		name       string
		namespace  string
		policyName string
		want       string
	}{
		{
			name:       "standard namespace and name",
			namespace:  "default",
			policyName: "my-policy",
			want:       "default-my-policy",
		},
		{
			name:       "production namespace",
			namespace:  "production",
			policyName: "api-secrets",
			want:       "production-api-secrets",
		},
		{
			name:       "hyphenated namespace and name",
			namespace:  "my-namespace",
			policyName: "my-policy-name",
			want:       "my-namespace-my-policy-name",
		},
		{
			name:       "single character namespace and name",
			namespace:  "a",
			policyName: "b",
			want:       "a-b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: tt.namespace,
					Name:      tt.policyName,
				},
			}
			adapter := NewVaultPolicyAdapter(policy)

			got := adapter.GetVaultPolicyName()
			if got != tt.want {
				t.Errorf("GetVaultPolicyName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVaultPolicyAdapter_GetK8sResourceIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		namespace  string
		policyName string
		want       string
	}{
		{
			name:       "standard namespace and name",
			namespace:  "default",
			policyName: "my-policy",
			want:       "default/my-policy",
		},
		{
			name:       "production namespace",
			namespace:  "production",
			policyName: "api-secrets",
			want:       "production/api-secrets",
		},
		{
			name:       "hyphenated namespace and name",
			namespace:  "my-namespace",
			policyName: "my-policy-name",
			want:       "my-namespace/my-policy-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: tt.namespace,
					Name:      tt.policyName,
				},
			}
			adapter := NewVaultPolicyAdapter(policy)

			got := adapter.GetK8sResourceIdentifier()
			if got != tt.want {
				t.Errorf("GetK8sResourceIdentifier() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVaultPolicyAdapter_IsNamespaced(t *testing.T) {
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-policy",
		},
	}
	adapter := NewVaultPolicyAdapter(policy)

	got := adapter.IsNamespaced()
	if !got {
		t.Errorf("IsNamespaced() = %v, want true", got)
	}
}

func TestVaultPolicyAdapter_IsEnforceNamespaceBoundary(t *testing.T) {
	tests := []struct {
		name                     string
		enforceNamespaceBoundary *bool
		want                     bool
	}{
		{
			name:                     "enforceNamespaceBoundary is nil (default false)",
			enforceNamespaceBoundary: nil,
			want:                     false,
		},
		{
			name:                     "enforceNamespaceBoundary is true",
			enforceNamespaceBoundary: boolPtr(true),
			want:                     true,
		},
		{
			name:                     "enforceNamespaceBoundary is false",
			enforceNamespaceBoundary: boolPtr(false),
			want:                     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test-policy",
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					EnforceNamespaceBoundary: tt.enforceNamespaceBoundary,
				},
			}
			adapter := NewVaultPolicyAdapter(policy)

			got := adapter.IsEnforceNamespaceBoundary()
			if got != tt.want {
				t.Errorf("IsEnforceNamespaceBoundary() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVaultPolicyAdapter_GetConnectionRef(t *testing.T) {
	tests := []struct {
		name          string
		connectionRef string
	}{
		{
			name:          "standard connection ref",
			connectionRef: "vault-connection",
		},
		{
			name:          "hyphenated connection ref",
			connectionRef: "my-vault-connection",
		},
		{
			name:          "empty connection ref",
			connectionRef: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultPolicy{
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: tt.connectionRef,
				},
			}
			adapter := NewVaultPolicyAdapter(policy)

			got := adapter.GetConnectionRef()
			if got != tt.connectionRef {
				t.Errorf("GetConnectionRef() = %q, want %q", got, tt.connectionRef)
			}
		})
	}
}

func TestVaultPolicyAdapter_GetRules(t *testing.T) {
	tests := []struct {
		name  string
		rules []vaultv1alpha1.PolicyRule
	}{
		{
			name:  "empty rules",
			rules: []vaultv1alpha1.PolicyRule{},
		},
		{
			name: "single rule",
			rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/app",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
				},
			},
		},
		{
			name: "multiple rules",
			rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/app/*",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead, vaultv1alpha1.CapabilityList},
				},
				{
					Path:         "secret/metadata/app/*",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityList},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultPolicy{
				Spec: vaultv1alpha1.VaultPolicySpec{
					Rules: tt.rules,
				},
			}
			adapter := NewVaultPolicyAdapter(policy)

			got := adapter.GetRules()
			if len(got) != len(tt.rules) {
				t.Errorf("GetRules() returned %d rules, want %d", len(got), len(tt.rules))
			}
			for i := range got {
				if got[i].Path != tt.rules[i].Path {
					t.Errorf("GetRules()[%d].Path = %q, want %q", i, got[i].Path, tt.rules[i].Path)
				}
			}
		})
	}
}

func TestVaultPolicyAdapter_GetDeletionPolicy(t *testing.T) {
	tests := []struct {
		name           string
		deletionPolicy vaultv1alpha1.DeletionPolicy
	}{
		{
			name:           "delete policy",
			deletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
		{
			name:           "retain policy",
			deletionPolicy: vaultv1alpha1.DeletionPolicyRetain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultPolicy{
				Spec: vaultv1alpha1.VaultPolicySpec{
					DeletionPolicy: tt.deletionPolicy,
				},
			}
			adapter := NewVaultPolicyAdapter(policy)

			got := adapter.GetDeletionPolicy()
			if got != tt.deletionPolicy {
				t.Errorf("GetDeletionPolicy() = %q, want %q", got, tt.deletionPolicy)
			}
		})
	}
}

func TestVaultPolicyAdapter_GetConflictPolicy(t *testing.T) {
	tests := []struct {
		name           string
		conflictPolicy vaultv1alpha1.ConflictPolicy
	}{
		{
			name:           "fail policy",
			conflictPolicy: vaultv1alpha1.ConflictPolicyFail,
		},
		{
			name:           "adopt policy",
			conflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultPolicy{
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConflictPolicy: tt.conflictPolicy,
				},
			}
			adapter := NewVaultPolicyAdapter(policy)

			got := adapter.GetConflictPolicy()
			if got != tt.conflictPolicy {
				t.Errorf("GetConflictPolicy() = %q, want %q", got, tt.conflictPolicy)
			}
		})
	}
}

func TestVaultPolicyAdapter_StatusAccessors(t *testing.T) {
	t.Run("Phase get and set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		// Test initial empty phase
		if got := adapter.GetPhase(); got != "" {
			t.Errorf("GetPhase() initial = %q, want empty string", got)
		}

		// Test setting and getting various phases
		phases := []vaultv1alpha1.Phase{
			vaultv1alpha1.PhasePending,
			vaultv1alpha1.PhaseSyncing,
			vaultv1alpha1.PhaseActive,
			vaultv1alpha1.PhaseConflict,
			vaultv1alpha1.PhaseError,
			vaultv1alpha1.PhaseDeleting,
		}

		for _, phase := range phases {
			adapter.SetPhase(phase)
			if got := adapter.GetPhase(); got != phase {
				t.Errorf("GetPhase() after SetPhase(%q) = %q", phase, got)
			}
		}
	})

	t.Run("LastAppliedHash get and set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		// Test initial empty hash
		if got := adapter.GetLastAppliedHash(); got != "" {
			t.Errorf("GetLastAppliedHash() initial = %q, want empty string", got)
		}

		// Test setting and getting hash
		hashes := []string{
			"abc123",
			"sha256:deadbeef",
			"",
		}

		for _, hash := range hashes {
			adapter.SetLastAppliedHash(hash)
			if got := adapter.GetLastAppliedHash(); got != hash {
				t.Errorf("GetLastAppliedHash() after SetLastAppliedHash(%q) = %q", hash, got)
			}
		}
	})

	t.Run("VaultName get and set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		// Test initial empty vault name
		if got := adapter.GetVaultName(); got != "" {
			t.Errorf("GetVaultName() initial = %q, want empty string", got)
		}

		// Test setting and getting vault name
		vaultName := "default-my-policy"
		adapter.SetVaultName(vaultName)
		if got := adapter.GetVaultName(); got != vaultName {
			t.Errorf("GetVaultName() after SetVaultName(%q) = %q", vaultName, got)
		}
	})

	t.Run("Managed set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		adapter.SetManaged(true)
		if !policy.Status.Managed {
			t.Error("SetManaged(true) did not set Managed to true")
		}

		adapter.SetManaged(false)
		if policy.Status.Managed {
			t.Error("SetManaged(false) did not set Managed to false")
		}
	})

	t.Run("RulesCount set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		counts := []int{0, 1, 5, 100}
		for _, count := range counts {
			adapter.SetRulesCount(count)
			if policy.Status.RulesCount != count {
				t.Errorf("SetRulesCount(%d) resulted in %d", count, policy.Status.RulesCount)
			}
		}
	})

	t.Run("RetryCount get and set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		// Test initial zero retry count
		if got := adapter.GetRetryCount(); got != 0 {
			t.Errorf("GetRetryCount() initial = %d, want 0", got)
		}

		counts := []int{1, 5, 10}
		for _, count := range counts {
			adapter.SetRetryCount(count)
			if got := adapter.GetRetryCount(); got != count {
				t.Errorf("GetRetryCount() after SetRetryCount(%d) = %d", count, got)
			}
		}
	})

	t.Run("LastSyncedAt set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		now := metav1.NewTime(time.Now())
		adapter.SetLastSyncedAt(&now)
		if policy.Status.LastSyncedAt == nil || !policy.Status.LastSyncedAt.Equal(&now) {
			t.Error("SetLastSyncedAt did not set the time correctly")
		}

		adapter.SetLastSyncedAt(nil)
		if policy.Status.LastSyncedAt != nil {
			t.Error("SetLastSyncedAt(nil) did not clear the time")
		}
	})

	t.Run("LastAttemptAt set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		now := metav1.NewTime(time.Now())
		adapter.SetLastAttemptAt(&now)
		if policy.Status.LastAttemptAt == nil || !policy.Status.LastAttemptAt.Equal(&now) {
			t.Error("SetLastAttemptAt did not set the time correctly")
		}
	})

	t.Run("NextRetryAt set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		future := metav1.NewTime(time.Now().Add(time.Minute))
		adapter.SetNextRetryAt(&future)
		if policy.Status.NextRetryAt == nil || !policy.Status.NextRetryAt.Equal(&future) {
			t.Error("SetNextRetryAt did not set the time correctly")
		}
	})

	t.Run("Message set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		messages := []string{
			"",
			"Policy synced successfully",
			"Error: connection refused",
		}

		for _, msg := range messages {
			adapter.SetMessage(msg)
			if policy.Status.Message != msg {
				t.Errorf("SetMessage(%q) resulted in %q", msg, policy.Status.Message)
			}
		}
	})

	t.Run("Conditions get and set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultPolicy{}
		adapter := NewVaultPolicyAdapter(policy)

		// Test initial empty conditions
		if got := adapter.GetConditions(); len(got) != 0 {
			t.Errorf("GetConditions() initial = %v, want empty slice", got)
		}

		// Test setting conditions
		conditions := []vaultv1alpha1.Condition{
			{
				Type:               vaultv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             vaultv1alpha1.ReasonSucceeded,
				Message:            "Policy is ready",
			},
			{
				Type:               vaultv1alpha1.ConditionTypeSynced,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             vaultv1alpha1.ReasonSucceeded,
				Message:            "Policy is synced",
			},
		}

		adapter.SetConditions(conditions)
		got := adapter.GetConditions()
		if len(got) != len(conditions) {
			t.Errorf("GetConditions() returned %d conditions, want %d", len(got), len(conditions))
		}
		for i := range got {
			if got[i].Type != conditions[i].Type {
				t.Errorf("GetConditions()[%d].Type = %q, want %q", i, got[i].Type, conditions[i].Type)
			}
		}
	})
}

// =============================================================================
// VaultClusterPolicyAdapter Tests
// =============================================================================

func TestVaultClusterPolicyAdapter_GetVaultPolicyName(t *testing.T) {
	tests := []struct {
		name       string
		policyName string
		want       string
	}{
		{
			name:       "standard name",
			policyName: "my-cluster-policy",
			want:       "my-cluster-policy",
		},
		{
			name:       "hyphenated name",
			policyName: "global-read-policy",
			want:       "global-read-policy",
		},
		{
			name:       "single character name",
			policyName: "x",
			want:       "x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: tt.policyName,
				},
			}
			adapter := NewVaultClusterPolicyAdapter(policy)

			got := adapter.GetVaultPolicyName()
			if got != tt.want {
				t.Errorf("GetVaultPolicyName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVaultClusterPolicyAdapter_GetK8sResourceIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		policyName string
		want       string
	}{
		{
			name:       "standard name",
			policyName: "my-cluster-policy",
			want:       "my-cluster-policy",
		},
		{
			name:       "hyphenated name",
			policyName: "global-read-policy",
			want:       "global-read-policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: tt.policyName,
				},
			}
			adapter := NewVaultClusterPolicyAdapter(policy)

			got := adapter.GetK8sResourceIdentifier()
			if got != tt.want {
				t.Errorf("GetK8sResourceIdentifier() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVaultClusterPolicyAdapter_IsNamespaced(t *testing.T) {
	policy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-policy",
		},
	}
	adapter := NewVaultClusterPolicyAdapter(policy)

	got := adapter.IsNamespaced()
	if got {
		t.Errorf("IsNamespaced() = %v, want false", got)
	}
}

func TestVaultClusterPolicyAdapter_IsEnforceNamespaceBoundary(t *testing.T) {
	// VaultClusterPolicy should always return false for IsEnforceNamespaceBoundary
	policy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-policy",
		},
	}
	adapter := NewVaultClusterPolicyAdapter(policy)

	got := adapter.IsEnforceNamespaceBoundary()
	if got {
		t.Errorf("IsEnforceNamespaceBoundary() = %v, want false for cluster-scoped policy", got)
	}
}

func TestVaultClusterPolicyAdapter_GetConnectionRef(t *testing.T) {
	tests := []struct {
		name          string
		connectionRef string
	}{
		{
			name:          "standard connection ref",
			connectionRef: "vault-connection",
		},
		{
			name:          "hyphenated connection ref",
			connectionRef: "my-vault-connection",
		},
		{
			name:          "empty connection ref",
			connectionRef: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultClusterPolicy{
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: tt.connectionRef,
				},
			}
			adapter := NewVaultClusterPolicyAdapter(policy)

			got := adapter.GetConnectionRef()
			if got != tt.connectionRef {
				t.Errorf("GetConnectionRef() = %q, want %q", got, tt.connectionRef)
			}
		})
	}
}

func TestVaultClusterPolicyAdapter_GetRules(t *testing.T) {
	tests := []struct {
		name  string
		rules []vaultv1alpha1.PolicyRule
	}{
		{
			name:  "empty rules",
			rules: []vaultv1alpha1.PolicyRule{},
		},
		{
			name: "single rule",
			rules: []vaultv1alpha1.PolicyRule{
				{
					Path:         "secret/data/global/*",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
				},
			},
		},
		{
			name: "multiple rules with all capabilities",
			rules: []vaultv1alpha1.PolicyRule{
				{
					Path: "secret/data/global/*",
					Capabilities: []vaultv1alpha1.Capability{
						vaultv1alpha1.CapabilityCreate,
						vaultv1alpha1.CapabilityRead,
						vaultv1alpha1.CapabilityUpdate,
						vaultv1alpha1.CapabilityDelete,
						vaultv1alpha1.CapabilityList,
					},
				},
				{
					Path:         "auth/token/lookup-self",
					Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultClusterPolicy{
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					Rules: tt.rules,
				},
			}
			adapter := NewVaultClusterPolicyAdapter(policy)

			got := adapter.GetRules()
			if len(got) != len(tt.rules) {
				t.Errorf("GetRules() returned %d rules, want %d", len(got), len(tt.rules))
			}
			for i := range got {
				if got[i].Path != tt.rules[i].Path {
					t.Errorf("GetRules()[%d].Path = %q, want %q", i, got[i].Path, tt.rules[i].Path)
				}
			}
		})
	}
}

func TestVaultClusterPolicyAdapter_GetDeletionPolicy(t *testing.T) {
	tests := []struct {
		name           string
		deletionPolicy vaultv1alpha1.DeletionPolicy
	}{
		{
			name:           "delete policy",
			deletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
		{
			name:           "retain policy",
			deletionPolicy: vaultv1alpha1.DeletionPolicyRetain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultClusterPolicy{
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					DeletionPolicy: tt.deletionPolicy,
				},
			}
			adapter := NewVaultClusterPolicyAdapter(policy)

			got := adapter.GetDeletionPolicy()
			if got != tt.deletionPolicy {
				t.Errorf("GetDeletionPolicy() = %q, want %q", got, tt.deletionPolicy)
			}
		})
	}
}

func TestVaultClusterPolicyAdapter_GetConflictPolicy(t *testing.T) {
	tests := []struct {
		name           string
		conflictPolicy vaultv1alpha1.ConflictPolicy
	}{
		{
			name:           "fail policy",
			conflictPolicy: vaultv1alpha1.ConflictPolicyFail,
		},
		{
			name:           "adopt policy",
			conflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &vaultv1alpha1.VaultClusterPolicy{
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConflictPolicy: tt.conflictPolicy,
				},
			}
			adapter := NewVaultClusterPolicyAdapter(policy)

			got := adapter.GetConflictPolicy()
			if got != tt.conflictPolicy {
				t.Errorf("GetConflictPolicy() = %q, want %q", got, tt.conflictPolicy)
			}
		})
	}
}

func TestVaultClusterPolicyAdapter_StatusAccessors(t *testing.T) {
	t.Run("Phase get and set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		// Test initial empty phase
		if got := adapter.GetPhase(); got != "" {
			t.Errorf("GetPhase() initial = %q, want empty string", got)
		}

		// Test setting and getting various phases
		phases := []vaultv1alpha1.Phase{
			vaultv1alpha1.PhasePending,
			vaultv1alpha1.PhaseSyncing,
			vaultv1alpha1.PhaseActive,
			vaultv1alpha1.PhaseConflict,
			vaultv1alpha1.PhaseError,
			vaultv1alpha1.PhaseDeleting,
		}

		for _, phase := range phases {
			adapter.SetPhase(phase)
			if got := adapter.GetPhase(); got != phase {
				t.Errorf("GetPhase() after SetPhase(%q) = %q", phase, got)
			}
		}
	})

	t.Run("LastAppliedHash get and set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		// Test initial empty hash
		if got := adapter.GetLastAppliedHash(); got != "" {
			t.Errorf("GetLastAppliedHash() initial = %q, want empty string", got)
		}

		// Test setting and getting hash
		hashes := []string{
			"abc123",
			"sha256:deadbeef",
			"",
		}

		for _, hash := range hashes {
			adapter.SetLastAppliedHash(hash)
			if got := adapter.GetLastAppliedHash(); got != hash {
				t.Errorf("GetLastAppliedHash() after SetLastAppliedHash(%q) = %q", hash, got)
			}
		}
	})

	t.Run("VaultName get and set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		// Test initial empty vault name
		if got := adapter.GetVaultName(); got != "" {
			t.Errorf("GetVaultName() initial = %q, want empty string", got)
		}

		// Test setting and getting vault name
		vaultName := "cluster-policy"
		adapter.SetVaultName(vaultName)
		if got := adapter.GetVaultName(); got != vaultName {
			t.Errorf("GetVaultName() after SetVaultName(%q) = %q", vaultName, got)
		}
	})

	t.Run("Managed set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		adapter.SetManaged(true)
		if !policy.Status.Managed {
			t.Error("SetManaged(true) did not set Managed to true")
		}

		adapter.SetManaged(false)
		if policy.Status.Managed {
			t.Error("SetManaged(false) did not set Managed to false")
		}
	})

	t.Run("RulesCount set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		counts := []int{0, 1, 5, 100}
		for _, count := range counts {
			adapter.SetRulesCount(count)
			if policy.Status.RulesCount != count {
				t.Errorf("SetRulesCount(%d) resulted in %d", count, policy.Status.RulesCount)
			}
		}
	})

	t.Run("RetryCount get and set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		// Test initial zero retry count
		if got := adapter.GetRetryCount(); got != 0 {
			t.Errorf("GetRetryCount() initial = %d, want 0", got)
		}

		counts := []int{1, 5, 10}
		for _, count := range counts {
			adapter.SetRetryCount(count)
			if got := adapter.GetRetryCount(); got != count {
				t.Errorf("GetRetryCount() after SetRetryCount(%d) = %d", count, got)
			}
		}
	})

	t.Run("LastSyncedAt set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		now := metav1.NewTime(time.Now())
		adapter.SetLastSyncedAt(&now)
		if policy.Status.LastSyncedAt == nil || !policy.Status.LastSyncedAt.Equal(&now) {
			t.Error("SetLastSyncedAt did not set the time correctly")
		}

		adapter.SetLastSyncedAt(nil)
		if policy.Status.LastSyncedAt != nil {
			t.Error("SetLastSyncedAt(nil) did not clear the time")
		}
	})

	t.Run("LastAttemptAt set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		now := metav1.NewTime(time.Now())
		adapter.SetLastAttemptAt(&now)
		if policy.Status.LastAttemptAt == nil || !policy.Status.LastAttemptAt.Equal(&now) {
			t.Error("SetLastAttemptAt did not set the time correctly")
		}
	})

	t.Run("NextRetryAt set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		future := metav1.NewTime(time.Now().Add(time.Minute))
		adapter.SetNextRetryAt(&future)
		if policy.Status.NextRetryAt == nil || !policy.Status.NextRetryAt.Equal(&future) {
			t.Error("SetNextRetryAt did not set the time correctly")
		}
	})

	t.Run("Message set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		messages := []string{
			"",
			"Cluster policy synced successfully",
			"Error: permission denied",
		}

		for _, msg := range messages {
			adapter.SetMessage(msg)
			if policy.Status.Message != msg {
				t.Errorf("SetMessage(%q) resulted in %q", msg, policy.Status.Message)
			}
		}
	})

	t.Run("Conditions get and set", func(t *testing.T) {
		policy := &vaultv1alpha1.VaultClusterPolicy{}
		adapter := NewVaultClusterPolicyAdapter(policy)

		// Test initial empty conditions
		if got := adapter.GetConditions(); len(got) != 0 {
			t.Errorf("GetConditions() initial = %v, want empty slice", got)
		}

		// Test setting conditions
		conditions := []vaultv1alpha1.Condition{
			{
				Type:               vaultv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             vaultv1alpha1.ReasonSucceeded,
				Message:            "Cluster policy is ready",
			},
			{
				Type:               vaultv1alpha1.ConditionTypeSynced,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             vaultv1alpha1.ReasonSucceeded,
				Message:            "Cluster policy is synced",
			},
		}

		adapter.SetConditions(conditions)
		got := adapter.GetConditions()
		if len(got) != len(conditions) {
			t.Errorf("GetConditions() returned %d conditions, want %d", len(got), len(conditions))
		}
		for i := range got {
			if got[i].Type != conditions[i].Type {
				t.Errorf("GetConditions()[%d].Type = %q, want %q", i, got[i].Type, conditions[i].Type)
			}
		}
	})
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewVaultPolicyAdapter(t *testing.T) {
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "test-policy",
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "vault-connection",
		},
	}

	adapter := NewVaultPolicyAdapter(policy)

	if adapter == nil {
		t.Fatal("NewVaultPolicyAdapter returned nil")
	}
	if adapter.VaultPolicy != policy {
		t.Error("NewVaultPolicyAdapter did not set the underlying VaultPolicy correctly")
	}
}

func TestNewVaultClusterPolicyAdapter(t *testing.T) {
	policy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-policy",
		},
		Spec: vaultv1alpha1.VaultClusterPolicySpec{
			ConnectionRef: "vault-connection",
		},
	}

	adapter := NewVaultClusterPolicyAdapter(policy)

	if adapter == nil {
		t.Fatal("NewVaultClusterPolicyAdapter returned nil")
	}
	if adapter.VaultClusterPolicy != policy {
		t.Error("NewVaultClusterPolicyAdapter did not set the underlying VaultClusterPolicy correctly")
	}
}

// =============================================================================
// Interface Compliance Tests
// =============================================================================

func TestVaultPolicyAdapter_ImplementsPolicyAdapter(t *testing.T) {
	var _ PolicyAdapter = (*VaultPolicyAdapter)(nil)
}

func TestVaultClusterPolicyAdapter_ImplementsPolicyAdapter(t *testing.T) {
	var _ PolicyAdapter = (*VaultClusterPolicyAdapter)(nil)
}

// =============================================================================
// Comparison Tests (Namespaced vs Cluster-Scoped)
// =============================================================================

func TestPolicyAdapters_NamespaceVsClusterScoped(t *testing.T) {
	// Create both adapters with similar names to verify namespace handling difference
	namespacedPolicy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "production",
			Name:      "app-secrets",
		},
	}

	clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app-secrets",
		},
	}

	namespacedAdapter := NewVaultPolicyAdapter(namespacedPolicy)
	clusterAdapter := NewVaultClusterPolicyAdapter(clusterPolicy)

	t.Run("VaultPolicyName differs by namespace prefix", func(t *testing.T) {
		namespacedName := namespacedAdapter.GetVaultPolicyName()
		clusterName := clusterAdapter.GetVaultPolicyName()

		expectedNamespaced := "production-app-secrets"
		expectedCluster := "app-secrets"

		if namespacedName != expectedNamespaced {
			t.Errorf("Namespaced GetVaultPolicyName() = %q, want %q", namespacedName, expectedNamespaced)
		}
		if clusterName != expectedCluster {
			t.Errorf("Cluster GetVaultPolicyName() = %q, want %q", clusterName, expectedCluster)
		}
	})

	t.Run("K8sResourceIdentifier differs by namespace", func(t *testing.T) {
		namespacedID := namespacedAdapter.GetK8sResourceIdentifier()
		clusterID := clusterAdapter.GetK8sResourceIdentifier()

		expectedNamespaced := "production/app-secrets"
		expectedCluster := "app-secrets"

		if namespacedID != expectedNamespaced {
			t.Errorf("Namespaced GetK8sResourceIdentifier() = %q, want %q", namespacedID, expectedNamespaced)
		}
		if clusterID != expectedCluster {
			t.Errorf("Cluster GetK8sResourceIdentifier() = %q, want %q", clusterID, expectedCluster)
		}
	})

	t.Run("IsNamespaced returns correct value", func(t *testing.T) {
		if !namespacedAdapter.IsNamespaced() {
			t.Error("Namespaced adapter should return true for IsNamespaced()")
		}
		if clusterAdapter.IsNamespaced() {
			t.Error("Cluster adapter should return false for IsNamespaced()")
		}
	})

	t.Run("IsEnforceNamespaceBoundary behavior", func(t *testing.T) {
		// Even with enforce enabled on namespaced, cluster should always be false
		namespacedPolicy.Spec.EnforceNamespaceBoundary = boolPtr(true)

		if !namespacedAdapter.IsEnforceNamespaceBoundary() {
			t.Error("Namespaced adapter with enforce=true should return true")
		}
		if clusterAdapter.IsEnforceNamespaceBoundary() {
			t.Error("Cluster adapter should always return false for IsEnforceNamespaceBoundary()")
		}
	})
}
