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
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// Test constants
const (
	testRoleName       = "test-role"
	testNamespace      = "test-namespace"
	testConnectionRef  = "test-connection"
	testAuthPath       = "auth/kubernetes"
	testTokenTTL       = "1h"
	testTokenMaxTTL    = "24h"
	testServiceAccount = "test-sa"
)

// Helper function to create a test VaultRole
func newTestVaultRole() *vaultv1alpha1.VaultRole {
	return &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRoleName,
			Namespace: testNamespace,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:  testConnectionRef,
			AuthPath:       testAuthPath,
			ConflictPolicy: vaultv1alpha1.ConflictPolicyFail,
			ServiceAccounts: []string{
				"sa1",
				"sa2",
			},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "policy1", Namespace: testNamespace},
				{Kind: "VaultClusterPolicy", Name: "cluster-policy"},
			},
			TokenTTL:       testTokenTTL,
			TokenMaxTTL:    testTokenMaxTTL,
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
		Status: vaultv1alpha1.VaultRoleStatus{},
	}
}

// Helper function to create a test VaultClusterRole
func newTestVaultClusterRole() *vaultv1alpha1.VaultClusterRole {
	return &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: testRoleName,
		},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			ConnectionRef:  testConnectionRef,
			AuthPath:       testAuthPath,
			ConflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
			ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "sa1", Namespace: "ns1"},
				{Name: "sa2", Namespace: "ns2"},
			},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "policy1", Namespace: "default"},
				{Kind: "VaultClusterPolicy", Name: "cluster-policy"},
			},
			TokenTTL:       testTokenTTL,
			TokenMaxTTL:    testTokenMaxTTL,
			DeletionPolicy: vaultv1alpha1.DeletionPolicyRetain,
		},
		Status: vaultv1alpha1.VaultClusterRoleStatus{},
	}
}

// ============================================================================
// VaultRoleAdapter Tests
// ============================================================================

func TestNewVaultRoleAdapter(t *testing.T) {
	role := newTestVaultRole()
	adapter := NewVaultRoleAdapter(role)

	if adapter == nil {
		t.Fatal("expected adapter to be non-nil")
		return
	}

	if adapter.VaultRole != role {
		t.Error("expected adapter to wrap the provided VaultRole")
	}
}

func TestVaultRoleAdapter_GetVaultRoleName(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		roleName  string
		expected  string
	}{
		{
			name:      "standard namespace and name",
			namespace: "default",
			roleName:  "my-role",
			expected:  "default-my-role",
		},
		{
			name:      "production namespace",
			namespace: "production",
			roleName:  "app-role",
			expected:  "production-app-role",
		},
		{
			name:      "complex names",
			namespace: "my-namespace",
			roleName:  "my-complex-role-name",
			expected:  "my-namespace-my-complex-role-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tt.roleName,
					Namespace: tt.namespace,
				},
			}
			adapter := NewVaultRoleAdapter(role)

			result := adapter.GetVaultRoleName()

			if result != tt.expected {
				t.Errorf("GetVaultRoleName() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestVaultRoleAdapter_GetK8sResourceIdentifier(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		roleName  string
		expected  string
	}{
		{
			name:      "standard namespace and name",
			namespace: "default",
			roleName:  "my-role",
			expected:  "default/my-role",
		},
		{
			name:      "production namespace",
			namespace: "production",
			roleName:  "app-role",
			expected:  "production/app-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tt.roleName,
					Namespace: tt.namespace,
				},
			}
			adapter := NewVaultRoleAdapter(role)

			result := adapter.GetK8sResourceIdentifier()

			if result != tt.expected {
				t.Errorf("GetK8sResourceIdentifier() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestVaultRoleAdapter_IsNamespaced(t *testing.T) {
	role := newTestVaultRole()
	adapter := NewVaultRoleAdapter(role)

	if !adapter.IsNamespaced() {
		t.Error("VaultRoleAdapter.IsNamespaced() should return true")
	}
}

func TestVaultRoleAdapter_GetServiceAccountBindings(t *testing.T) {
	tests := []struct {
		name            string
		namespace       string
		serviceAccounts []string
		expected        []string
	}{
		{
			name:            "single service account",
			namespace:       "default",
			serviceAccounts: []string{"my-sa"},
			expected:        []string{"default/my-sa"},
		},
		{
			name:            "multiple service accounts",
			namespace:       "production",
			serviceAccounts: []string{"sa1", "sa2", "sa3"},
			expected:        []string{"production/sa1", "production/sa2", "production/sa3"},
		},
		{
			name:            "empty service accounts",
			namespace:       "default",
			serviceAccounts: []string{},
			expected:        []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: tt.namespace,
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ServiceAccounts: tt.serviceAccounts,
				},
			}
			adapter := NewVaultRoleAdapter(role)

			result := adapter.GetServiceAccountBindings()

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("GetServiceAccountBindings() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVaultRoleAdapter_GetConnectionRef(t *testing.T) {
	role := newTestVaultRole()
	adapter := NewVaultRoleAdapter(role)

	result := adapter.GetConnectionRef()

	if result != testConnectionRef {
		t.Errorf("GetConnectionRef() = %q, want %q", result, testConnectionRef)
	}
}

func TestVaultRoleAdapter_GetAuthPath(t *testing.T) {
	tests := []struct {
		name     string
		authPath string
		expected string
	}{
		{
			name:     "standard auth path",
			authPath: "auth/kubernetes",
			expected: "auth/kubernetes",
		},
		{
			name:     "custom auth path",
			authPath: "kubernetes",
			expected: "kubernetes",
		},
		{
			name:     "empty auth path",
			authPath: "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultRole{
				Spec: vaultv1alpha1.VaultRoleSpec{
					AuthPath: tt.authPath,
				},
			}
			adapter := NewVaultRoleAdapter(role)

			result := adapter.GetAuthPath()

			if result != tt.expected {
				t.Errorf("GetAuthPath() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestVaultRoleAdapter_GetConflictPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   vaultv1alpha1.ConflictPolicy
		expected vaultv1alpha1.ConflictPolicy
	}{
		{
			name:     "fail policy",
			policy:   vaultv1alpha1.ConflictPolicyFail,
			expected: vaultv1alpha1.ConflictPolicyFail,
		},
		{
			name:     "adopt policy",
			policy:   vaultv1alpha1.ConflictPolicyAdopt,
			expected: vaultv1alpha1.ConflictPolicyAdopt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultRole{
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConflictPolicy: tt.policy,
				},
			}
			adapter := NewVaultRoleAdapter(role)

			result := adapter.GetConflictPolicy()

			if result != tt.expected {
				t.Errorf("GetConflictPolicy() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVaultRoleAdapter_GetPolicies(t *testing.T) {
	policies := []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "policy1", Namespace: "ns1"},
		{Kind: "VaultClusterPolicy", Name: "cluster-policy"},
	}

	role := &vaultv1alpha1.VaultRole{
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: policies,
		},
	}
	adapter := NewVaultRoleAdapter(role)

	result := adapter.GetPolicies()

	if !reflect.DeepEqual(result, policies) {
		t.Errorf("GetPolicies() = %v, want %v", result, policies)
	}
}

func TestVaultRoleAdapter_GetTokenTTL(t *testing.T) {
	role := newTestVaultRole()
	adapter := NewVaultRoleAdapter(role)

	result := adapter.GetTokenTTL()

	if result != testTokenTTL {
		t.Errorf("GetTokenTTL() = %q, want %q", result, testTokenTTL)
	}
}

func TestVaultRoleAdapter_GetTokenMaxTTL(t *testing.T) {
	role := newTestVaultRole()
	adapter := NewVaultRoleAdapter(role)

	result := adapter.GetTokenMaxTTL()

	if result != testTokenMaxTTL {
		t.Errorf("GetTokenMaxTTL() = %q, want %q", result, testTokenMaxTTL)
	}
}

func TestVaultRoleAdapter_GetDeletionPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   vaultv1alpha1.DeletionPolicy
		expected vaultv1alpha1.DeletionPolicy
	}{
		{
			name:     "delete policy",
			policy:   vaultv1alpha1.DeletionPolicyDelete,
			expected: vaultv1alpha1.DeletionPolicyDelete,
		},
		{
			name:     "retain policy",
			policy:   vaultv1alpha1.DeletionPolicyRetain,
			expected: vaultv1alpha1.DeletionPolicyRetain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultRole{
				Spec: vaultv1alpha1.VaultRoleSpec{
					DeletionPolicy: tt.policy,
				},
			}
			adapter := NewVaultRoleAdapter(role)

			result := adapter.GetDeletionPolicy()

			if result != tt.expected {
				t.Errorf("GetDeletionPolicy() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVaultRoleAdapter_StatusAccessors(t *testing.T) {
	role := newTestVaultRole()
	adapter := NewVaultRoleAdapter(role)

	t.Run("Phase", func(t *testing.T) {
		// Initial phase should be empty
		if adapter.GetPhase() != "" {
			t.Errorf("initial GetPhase() = %q, want empty string", adapter.GetPhase())
		}

		// Set phase and verify
		adapter.SetPhase(vaultv1alpha1.PhaseActive)
		if adapter.GetPhase() != vaultv1alpha1.PhaseActive {
			t.Errorf("GetPhase() = %q, want %q", adapter.GetPhase(), vaultv1alpha1.PhaseActive)
		}

		// Verify the underlying VaultRole status was updated
		if role.Status.Phase != vaultv1alpha1.PhaseActive {
			t.Errorf("role.Status.Phase = %q, want %q", role.Status.Phase, vaultv1alpha1.PhaseActive)
		}
	})

	t.Run("VaultRoleName", func(t *testing.T) {
		vaultRoleName := "test-namespace-test-role"
		adapter.SetVaultRoleName(vaultRoleName)

		if role.Status.VaultRoleName != vaultRoleName {
			t.Errorf("role.Status.VaultRoleName = %q, want %q", role.Status.VaultRoleName, vaultRoleName)
		}
	})

	t.Run("Managed", func(t *testing.T) {
		adapter.SetManaged(true)

		if !role.Status.Managed {
			t.Error("role.Status.Managed should be true")
		}

		adapter.SetManaged(false)

		if role.Status.Managed {
			t.Error("role.Status.Managed should be false")
		}
	})

	t.Run("BoundServiceAccounts", func(t *testing.T) {
		accounts := []string{"ns1/sa1", "ns2/sa2"}
		adapter.SetBoundServiceAccounts(accounts)

		if !reflect.DeepEqual(role.Status.BoundServiceAccounts, accounts) {
			t.Errorf("role.Status.BoundServiceAccounts = %v, want %v", role.Status.BoundServiceAccounts, accounts)
		}
	})

	t.Run("ResolvedPolicies", func(t *testing.T) {
		policies := []string{"ns-policy1", "cluster-policy2"}
		adapter.SetResolvedPolicies(policies)

		if !reflect.DeepEqual(role.Status.ResolvedPolicies, policies) {
			t.Errorf("role.Status.ResolvedPolicies = %v, want %v", role.Status.ResolvedPolicies, policies)
		}
	})

	t.Run("LastSyncedAt", func(t *testing.T) {
		now := metav1.NewTime(time.Now())
		adapter.SetLastSyncedAt(&now)

		if role.Status.LastSyncedAt == nil || !role.Status.LastSyncedAt.Equal(&now) {
			t.Errorf("role.Status.LastSyncedAt = %v, want %v", role.Status.LastSyncedAt, &now)
		}

		// Test nil
		adapter.SetLastSyncedAt(nil)
		if role.Status.LastSyncedAt != nil {
			t.Errorf("role.Status.LastSyncedAt = %v, want nil", role.Status.LastSyncedAt)
		}
	})

	t.Run("LastAttemptAt", func(t *testing.T) {
		now := metav1.NewTime(time.Now())
		adapter.SetLastAttemptAt(&now)

		if role.Status.LastAttemptAt == nil || !role.Status.LastAttemptAt.Equal(&now) {
			t.Errorf("role.Status.LastAttemptAt = %v, want %v", role.Status.LastAttemptAt, &now)
		}
	})

	t.Run("RetryCount", func(t *testing.T) {
		// Initial retry count should be 0
		if adapter.GetRetryCount() != 0 {
			t.Errorf("initial GetRetryCount() = %d, want 0", adapter.GetRetryCount())
		}

		adapter.SetRetryCount(5)

		if adapter.GetRetryCount() != 5 {
			t.Errorf("GetRetryCount() = %d, want 5", adapter.GetRetryCount())
		}

		if role.Status.RetryCount != 5 {
			t.Errorf("role.Status.RetryCount = %d, want 5", role.Status.RetryCount)
		}
	})

	t.Run("NextRetryAt", func(t *testing.T) {
		futureTime := metav1.NewTime(time.Now().Add(5 * time.Minute))
		adapter.SetNextRetryAt(&futureTime)

		if role.Status.NextRetryAt == nil || !role.Status.NextRetryAt.Equal(&futureTime) {
			t.Errorf("role.Status.NextRetryAt = %v, want %v", role.Status.NextRetryAt, &futureTime)
		}
	})

	t.Run("Message", func(t *testing.T) {
		message := "Role successfully synced to Vault"
		adapter.SetMessage(message)

		if role.Status.Message != message {
			t.Errorf("role.Status.Message = %q, want %q", role.Status.Message, message)
		}
	})

	t.Run("Conditions", func(t *testing.T) {
		// Initial conditions should be empty
		if len(adapter.GetConditions()) != 0 {
			t.Errorf("initial GetConditions() length = %d, want 0", len(adapter.GetConditions()))
		}

		conditions := []vaultv1alpha1.Condition{
			{
				Type:               vaultv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             vaultv1alpha1.ReasonSucceeded,
				Message:            "Role is ready",
			},
			{
				Type:               vaultv1alpha1.ConditionTypeSynced,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             vaultv1alpha1.ReasonSucceeded,
				Message:            "Role is synced",
			},
		}
		adapter.SetConditions(conditions)

		result := adapter.GetConditions()
		if len(result) != 2 {
			t.Fatalf("GetConditions() length = %d, want 2", len(result))
		}

		if result[0].Type != vaultv1alpha1.ConditionTypeReady {
			t.Errorf("GetConditions()[0].Type = %q, want %q", result[0].Type, vaultv1alpha1.ConditionTypeReady)
		}

		if !reflect.DeepEqual(role.Status.Conditions, conditions) {
			t.Errorf("role.Status.Conditions = %v, want %v", role.Status.Conditions, conditions)
		}
	})
}

// ============================================================================
// VaultClusterRoleAdapter Tests
// ============================================================================

func TestNewVaultClusterRoleAdapter(t *testing.T) {
	role := newTestVaultClusterRole()
	adapter := NewVaultClusterRoleAdapter(role)

	if adapter == nil {
		t.Fatal("expected adapter to be non-nil")
		return
	}

	if adapter.VaultClusterRole != role {
		t.Error("expected adapter to wrap the provided VaultClusterRole")
	}
}

func TestVaultClusterRoleAdapter_GetVaultRoleName(t *testing.T) {
	tests := []struct {
		name     string
		roleName string
		expected string
	}{
		{
			name:     "simple name",
			roleName: "my-role",
			expected: "my-role",
		},
		{
			name:     "complex name",
			roleName: "my-complex-cluster-role",
			expected: "my-complex-cluster-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: tt.roleName,
				},
			}
			adapter := NewVaultClusterRoleAdapter(role)

			result := adapter.GetVaultRoleName()

			if result != tt.expected {
				t.Errorf("GetVaultRoleName() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestVaultClusterRoleAdapter_GetK8sResourceIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		roleName string
		expected string
	}{
		{
			name:     "simple name",
			roleName: "my-role",
			expected: "my-role",
		},
		{
			name:     "complex name",
			roleName: "my-cluster-role",
			expected: "my-cluster-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: tt.roleName,
				},
			}
			adapter := NewVaultClusterRoleAdapter(role)

			result := adapter.GetK8sResourceIdentifier()

			if result != tt.expected {
				t.Errorf("GetK8sResourceIdentifier() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestVaultClusterRoleAdapter_IsNamespaced(t *testing.T) {
	role := newTestVaultClusterRole()
	adapter := NewVaultClusterRoleAdapter(role)

	if adapter.IsNamespaced() {
		t.Error("VaultClusterRoleAdapter.IsNamespaced() should return false")
	}
}

func TestVaultClusterRoleAdapter_GetServiceAccountBindings(t *testing.T) {
	tests := []struct {
		name            string
		serviceAccounts []vaultv1alpha1.ServiceAccountRef
		expected        []string
	}{
		{
			name: "single service account",
			serviceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "my-sa", Namespace: "default"},
			},
			expected: []string{"default/my-sa"},
		},
		{
			name: "multiple service accounts from different namespaces",
			serviceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "sa1", Namespace: "ns1"},
				{Name: "sa2", Namespace: "ns2"},
				{Name: "sa3", Namespace: "ns3"},
			},
			expected: []string{"ns1/sa1", "ns2/sa2", "ns3/sa3"},
		},
		{
			name:            "empty service accounts",
			serviceAccounts: []vaultv1alpha1.ServiceAccountRef{},
			expected:        []string{},
		},
		{
			name: "same namespace different accounts",
			serviceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "sa1", Namespace: "production"},
				{Name: "sa2", Namespace: "production"},
			},
			expected: []string{"production/sa1", "production/sa2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ServiceAccounts: tt.serviceAccounts,
				},
			}
			adapter := NewVaultClusterRoleAdapter(role)

			result := adapter.GetServiceAccountBindings()

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("GetServiceAccountBindings() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVaultClusterRoleAdapter_GetConnectionRef(t *testing.T) {
	role := newTestVaultClusterRole()
	adapter := NewVaultClusterRoleAdapter(role)

	result := adapter.GetConnectionRef()

	if result != testConnectionRef {
		t.Errorf("GetConnectionRef() = %q, want %q", result, testConnectionRef)
	}
}

func TestVaultClusterRoleAdapter_GetAuthPath(t *testing.T) {
	tests := []struct {
		name     string
		authPath string
		expected string
	}{
		{
			name:     "standard auth path",
			authPath: "auth/kubernetes",
			expected: "auth/kubernetes",
		},
		{
			name:     "custom auth path",
			authPath: "kubernetes-cluster1",
			expected: "kubernetes-cluster1",
		},
		{
			name:     "empty auth path",
			authPath: "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultClusterRole{
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					AuthPath: tt.authPath,
				},
			}
			adapter := NewVaultClusterRoleAdapter(role)

			result := adapter.GetAuthPath()

			if result != tt.expected {
				t.Errorf("GetAuthPath() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestVaultClusterRoleAdapter_GetConflictPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   vaultv1alpha1.ConflictPolicy
		expected vaultv1alpha1.ConflictPolicy
	}{
		{
			name:     "fail policy",
			policy:   vaultv1alpha1.ConflictPolicyFail,
			expected: vaultv1alpha1.ConflictPolicyFail,
		},
		{
			name:     "adopt policy",
			policy:   vaultv1alpha1.ConflictPolicyAdopt,
			expected: vaultv1alpha1.ConflictPolicyAdopt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultClusterRole{
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConflictPolicy: tt.policy,
				},
			}
			adapter := NewVaultClusterRoleAdapter(role)

			result := adapter.GetConflictPolicy()

			if result != tt.expected {
				t.Errorf("GetConflictPolicy() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVaultClusterRoleAdapter_GetPolicies(t *testing.T) {
	policies := []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "policy1", Namespace: "ns1"},
		{Kind: "VaultClusterPolicy", Name: "cluster-policy"},
	}

	role := &vaultv1alpha1.VaultClusterRole{
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			Policies: policies,
		},
	}
	adapter := NewVaultClusterRoleAdapter(role)

	result := adapter.GetPolicies()

	if !reflect.DeepEqual(result, policies) {
		t.Errorf("GetPolicies() = %v, want %v", result, policies)
	}
}

func TestVaultClusterRoleAdapter_GetTokenTTL(t *testing.T) {
	role := newTestVaultClusterRole()
	adapter := NewVaultClusterRoleAdapter(role)

	result := adapter.GetTokenTTL()

	if result != testTokenTTL {
		t.Errorf("GetTokenTTL() = %q, want %q", result, testTokenTTL)
	}
}

func TestVaultClusterRoleAdapter_GetTokenMaxTTL(t *testing.T) {
	role := newTestVaultClusterRole()
	adapter := NewVaultClusterRoleAdapter(role)

	result := adapter.GetTokenMaxTTL()

	if result != testTokenMaxTTL {
		t.Errorf("GetTokenMaxTTL() = %q, want %q", result, testTokenMaxTTL)
	}
}

func TestVaultClusterRoleAdapter_GetDeletionPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   vaultv1alpha1.DeletionPolicy
		expected vaultv1alpha1.DeletionPolicy
	}{
		{
			name:     "delete policy",
			policy:   vaultv1alpha1.DeletionPolicyDelete,
			expected: vaultv1alpha1.DeletionPolicyDelete,
		},
		{
			name:     "retain policy",
			policy:   vaultv1alpha1.DeletionPolicyRetain,
			expected: vaultv1alpha1.DeletionPolicyRetain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := &vaultv1alpha1.VaultClusterRole{
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					DeletionPolicy: tt.policy,
				},
			}
			adapter := NewVaultClusterRoleAdapter(role)

			result := adapter.GetDeletionPolicy()

			if result != tt.expected {
				t.Errorf("GetDeletionPolicy() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVaultClusterRoleAdapter_StatusAccessors(t *testing.T) {
	role := newTestVaultClusterRole()
	adapter := NewVaultClusterRoleAdapter(role)

	t.Run("Phase", func(t *testing.T) {
		// Initial phase should be empty
		if adapter.GetPhase() != "" {
			t.Errorf("initial GetPhase() = %q, want empty string", adapter.GetPhase())
		}

		// Set phase and verify
		adapter.SetPhase(vaultv1alpha1.PhaseSyncing)
		if adapter.GetPhase() != vaultv1alpha1.PhaseSyncing {
			t.Errorf("GetPhase() = %q, want %q", adapter.GetPhase(), vaultv1alpha1.PhaseSyncing)
		}

		// Verify the underlying VaultClusterRole status was updated
		if role.Status.Phase != vaultv1alpha1.PhaseSyncing {
			t.Errorf("role.Status.Phase = %q, want %q", role.Status.Phase, vaultv1alpha1.PhaseSyncing)
		}
	})

	t.Run("VaultRoleName", func(t *testing.T) {
		vaultRoleName := "test-cluster-role"
		adapter.SetVaultRoleName(vaultRoleName)

		if role.Status.VaultRoleName != vaultRoleName {
			t.Errorf("role.Status.VaultRoleName = %q, want %q", role.Status.VaultRoleName, vaultRoleName)
		}
	})

	t.Run("Managed", func(t *testing.T) {
		adapter.SetManaged(true)

		if !role.Status.Managed {
			t.Error("role.Status.Managed should be true")
		}

		adapter.SetManaged(false)

		if role.Status.Managed {
			t.Error("role.Status.Managed should be false")
		}
	})

	t.Run("BoundServiceAccounts", func(t *testing.T) {
		accounts := []string{"ns1/sa1", "ns2/sa2", "ns3/sa3"}
		adapter.SetBoundServiceAccounts(accounts)

		if !reflect.DeepEqual(role.Status.BoundServiceAccounts, accounts) {
			t.Errorf("role.Status.BoundServiceAccounts = %v, want %v", role.Status.BoundServiceAccounts, accounts)
		}
	})

	t.Run("ResolvedPolicies", func(t *testing.T) {
		policies := []string{"ns-policy1", "cluster-policy2", "default-policy3"}
		adapter.SetResolvedPolicies(policies)

		if !reflect.DeepEqual(role.Status.ResolvedPolicies, policies) {
			t.Errorf("role.Status.ResolvedPolicies = %v, want %v", role.Status.ResolvedPolicies, policies)
		}
	})

	t.Run("LastSyncedAt", func(t *testing.T) {
		now := metav1.NewTime(time.Now())
		adapter.SetLastSyncedAt(&now)

		if role.Status.LastSyncedAt == nil || !role.Status.LastSyncedAt.Equal(&now) {
			t.Errorf("role.Status.LastSyncedAt = %v, want %v", role.Status.LastSyncedAt, &now)
		}

		// Test nil
		adapter.SetLastSyncedAt(nil)
		if role.Status.LastSyncedAt != nil {
			t.Errorf("role.Status.LastSyncedAt = %v, want nil", role.Status.LastSyncedAt)
		}
	})

	t.Run("LastAttemptAt", func(t *testing.T) {
		now := metav1.NewTime(time.Now())
		adapter.SetLastAttemptAt(&now)

		if role.Status.LastAttemptAt == nil || !role.Status.LastAttemptAt.Equal(&now) {
			t.Errorf("role.Status.LastAttemptAt = %v, want %v", role.Status.LastAttemptAt, &now)
		}
	})

	t.Run("RetryCount", func(t *testing.T) {
		// Initial retry count should be 0
		if adapter.GetRetryCount() != 0 {
			t.Errorf("initial GetRetryCount() = %d, want 0", adapter.GetRetryCount())
		}

		adapter.SetRetryCount(3)

		if adapter.GetRetryCount() != 3 {
			t.Errorf("GetRetryCount() = %d, want 3", adapter.GetRetryCount())
		}

		if role.Status.RetryCount != 3 {
			t.Errorf("role.Status.RetryCount = %d, want 3", role.Status.RetryCount)
		}
	})

	t.Run("NextRetryAt", func(t *testing.T) {
		futureTime := metav1.NewTime(time.Now().Add(10 * time.Minute))
		adapter.SetNextRetryAt(&futureTime)

		if role.Status.NextRetryAt == nil || !role.Status.NextRetryAt.Equal(&futureTime) {
			t.Errorf("role.Status.NextRetryAt = %v, want %v", role.Status.NextRetryAt, &futureTime)
		}
	})

	t.Run("Message", func(t *testing.T) {
		message := "Cluster role successfully created in Vault"
		adapter.SetMessage(message)

		if role.Status.Message != message {
			t.Errorf("role.Status.Message = %q, want %q", role.Status.Message, message)
		}
	})

	t.Run("Conditions", func(t *testing.T) {
		// Initial conditions should be empty
		if len(adapter.GetConditions()) != 0 {
			t.Errorf("initial GetConditions() length = %d, want 0", len(adapter.GetConditions()))
		}

		conditions := []vaultv1alpha1.Condition{
			{
				Type:               vaultv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             vaultv1alpha1.ReasonSucceeded,
				Message:            "Cluster role is ready",
			},
		}
		adapter.SetConditions(conditions)

		result := adapter.GetConditions()
		if len(result) != 1 {
			t.Fatalf("GetConditions() length = %d, want 1", len(result))
		}

		if result[0].Type != vaultv1alpha1.ConditionTypeReady {
			t.Errorf("GetConditions()[0].Type = %q, want %q", result[0].Type, vaultv1alpha1.ConditionTypeReady)
		}

		if !reflect.DeepEqual(role.Status.Conditions, conditions) {
			t.Errorf("role.Status.Conditions = %v, want %v", role.Status.Conditions, conditions)
		}
	})
}

// ============================================================================
// Interface Compliance Tests
// ============================================================================

func TestVaultRoleAdapter_ImplementsRoleAdapter(t *testing.T) {
	var _ RoleAdapter = (*VaultRoleAdapter)(nil)
}

func TestVaultClusterRoleAdapter_ImplementsRoleAdapter(t *testing.T) {
	var _ RoleAdapter = (*VaultClusterRoleAdapter)(nil)
}

// ============================================================================
// Comparison Tests
// ============================================================================

func TestVaultRoleAdapter_VsVaultClusterRoleAdapter(t *testing.T) {
	// Create both adapters with similar data
	vaultRole := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared-role",
			Namespace: "my-namespace",
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "shared-connection",
			ServiceAccounts: []string{"sa1", "sa2"},
		},
	}

	vaultClusterRole := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "shared-role",
		},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			ConnectionRef: "shared-connection",
			ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "sa1", Namespace: "my-namespace"},
				{Name: "sa2", Namespace: "my-namespace"},
			},
		},
	}

	roleAdapter := NewVaultRoleAdapter(vaultRole)
	clusterRoleAdapter := NewVaultClusterRoleAdapter(vaultClusterRole)

	t.Run("GetVaultRoleName differs", func(t *testing.T) {
		// VaultRole: namespace-name format
		roleResult := roleAdapter.GetVaultRoleName()
		expectedRole := "my-namespace-shared-role"
		if roleResult != expectedRole {
			t.Errorf("VaultRoleAdapter.GetVaultRoleName() = %q, want %q", roleResult, expectedRole)
		}

		// VaultClusterRole: just name
		clusterResult := clusterRoleAdapter.GetVaultRoleName()
		expectedCluster := "shared-role"
		if clusterResult != expectedCluster {
			t.Errorf("VaultClusterRoleAdapter.GetVaultRoleName() = %q, want %q", clusterResult, expectedCluster)
		}
	})

	t.Run("GetK8sResourceIdentifier differs", func(t *testing.T) {
		// VaultRole: namespace/name format
		roleResult := roleAdapter.GetK8sResourceIdentifier()
		expectedRole := "my-namespace/shared-role"
		if roleResult != expectedRole {
			t.Errorf("VaultRoleAdapter.GetK8sResourceIdentifier() = %q, want %q", roleResult, expectedRole)
		}

		// VaultClusterRole: just name
		clusterResult := clusterRoleAdapter.GetK8sResourceIdentifier()
		expectedCluster := "shared-role"
		if clusterResult != expectedCluster {
			t.Errorf("VaultClusterRoleAdapter.GetK8sResourceIdentifier() = %q, want %q", clusterResult, expectedCluster)
		}
	})

	t.Run("IsNamespaced differs", func(t *testing.T) {
		if !roleAdapter.IsNamespaced() {
			t.Error("VaultRoleAdapter.IsNamespaced() should be true")
		}

		if clusterRoleAdapter.IsNamespaced() {
			t.Error("VaultClusterRoleAdapter.IsNamespaced() should be false")
		}
	})

	t.Run("GetServiceAccountBindings produces same result with matching data", func(t *testing.T) {
		roleBindings := roleAdapter.GetServiceAccountBindings()
		clusterBindings := clusterRoleAdapter.GetServiceAccountBindings()

		// Both should produce the same bindings when data matches
		if !reflect.DeepEqual(roleBindings, clusterBindings) {
			t.Errorf("Bindings should match: role=%v, cluster=%v", roleBindings, clusterBindings)
		}
	})

	t.Run("GetConnectionRef is same", func(t *testing.T) {
		if roleAdapter.GetConnectionRef() != clusterRoleAdapter.GetConnectionRef() {
			t.Errorf("ConnectionRef should match: role=%q, cluster=%q",
				roleAdapter.GetConnectionRef(), clusterRoleAdapter.GetConnectionRef())
		}
	})
}

// ============================================================================
// Edge Cases Tests
// ============================================================================

func TestVaultRoleAdapter_EmptyServiceAccounts(t *testing.T) {
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "test-ns",
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ServiceAccounts: []string{},
		},
	}
	adapter := NewVaultRoleAdapter(role)

	bindings := adapter.GetServiceAccountBindings()

	if len(bindings) != 0 {
		t.Errorf("expected empty bindings, got %v", bindings)
	}
}

func TestVaultClusterRoleAdapter_EmptyServiceAccounts(t *testing.T) {
	role := &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-role",
		},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{},
		},
	}
	adapter := NewVaultClusterRoleAdapter(role)

	bindings := adapter.GetServiceAccountBindings()

	if len(bindings) != 0 {
		t.Errorf("expected empty bindings, got %v", bindings)
	}
}

func TestVaultRoleAdapter_EmptyPolicies(t *testing.T) {
	role := &vaultv1alpha1.VaultRole{
		Spec: vaultv1alpha1.VaultRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{},
		},
	}
	adapter := NewVaultRoleAdapter(role)

	policies := adapter.GetPolicies()

	if len(policies) != 0 {
		t.Errorf("expected empty policies, got %v", policies)
	}
}

func TestVaultClusterRoleAdapter_EmptyPolicies(t *testing.T) {
	role := &vaultv1alpha1.VaultClusterRole{
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			Policies: []vaultv1alpha1.PolicyReference{},
		},
	}
	adapter := NewVaultClusterRoleAdapter(role)

	policies := adapter.GetPolicies()

	if len(policies) != 0 {
		t.Errorf("expected empty policies, got %v", policies)
	}
}

func TestVaultRoleAdapter_AllPhases(t *testing.T) {
	phases := []vaultv1alpha1.Phase{
		vaultv1alpha1.PhasePending,
		vaultv1alpha1.PhaseSyncing,
		vaultv1alpha1.PhaseActive,
		vaultv1alpha1.PhaseConflict,
		vaultv1alpha1.PhaseError,
		vaultv1alpha1.PhaseDeleting,
	}

	for _, phase := range phases {
		t.Run(string(phase), func(t *testing.T) {
			role := &vaultv1alpha1.VaultRole{}
			adapter := NewVaultRoleAdapter(role)

			adapter.SetPhase(phase)

			if adapter.GetPhase() != phase {
				t.Errorf("GetPhase() = %q, want %q", adapter.GetPhase(), phase)
			}
		})
	}
}

func TestVaultClusterRoleAdapter_AllPhases(t *testing.T) {
	phases := []vaultv1alpha1.Phase{
		vaultv1alpha1.PhasePending,
		vaultv1alpha1.PhaseSyncing,
		vaultv1alpha1.PhaseActive,
		vaultv1alpha1.PhaseConflict,
		vaultv1alpha1.PhaseError,
		vaultv1alpha1.PhaseDeleting,
	}

	for _, phase := range phases {
		t.Run(string(phase), func(t *testing.T) {
			role := &vaultv1alpha1.VaultClusterRole{}
			adapter := NewVaultClusterRoleAdapter(role)

			adapter.SetPhase(phase)

			if adapter.GetPhase() != phase {
				t.Errorf("GetPhase() = %q, want %q", adapter.GetPhase(), phase)
			}
		})
	}
}
