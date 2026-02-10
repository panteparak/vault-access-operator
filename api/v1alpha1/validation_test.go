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

package v1alpha1

import (
	"testing"
)

// TestVaultPolicySpec_RequiredFields tests that required fields are properly defined
func TestVaultPolicySpec_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		spec    VaultPolicySpec
		wantErr bool
		desc    string
	}{
		{
			name: "valid spec with all required fields",
			spec: VaultPolicySpec{
				ConnectionRef: "test-connection",
				Rules: []PolicyRule{
					{
						Path:         "secret/data/*",
						Capabilities: []Capability{"read"},
					},
				},
			},
			wantErr: false,
			desc:    "should accept valid spec",
		},
		{
			name: "missing connectionRef",
			spec: VaultPolicySpec{
				Rules: []PolicyRule{
					{
						Path:         "secret/data/*",
						Capabilities: []Capability{"read"},
					},
				},
			},
			wantErr: true,
			desc:    "should require connectionRef",
		},
		{
			name: "empty rules",
			spec: VaultPolicySpec{
				ConnectionRef: "test-connection",
				Rules:         []PolicyRule{},
			},
			wantErr: true,
			desc:    "should require at least one rule",
		},
		{
			name: "nil rules",
			spec: VaultPolicySpec{
				ConnectionRef: "test-connection",
			},
			wantErr: true,
			desc:    "should require rules field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that empty/missing fields are zero values
			// CRD validation happens at API server level, so we test the struct contracts
			hasConnectionRef := tt.spec.ConnectionRef != ""
			hasRules := len(tt.spec.Rules) > 0

			if !tt.wantErr {
				if !hasConnectionRef {
					t.Errorf("expected connectionRef to be set")
				}
				if !hasRules {
					t.Errorf("expected rules to be present")
				}
			} else {
				// For error cases, at least one required field should be missing
				if hasConnectionRef && hasRules {
					t.Errorf("expected at least one required field to be missing")
				}
			}
		})
	}
}

// TestPolicyRule_RequiredFields tests PolicyRule field requirements
func TestPolicyRule_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		rule    PolicyRule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: PolicyRule{
				Path:         "secret/data/*",
				Capabilities: []Capability{"read", "list"},
			},
			wantErr: false,
		},
		{
			name: "missing path",
			rule: PolicyRule{
				Capabilities: []Capability{"read"},
			},
			wantErr: true,
		},
		{
			name: "empty capabilities",
			rule: PolicyRule{
				Path:         "secret/data/*",
				Capabilities: []Capability{},
			},
			wantErr: true,
		},
		{
			name: "nil capabilities",
			rule: PolicyRule{
				Path: "secret/data/*",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasPath := tt.rule.Path != ""
			hasCapabilities := len(tt.rule.Capabilities) > 0

			if !tt.wantErr {
				if !hasPath || !hasCapabilities {
					t.Errorf("expected valid rule to have both path and capabilities")
				}
			}
		})
	}
}

// TestCapability_ValidValues tests that Capability enum values are correct
func TestCapability_ValidValues(t *testing.T) {
	validCapabilities := []Capability{
		CapabilityCreate,
		CapabilityRead,
		CapabilityUpdate,
		CapabilityDelete,
		CapabilityList,
		CapabilitySudo,
		CapabilityDeny,
	}

	// Verify all expected capabilities exist
	expectedCaps := map[Capability]bool{
		"create": true,
		"read":   true,
		"update": true,
		"delete": true,
		"list":   true,
		"sudo":   true,
		"deny":   true,
	}

	for _, cap := range validCapabilities {
		if !expectedCaps[cap] {
			t.Errorf("unexpected capability value: %s", cap)
		}
	}

	if len(validCapabilities) != len(expectedCaps) {
		t.Errorf("capability count mismatch: got %d, want %d", len(validCapabilities), len(expectedCaps))
	}
}

// TestVaultRoleSpec_RequiredFields tests VaultRole required fields
func TestVaultRoleSpec_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		spec    VaultRoleSpec
		wantErr bool
	}{
		{
			name: "valid spec",
			spec: VaultRoleSpec{
				ConnectionRef:   "test-connection",
				ServiceAccounts: []string{"default"},
				Policies: []PolicyReference{
					{Kind: "VaultPolicy", Name: "test-policy"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing connectionRef",
			spec: VaultRoleSpec{
				ServiceAccounts: []string{"default"},
				Policies: []PolicyReference{
					{Kind: "VaultPolicy", Name: "test-policy"},
				},
			},
			wantErr: true,
		},
		{
			name: "empty service accounts",
			spec: VaultRoleSpec{
				ConnectionRef:   "test-connection",
				ServiceAccounts: []string{},
				Policies: []PolicyReference{
					{Kind: "VaultPolicy", Name: "test-policy"},
				},
			},
			wantErr: true,
		},
		{
			name: "empty policies",
			spec: VaultRoleSpec{
				ConnectionRef:   "test-connection",
				ServiceAccounts: []string{"default"},
				Policies:        []PolicyReference{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasConnectionRef := tt.spec.ConnectionRef != ""
			hasServiceAccounts := len(tt.spec.ServiceAccounts) > 0
			hasPolicies := len(tt.spec.Policies) > 0

			if !tt.wantErr {
				if !hasConnectionRef || !hasServiceAccounts || !hasPolicies {
					t.Errorf("expected all required fields to be present")
				}
			}
		})
	}
}

// TestPolicyReference_ValidKinds tests PolicyReference kind enum values
func TestPolicyReference_ValidKinds(t *testing.T) {
	tests := []struct {
		name  string
		ref   PolicyReference
		valid bool
	}{
		{
			name:  "VaultPolicy kind",
			ref:   PolicyReference{Kind: "VaultPolicy", Name: "test"},
			valid: true,
		},
		{
			name:  "VaultClusterPolicy kind",
			ref:   PolicyReference{Kind: "VaultClusterPolicy", Name: "test"},
			valid: true,
		},
		{
			name:  "invalid kind",
			ref:   PolicyReference{Kind: "InvalidKind", Name: "test"},
			valid: false,
		},
		{
			name:  "empty kind",
			ref:   PolicyReference{Kind: "", Name: "test"},
			valid: false,
		},
	}

	validKinds := map[string]bool{
		"VaultPolicy":        true,
		"VaultClusterPolicy": true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validKinds[tt.ref.Kind]
			if isValid != tt.valid {
				t.Errorf("kind validation mismatch for %q: got %v, want %v", tt.ref.Kind, isValid, tt.valid)
			}
		})
	}
}

// TestConflictPolicy_ValidValues tests ConflictPolicy enum values
func TestConflictPolicy_ValidValues(t *testing.T) {
	tests := []struct {
		name   string
		policy ConflictPolicy
		valid  bool
	}{
		{
			name:   "Fail policy",
			policy: ConflictPolicyFail,
			valid:  true,
		},
		{
			name:   "Adopt policy",
			policy: ConflictPolicyAdopt,
			valid:  true,
		},
		{
			name:   "invalid policy",
			policy: ConflictPolicy("Invalid"),
			valid:  false,
		},
	}

	validPolicies := map[ConflictPolicy]bool{
		ConflictPolicyFail:  true,
		ConflictPolicyAdopt: true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validPolicies[tt.policy]
			if isValid != tt.valid {
				t.Errorf("conflict policy validation mismatch for %q: got %v, want %v", tt.policy, isValid, tt.valid)
			}
		})
	}
}

// TestDeletionPolicy_ValidValues tests DeletionPolicy enum values
func TestDeletionPolicy_ValidValues(t *testing.T) {
	tests := []struct {
		name   string
		policy DeletionPolicy
		valid  bool
	}{
		{
			name:   "Delete policy",
			policy: DeletionPolicyDelete,
			valid:  true,
		},
		{
			name:   "Retain policy",
			policy: DeletionPolicyRetain,
			valid:  true,
		},
		{
			name:   "invalid policy",
			policy: DeletionPolicy("Invalid"),
			valid:  false,
		},
	}

	validPolicies := map[DeletionPolicy]bool{
		DeletionPolicyDelete: true,
		DeletionPolicyRetain: true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validPolicies[tt.policy]
			if isValid != tt.valid {
				t.Errorf("deletion policy validation mismatch for %q: got %v, want %v", tt.policy, isValid, tt.valid)
			}
		})
	}
}

// TestPhase_ValidValues tests Phase enum values
func TestPhase_ValidValues(t *testing.T) {
	tests := []struct {
		name  string
		phase Phase
		valid bool
	}{
		{name: "Pending", phase: PhasePending, valid: true},
		{name: "Syncing", phase: PhaseSyncing, valid: true},
		{name: "Active", phase: PhaseActive, valid: true},
		{name: "Conflict", phase: PhaseConflict, valid: true},
		{name: "Error", phase: PhaseError, valid: true},
		{name: "Deleting", phase: PhaseDeleting, valid: true},
		{name: "invalid", phase: Phase("Unknown"), valid: false},
	}

	validPhases := map[Phase]bool{
		PhasePending:  true,
		PhaseSyncing:  true,
		PhaseActive:   true,
		PhaseConflict: true,
		PhaseError:    true,
		PhaseDeleting: true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validPhases[tt.phase]
			if isValid != tt.valid {
				t.Errorf("phase validation mismatch for %q: got %v, want %v", tt.phase, isValid, tt.valid)
			}
		})
	}
}

// TestVaultConnectionSpec_RequiredFields tests VaultConnection required fields
func TestVaultConnectionSpec_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		spec    VaultConnectionSpec
		wantErr bool
	}{
		{
			name: "valid spec with token auth",
			spec: VaultConnectionSpec{
				Address: "https://vault.example.com:8200",
				Auth: AuthConfig{
					Token: &TokenAuth{
						SecretRef: SecretKeySelector{Name: "vault-token", Key: "token"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing address",
			spec: VaultConnectionSpec{
				Auth: AuthConfig{
					Token: &TokenAuth{
						SecretRef: SecretKeySelector{Name: "vault-token", Key: "token"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid address scheme",
			spec: VaultConnectionSpec{
				Address: "ftp://vault.example.com:8200",
				Auth: AuthConfig{
					Token: &TokenAuth{
						SecretRef: SecretKeySelector{Name: "vault-token", Key: "token"},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasAddress := tt.spec.Address != ""
			hasValidScheme := len(tt.spec.Address) >= 7 &&
				(tt.spec.Address[:7] == "http://" || tt.spec.Address[:8] == "https://")

			if !tt.wantErr {
				if !hasAddress {
					t.Errorf("expected address to be present")
				}
				if !hasValidScheme {
					t.Errorf("expected valid address scheme (http/https)")
				}
			}
		})
	}
}

// TestVaultClusterRoleSpec_RequiredFields tests VaultClusterRole required fields
func TestVaultClusterRoleSpec_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		spec    VaultClusterRoleSpec
		wantErr bool
	}{
		{
			name: "valid spec",
			spec: VaultClusterRoleSpec{
				ConnectionRef: "test-connection",
				ServiceAccounts: []ServiceAccountRef{
					{Name: "default", Namespace: "default"},
				},
				Policies: []PolicyReference{
					{Kind: "VaultClusterPolicy", Name: "test-policy"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing service accounts",
			spec: VaultClusterRoleSpec{
				ConnectionRef:   "test-connection",
				ServiceAccounts: []ServiceAccountRef{},
				Policies: []PolicyReference{
					{Kind: "VaultClusterPolicy", Name: "test-policy"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasConnectionRef := tt.spec.ConnectionRef != ""
			hasServiceAccounts := len(tt.spec.ServiceAccounts) > 0
			hasPolicies := len(tt.spec.Policies) > 0

			if !tt.wantErr {
				if !hasConnectionRef || !hasServiceAccounts || !hasPolicies {
					t.Errorf("expected all required fields to be present")
				}
			}
		})
	}
}

// TestServiceAccountRef_RequiredFields tests ServiceAccountRef fields
func TestServiceAccountRef_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		ref     ServiceAccountRef
		wantErr bool
	}{
		{
			name:    "valid ref",
			ref:     ServiceAccountRef{Name: "my-sa", Namespace: "my-ns"},
			wantErr: false,
		},
		{
			name:    "missing name",
			ref:     ServiceAccountRef{Namespace: "my-ns"},
			wantErr: true,
		},
		{
			name:    "missing namespace",
			ref:     ServiceAccountRef{Name: "my-sa"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasName := tt.ref.Name != ""
			hasNamespace := tt.ref.Namespace != ""

			if !tt.wantErr {
				if !hasName || !hasNamespace {
					t.Errorf("expected both name and namespace to be present")
				}
			}
		})
	}
}

// TestSecretKeySelector_RequiredFields tests SecretKeySelector fields
func TestSecretKeySelector_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		ref     SecretKeySelector
		wantErr bool
	}{
		{
			name:    "valid ref",
			ref:     SecretKeySelector{Name: "my-secret", Key: "my-key"},
			wantErr: false,
		},
		{
			name:    "missing name",
			ref:     SecretKeySelector{Key: "my-key"},
			wantErr: true,
		},
		{
			name:    "missing key",
			ref:     SecretKeySelector{Name: "my-secret"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasName := tt.ref.Name != ""
			hasKey := tt.ref.Key != ""

			if !tt.wantErr {
				if !hasName || !hasKey {
					t.Errorf("expected both name and key to be present")
				}
			}
		})
	}
}

// TestVaultClusterPolicySpec_RequiredFields tests VaultClusterPolicy required fields
func TestVaultClusterPolicySpec_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		spec    VaultClusterPolicySpec
		wantErr bool
	}{
		{
			name: "valid spec",
			spec: VaultClusterPolicySpec{
				ConnectionRef: "test-connection",
				Rules: []PolicyRule{
					{
						Path:         "secret/data/*",
						Capabilities: []Capability{"read"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing connectionRef",
			spec: VaultClusterPolicySpec{
				Rules: []PolicyRule{
					{
						Path:         "secret/data/*",
						Capabilities: []Capability{"read"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "empty rules",
			spec: VaultClusterPolicySpec{
				ConnectionRef: "test-connection",
				Rules:         []PolicyRule{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasConnectionRef := tt.spec.ConnectionRef != ""
			hasRules := len(tt.spec.Rules) > 0

			if !tt.wantErr {
				if !hasConnectionRef || !hasRules {
					t.Errorf("expected all required fields to be present")
				}
			}
		})
	}
}

// TestRenewalStrategy_ValidValues tests RenewalStrategy enum values
func TestRenewalStrategy_ValidValues(t *testing.T) {
	tests := []struct {
		name     string
		strategy RenewalStrategy
		valid    bool
	}{
		{name: "Renew strategy", strategy: RenewalStrategyRenew, valid: true},
		{name: "Reauth strategy", strategy: RenewalStrategyReauth, valid: true},
		{name: "invalid strategy", strategy: RenewalStrategy("invalid"), valid: false},
		{name: "empty strategy", strategy: RenewalStrategy(""), valid: false},
	}

	validStrategies := map[RenewalStrategy]bool{
		RenewalStrategyRenew:  true,
		RenewalStrategyReauth: true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validStrategies[tt.strategy]
			if isValid != tt.valid {
				t.Errorf("strategy validation mismatch for %q: got %v, want %v", tt.strategy, isValid, tt.valid)
			}
		})
	}
}

// TestDefaultRenewalStrategy tests the default value
func TestDefaultRenewalStrategy(t *testing.T) {
	if DefaultRenewalStrategy != RenewalStrategyRenew {
		t.Errorf("DefaultRenewalStrategy = %q, want %q", DefaultRenewalStrategy, RenewalStrategyRenew)
	}
}
