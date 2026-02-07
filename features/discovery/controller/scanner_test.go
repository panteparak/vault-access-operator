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
	"testing"
	"time"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

func TestMatchesPolicyPatterns(t *testing.T) {
	tests := []struct {
		name       string
		patterns   []string
		policyName string
		want       bool
	}{
		{
			name:       "no patterns matches all",
			patterns:   []string{},
			policyName: "any-policy",
			want:       true,
		},
		{
			name:       "exact match",
			patterns:   []string{"app-policy"},
			policyName: "app-policy",
			want:       true,
		},
		{
			name:       "wildcard prefix",
			patterns:   []string{"app-*"},
			policyName: "app-reader",
			want:       true,
		},
		{
			name:       "wildcard suffix",
			patterns:   []string{"*-policy"},
			policyName: "team-policy",
			want:       true,
		},
		{
			name:       "no match",
			patterns:   []string{"app-*"},
			policyName: "team-policy",
			want:       false,
		},
		{
			name:       "multiple patterns - first matches",
			patterns:   []string{"app-*", "team-*"},
			policyName: "app-reader",
			want:       true,
		},
		{
			name:       "multiple patterns - second matches",
			patterns:   []string{"app-*", "team-*"},
			policyName: "team-writer",
			want:       true,
		},
		{
			name:       "multiple patterns - none match",
			patterns:   []string{"app-*", "team-*"},
			policyName: "prod-policy",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scanner{
				config: &vaultv1alpha1.DiscoveryConfig{
					PolicyPatterns: tt.patterns,
				},
			}
			if got := s.matchesPolicyPatterns(tt.policyName); got != tt.want {
				t.Errorf("matchesPolicyPatterns() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesRolePatterns(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		roleName string
		want     bool
	}{
		{
			name:     "no patterns matches all",
			patterns: []string{},
			roleName: "any-role",
			want:     true,
		},
		{
			name:     "wildcard suffix",
			patterns: []string{"*-reader"},
			roleName: "app-reader",
			want:     true,
		},
		{
			name:     "no match",
			patterns: []string{"*-reader"},
			roleName: "app-writer",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scanner{
				config: &vaultv1alpha1.DiscoveryConfig{
					RolePatterns: tt.patterns,
				},
			}
			if got := s.matchesRolePatterns(tt.roleName); got != tt.want {
				t.Errorf("matchesRolePatterns() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldExcludeSystemPolicy(t *testing.T) {
	tests := []struct {
		name                  string
		excludeSystemPolicies *bool
		policyName            string
		want                  bool
	}{
		{
			name:                  "default excludes root",
			excludeSystemPolicies: nil,
			policyName:            "root",
			want:                  true,
		},
		{
			name:                  "default excludes default",
			excludeSystemPolicies: nil,
			policyName:            "default",
			want:                  true,
		},
		{
			name:                  "default does not exclude app policy",
			excludeSystemPolicies: nil,
			policyName:            "app-policy",
			want:                  false,
		},
		{
			name:                  "explicit true excludes system policies",
			excludeSystemPolicies: boolPtr(true),
			policyName:            "root",
			want:                  true,
		},
		{
			name:                  "explicit false includes system policies",
			excludeSystemPolicies: boolPtr(false),
			policyName:            "root",
			want:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scanner{
				config: &vaultv1alpha1.DiscoveryConfig{
					ExcludeSystemPolicies: tt.excludeSystemPolicies,
				},
			}
			if got := s.shouldExcludeSystemPolicy(tt.policyName); got != tt.want {
				t.Errorf("shouldExcludeSystemPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval string
		want     time.Duration
	}{
		{
			name:     "empty defaults to 1h",
			interval: "",
			want:     time.Hour,
		},
		{
			name:     "30 minutes",
			interval: "30m",
			want:     30 * time.Minute,
		},
		{
			name:     "2 hours",
			interval: "2h",
			want:     2 * time.Hour,
		},
		{
			name:     "invalid defaults to 1h",
			interval: "invalid",
			want:     time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseInterval(tt.interval); got != tt.want {
				t.Errorf("ParseInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSuggestCRName(t *testing.T) {
	tests := []struct {
		name      string
		vaultName string
		want      string
	}{
		{
			name:      "simple name",
			vaultName: "app-policy",
			want:      "app-policy",
		},
		{
			name:      "namespaced name",
			vaultName: "prod-app-reader",
			want:      "prod-app-reader",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := suggestCRName(tt.vaultName); got != tt.want {
				t.Errorf("suggestCRName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}
