/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package conflict

import (
	"testing"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// fakeAdopt implements the AdoptCandidate interface with configurable
// annotations and conflict policy for table-driven testing.
type fakeAdopt struct {
	annotations    map[string]string
	conflictPolicy vaultv1alpha1.ConflictPolicy
}

func (f *fakeAdopt) GetAnnotations() map[string]string               { return f.annotations }
func (f *fakeAdopt) GetConflictPolicy() vaultv1alpha1.ConflictPolicy { return f.conflictPolicy }

// TestShouldAdopt pins the annotation-wins-over-policy precedence rule and
// every other decision path. Before IMPROVEMENTS §13 this logic was
// duplicated byte-for-byte between policy and role handlers; extracting it
// prevents the two sides from drifting apart when a third adoption trigger
// is added later.
func TestShouldAdopt(t *testing.T) {
	cases := []struct {
		name     string
		adapter  *fakeAdopt
		expected bool
	}{
		{
			name:     "nil annotations + no conflict policy",
			adapter:  &fakeAdopt{},
			expected: false,
		},
		{
			name: "annotation true wins even when policy is Fail",
			adapter: &fakeAdopt{
				annotations:    map[string]string{vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue},
				conflictPolicy: vaultv1alpha1.ConflictPolicyFail,
			},
			expected: true,
		},
		{
			name: "annotation false + ConflictPolicy=Adopt → adopt",
			adapter: &fakeAdopt{
				annotations:    map[string]string{vaultv1alpha1.AnnotationAdopt: "false"},
				conflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
			},
			expected: true,
		},
		{
			name: "annotation empty string + ConflictPolicy=Adopt → adopt (not a literal 'true')",
			adapter: &fakeAdopt{
				annotations:    map[string]string{vaultv1alpha1.AnnotationAdopt: ""},
				conflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
			},
			expected: true,
		},
		{
			name: "ConflictPolicy=Fail + no annotation → no adopt",
			adapter: &fakeAdopt{
				conflictPolicy: vaultv1alpha1.ConflictPolicyFail,
			},
			expected: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldAdopt(tc.adapter); got != tc.expected {
				t.Errorf("ShouldAdopt() = %v, want %v", got, tc.expected)
			}
		})
	}
}
