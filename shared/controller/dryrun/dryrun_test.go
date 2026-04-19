/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package dryrun

import (
	"testing"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

type fakeAnnotated struct{ anns map[string]string }

func (f *fakeAnnotated) GetAnnotations() map[string]string { return f.anns }

// TestIsActive covers the strict-equality semantics: only "true"
// suppresses; everything else (including "false", "0", empty, missing)
// is dry-run OFF. The test also pins the nil-safety contract.
func TestIsActive(t *testing.T) {
	cases := []struct {
		name string
		anns map[string]string
		want bool
	}{
		{"true → on", map[string]string{vaultv1alpha1.AnnotationDryRun: "true"}, true},
		{"false → off", map[string]string{vaultv1alpha1.AnnotationDryRun: "false"}, false},
		{"empty value → off", map[string]string{vaultv1alpha1.AnnotationDryRun: ""}, false},
		{"absent → off", nil, false},
		{"unrelated annotation only → off", map[string]string{"other": "true"}, false},
		// Strict equality — case mismatch should not enable.
		{"True (uppercase) → off", map[string]string{vaultv1alpha1.AnnotationDryRun: "True"}, false},
		{"1 → off (only literal 'true' enables)", map[string]string{vaultv1alpha1.AnnotationDryRun: "1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsActive(&fakeAnnotated{anns: tc.anns})
			if got != tc.want {
				t.Errorf("IsActive(%+v) = %v, want %v", tc.anns, got, tc.want)
			}
		})
	}
}

// TestIsActive_NilAdapter pins the nil-safety contract — caller never
// has to nil-check before calling IsActive.
func TestIsActive_NilAdapter(t *testing.T) {
	if IsActive(nil) {
		t.Error("IsActive(nil) must return false (safe default)")
	}
}
