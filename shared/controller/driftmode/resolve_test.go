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

package driftmode

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

func TestResolve(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	tests := []struct {
		name              string
		resourceDriftMode vaultv1alpha1.DriftMode
		connection        *vaultv1alpha1.VaultConnection
		connectionRef     string
		want              vaultv1alpha1.DriftMode
	}{
		{
			name:              "resource-level override takes priority",
			resourceDriftMode: vaultv1alpha1.DriftModeCorrect,
			connection: &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "test-conn"},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: "https://vault:8200",
					Auth:    vaultv1alpha1.AuthConfig{},
					Defaults: &vaultv1alpha1.ConnectionDefaults{
						DriftMode: vaultv1alpha1.DriftModeIgnore,
					},
				},
			},
			connectionRef: "test-conn",
			want:          vaultv1alpha1.DriftModeCorrect,
		},
		{
			name:              "connection default when resource has no override",
			resourceDriftMode: "",
			connection: &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "test-conn"},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: "https://vault:8200",
					Auth:    vaultv1alpha1.AuthConfig{},
					Defaults: &vaultv1alpha1.ConnectionDefaults{
						DriftMode: vaultv1alpha1.DriftModeCorrect,
					},
				},
			},
			connectionRef: "test-conn",
			want:          vaultv1alpha1.DriftModeCorrect,
		},
		{
			name:              "global default when no overrides",
			resourceDriftMode: "",
			connection: &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "test-conn"},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: "https://vault:8200",
					Auth:    vaultv1alpha1.AuthConfig{},
					// No Defaults set
				},
			},
			connectionRef: "test-conn",
			want:          vaultv1alpha1.DefaultDriftMode,
		},
		{
			name:              "global default when connection not found",
			resourceDriftMode: "",
			connection:        nil, // Connection doesn't exist
			connectionRef:     "missing-conn",
			want:              vaultv1alpha1.DefaultDriftMode,
		},
		{
			name:              "global default when connectionRef is empty",
			resourceDriftMode: "",
			connection:        nil,
			connectionRef:     "",
			want:              vaultv1alpha1.DefaultDriftMode,
		},
		{
			name:              "global default when defaults struct exists but driftMode empty",
			resourceDriftMode: "",
			connection: &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "test-conn"},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: "https://vault:8200",
					Auth:    vaultv1alpha1.AuthConfig{},
					Defaults: &vaultv1alpha1.ConnectionDefaults{
						// DriftMode not set, empty string
						SecretEnginePath: "secret",
					},
				},
			},
			connectionRef: "test-conn",
			want:          vaultv1alpha1.DefaultDriftMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build fake client with connection if provided
			var c client.Client
			if tt.connection != nil {
				c = fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(tt.connection).
					Build()
			} else {
				c = fake.NewClientBuilder().
					WithScheme(scheme).
					Build()
			}

			got := Resolve(context.Background(), c, tt.resourceDriftMode, tt.connectionRef)
			if got != tt.want {
				t.Errorf("Resolve() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveWithConnection(t *testing.T) {
	tests := []struct {
		name              string
		resourceDriftMode vaultv1alpha1.DriftMode
		connection        *vaultv1alpha1.VaultConnection
		want              vaultv1alpha1.DriftMode
	}{
		{
			name:              "resource-level override takes priority",
			resourceDriftMode: vaultv1alpha1.DriftModeIgnore,
			connection: &vaultv1alpha1.VaultConnection{
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Defaults: &vaultv1alpha1.ConnectionDefaults{
						DriftMode: vaultv1alpha1.DriftModeCorrect,
					},
				},
			},
			want: vaultv1alpha1.DriftModeIgnore,
		},
		{
			name:              "connection default when no resource override",
			resourceDriftMode: "",
			connection: &vaultv1alpha1.VaultConnection{
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Defaults: &vaultv1alpha1.ConnectionDefaults{
						DriftMode: vaultv1alpha1.DriftModeCorrect,
					},
				},
			},
			want: vaultv1alpha1.DriftModeCorrect,
		},
		{
			name:              "global default when connection is nil",
			resourceDriftMode: "",
			connection:        nil,
			want:              vaultv1alpha1.DefaultDriftMode,
		},
		{
			name:              "global default when defaults is nil",
			resourceDriftMode: "",
			connection: &vaultv1alpha1.VaultConnection{
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Defaults: nil,
				},
			},
			want: vaultv1alpha1.DefaultDriftMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveWithConnection(tt.resourceDriftMode, tt.connection)
			if got != tt.want {
				t.Errorf("ResolveWithConnection() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsIgnore(t *testing.T) {
	tests := []struct {
		mode vaultv1alpha1.DriftMode
		want bool
	}{
		{vaultv1alpha1.DriftModeIgnore, true},
		{vaultv1alpha1.DriftModeDetect, false},
		{vaultv1alpha1.DriftModeCorrect, false},
		{"", false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := IsIgnore(tt.mode); got != tt.want {
				t.Errorf("IsIgnore(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestIsDetect(t *testing.T) {
	tests := []struct {
		mode vaultv1alpha1.DriftMode
		want bool
	}{
		{vaultv1alpha1.DriftModeIgnore, false},
		{vaultv1alpha1.DriftModeDetect, true},
		{vaultv1alpha1.DriftModeCorrect, false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := IsDetect(tt.mode); got != tt.want {
				t.Errorf("IsDetect(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestIsCorrect(t *testing.T) {
	tests := []struct {
		mode vaultv1alpha1.DriftMode
		want bool
	}{
		{vaultv1alpha1.DriftModeIgnore, false},
		{vaultv1alpha1.DriftModeDetect, false},
		{vaultv1alpha1.DriftModeCorrect, true},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := IsCorrect(tt.mode); got != tt.want {
				t.Errorf("IsCorrect(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestShouldDetect(t *testing.T) {
	tests := []struct {
		mode vaultv1alpha1.DriftMode
		want bool
	}{
		{vaultv1alpha1.DriftModeIgnore, false},
		{vaultv1alpha1.DriftModeDetect, true},
		{vaultv1alpha1.DriftModeCorrect, true}, // correct implies detect
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := ShouldDetect(tt.mode); got != tt.want {
				t.Errorf("ShouldDetect(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestShouldCorrect(t *testing.T) {
	tests := []struct {
		mode vaultv1alpha1.DriftMode
		want bool
	}{
		{vaultv1alpha1.DriftModeIgnore, false},
		{vaultv1alpha1.DriftModeDetect, false},
		{vaultv1alpha1.DriftModeCorrect, true},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := ShouldCorrect(tt.mode); got != tt.want {
				t.Errorf("ShouldCorrect(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}
