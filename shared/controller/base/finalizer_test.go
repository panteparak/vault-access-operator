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

package base

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFinalizerManager_HasFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	fm := NewFinalizerManager(client, "test.finalizer")

	tests := []struct {
		name       string
		finalizers []string
		want       bool
	}{
		{
			name:       "no finalizers",
			finalizers: nil,
			want:       false,
		},
		{
			name:       "has other finalizer",
			finalizers: []string{"other.finalizer"},
			want:       false,
		},
		{
			name:       "has managed finalizer",
			finalizers: []string{"test.finalizer"},
			want:       true,
		},
		{
			name:       "has managed finalizer among others",
			finalizers: []string{"other.finalizer", "test.finalizer", "another.finalizer"},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test",
					Namespace:  "default",
					Finalizers: tt.finalizers,
				},
			}

			if got := fm.HasFinalizer(cm); got != tt.want {
				t.Errorf("HasFinalizer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFinalizerManager_Ensure(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	t.Run("adds finalizer when not present", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cm).
			Build()

		fm := NewFinalizerManager(client, "test.finalizer")

		if err := fm.Ensure(context.Background(), cm); err != nil {
			t.Fatalf("Ensure() error = %v", err)
		}

		if !fm.HasFinalizer(cm) {
			t.Error("expected finalizer to be added")
		}
	})

	t.Run("no-op when finalizer already present", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test",
				Namespace:  "default",
				Finalizers: []string{"test.finalizer"},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cm).
			Build()

		fm := NewFinalizerManager(client, "test.finalizer")

		if err := fm.Ensure(context.Background(), cm); err != nil {
			t.Fatalf("Ensure() error = %v", err)
		}

		// Should still have exactly one finalizer
		if len(cm.GetFinalizers()) != 1 {
			t.Errorf("expected 1 finalizer, got %d", len(cm.GetFinalizers()))
		}
	})
}

func TestFinalizerManager_Remove(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	t.Run("removes finalizer when present", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test",
				Namespace:  "default",
				Finalizers: []string{"test.finalizer"},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cm).
			Build()

		fm := NewFinalizerManager(client, "test.finalizer")

		if err := fm.Remove(context.Background(), cm); err != nil {
			t.Fatalf("Remove() error = %v", err)
		}

		if fm.HasFinalizer(cm) {
			t.Error("expected finalizer to be removed")
		}
	})

	t.Run("no-op when finalizer not present", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cm).
			Build()

		fm := NewFinalizerManager(client, "test.finalizer")

		if err := fm.Remove(context.Background(), cm); err != nil {
			t.Fatalf("Remove() error = %v", err)
		}

		if len(cm.GetFinalizers()) != 0 {
			t.Errorf("expected 0 finalizers, got %d", len(cm.GetFinalizers()))
		}
	})

	t.Run("preserves other finalizers", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test",
				Namespace:  "default",
				Finalizers: []string{"other.finalizer", "test.finalizer", "another.finalizer"},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cm).
			Build()

		fm := NewFinalizerManager(client, "test.finalizer")

		if err := fm.Remove(context.Background(), cm); err != nil {
			t.Fatalf("Remove() error = %v", err)
		}

		if fm.HasFinalizer(cm) {
			t.Error("expected managed finalizer to be removed")
		}

		if len(cm.GetFinalizers()) != 2 {
			t.Errorf("expected 2 finalizers remaining, got %d", len(cm.GetFinalizers()))
		}
	})
}

func TestFinalizerManager_FinalizerName(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	fm := NewFinalizerManager(client, "my.custom.finalizer")

	if got := fm.FinalizerName(); got != "my.custom.finalizer" {
		t.Errorf("FinalizerName() = %v, want %v", got, "my.custom.finalizer")
	}
}
