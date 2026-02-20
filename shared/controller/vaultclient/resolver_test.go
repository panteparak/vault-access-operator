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

package vaultclient

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(s)
	return s
}

func newActiveConnection(name, address string) *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: address,
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseActive,
			Healthy: true,
			Conditions: []vaultv1alpha1.Condition{
				{
					Type:               vaultv1alpha1.ConditionTypeReady,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1,
				},
			},
		},
	}
}

func TestResolve_Success(t *testing.T) {
	conn := newActiveConnection("vault-conn", "https://vault:8200")
	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultConnection{}).
		WithObjects(conn).
		Build()

	cache := vault.NewClientCache()
	vaultClient, err := vault.NewClient(vault.ClientConfig{Address: "https://vault:8200"})
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	cache.Set("vault-conn", vaultClient)

	result, err := Resolve(context.Background(), k8sClient, cache, "vault-conn", "default/test-policy")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil client")
	}
	if result.ConnectionName() != "vault-conn" {
		t.Errorf("expected connection name 'vault-conn', got %q", result.ConnectionName())
	}
}

func TestResolve_ConnectionNotFound(t *testing.T) {
	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	cache := vault.NewClientCache()

	_, err := Resolve(context.Background(), k8sClient, cache, "missing-conn", "default/test-policy")
	if err == nil {
		t.Fatal("expected error for missing connection")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T: %v", err, err)
	}
}

func TestResolve_ConnectionNotActive(t *testing.T) {
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pending-conn",
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase: vaultv1alpha1.PhasePending,
		},
	}
	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultConnection{}).
		WithObjects(conn).
		Build()

	cache := vault.NewClientCache()

	_, err := Resolve(context.Background(), k8sClient, cache, "pending-conn", "default/test-policy")
	if err == nil {
		t.Fatal("expected error for non-active connection")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T: %v", err, err)
	}

	var depErr *infraerrors.DependencyError
	if !errors.As(err, &depErr) {
		t.Fatal("expected error to be DependencyError")
	}
	if depErr.DependencyName != "pending-conn" {
		t.Errorf("expected dependency name 'pending-conn', got %q", depErr.DependencyName)
	}
}

func TestResolve_ClientNotInCache(t *testing.T) {
	conn := newActiveConnection("vault-conn", "https://vault:8200")
	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultConnection{}).
		WithObjects(conn).
		Build()

	cache := vault.NewClientCache() // empty cache

	_, err := Resolve(context.Background(), k8sClient, cache, "vault-conn", "default/test-policy")
	if err == nil {
		t.Fatal("expected error for client not in cache")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T: %v", err, err)
	}
}

func TestResolve_ConnectionInErrorPhase(t *testing.T) {
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name: "error-conn",
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase: vaultv1alpha1.PhaseError,
		},
	}
	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultConnection{}).
		WithObjects(conn).
		Build()

	cache := vault.NewClientCache()

	_, err := Resolve(context.Background(), k8sClient, cache, "error-conn", "ns/my-role")
	if err == nil {
		t.Fatal("expected error for connection in Error phase")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T: %v", err, err)
	}
}

func TestResolve_ResourceIDInErrorContext(t *testing.T) {
	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()
	cache := vault.NewClientCache()

	_, err := Resolve(context.Background(), k8sClient, cache, "missing", "production/critical-policy")
	if err == nil {
		t.Fatal("expected error")
	}

	var depErr *infraerrors.DependencyError
	if !errors.As(err, &depErr) {
		t.Fatal("expected DependencyError")
	}
	if depErr.Resource != "production/critical-policy" {
		t.Errorf("expected resource ID 'production/critical-policy' in error, got %q", depErr.Resource)
	}
}

func TestResolve_StaleObservedGeneration(t *testing.T) {
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "stale-conn",
			Generation: 2,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault:8200",
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseActive,
			Healthy: true,
			Conditions: []vaultv1alpha1.Condition{
				{
					Type:               vaultv1alpha1.ConditionTypeReady,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1, // Stale: generation is 2
				},
			},
		},
	}
	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultConnection{}).
		WithObjects(conn).
		Build()

	cache := vault.NewClientCache()

	_, err := Resolve(context.Background(), k8sClient, cache, "stale-conn", "ns/my-policy")
	if err == nil {
		t.Fatal("expected error for stale observed generation")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T: %v", err, err)
	}

	var depErr *infraerrors.DependencyError
	if errors.As(err, &depErr) {
		if depErr.DependencyName != "stale-conn" {
			t.Errorf("expected dependency name 'stale-conn', got %q", depErr.DependencyName)
		}
		if depErr.Reason == "" {
			t.Error("expected non-empty reason")
		}
	}
}

func TestResolve_UnhealthyConnection(t *testing.T) {
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "unhealthy-conn",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault:8200",
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:            vaultv1alpha1.PhaseActive,
			Healthy:          false,
			HealthCheckError: "connection refused",
			Conditions: []vaultv1alpha1.Condition{
				{
					Type:               vaultv1alpha1.ConditionTypeReady,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1,
				},
			},
		},
	}
	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultConnection{}).
		WithObjects(conn).
		Build()

	cache := vault.NewClientCache()

	_, err := Resolve(context.Background(), k8sClient, cache, "unhealthy-conn", "ns/my-role")
	if err == nil {
		t.Fatal("expected error for unhealthy connection")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T: %v", err, err)
	}

	var depErr *infraerrors.DependencyError
	if errors.As(err, &depErr) {
		if depErr.Reason == "" || depErr.Reason == "not ready" {
			t.Errorf("expected health-related reason, got %q", depErr.Reason)
		}
	}
}

func TestResolve_HealthyWithCurrentGeneration(t *testing.T) {
	// All checks pass — should succeed
	conn := newActiveConnection("healthy-conn", "https://vault:8200")
	scheme := newTestScheme()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&vaultv1alpha1.VaultConnection{}).
		WithObjects(conn).
		Build()

	cache := vault.NewClientCache()
	vaultClient, err := vault.NewClient(vault.ClientConfig{Address: "https://vault:8200"})
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	cache.Set("healthy-conn", vaultClient)

	result, err := Resolve(context.Background(), k8sClient, cache, "healthy-conn", "ns/test-policy")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil client")
	}
}
