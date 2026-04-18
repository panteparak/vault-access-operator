/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// TestRoleReconciler_EmitsReconcileMetric_OnNotFound pins IMPROVEMENTS §31 for
// the role side. Same rationale as the policy variant — see
// features/policy/controller/reconciler_metrics_test.go.
func TestRoleReconciler_EmitsReconcileMetric_OnNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logr.Discard())
	r := NewRoleReconciler(c, scheme, handler, logr.Discard(), recorder)

	const ns = "metric-test-ns"
	counter := metrics.RoleReconcileTotal.WithLabelValues("VaultRole", ns, "success")
	before := testutil.ToFloat64(counter)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile NotFound returned unexpected error: %v", err)
	}

	if got := testutil.ToFloat64(counter); got != before+1 {
		t.Errorf("role_reconcile_total{kind=VaultRole, namespace=%s} = %v, want %v",
			ns, got, before+1)
	}
}

func TestClusterRoleReconciler_EmitsReconcileMetric_OnNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logr.Discard())
	r := NewClusterRoleReconciler(c, scheme, handler, logr.Discard(), recorder)

	counter := metrics.RoleReconcileTotal.WithLabelValues("VaultClusterRole", "", "success")
	before := testutil.ToFloat64(counter)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing"},
	})
	if err != nil {
		t.Fatalf("Reconcile NotFound returned unexpected error: %v", err)
	}

	if got := testutil.ToFloat64(counter); got != before+1 {
		t.Errorf("role_reconcile_total cluster variant = %v, want %v", got, before+1)
	}
}

// TestRoleKindForMetric pins the adapter→label mapping used by the §31
// adoption metric. Wrong mapping mixes namespaced + cluster series.
func TestRoleKindForMetric(t *testing.T) {
	nsAdapter := domain.NewVaultRoleAdapter(&vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
	})
	if got := roleKindForMetric(nsAdapter); got != "VaultRole" {
		t.Errorf("namespaced roleKindForMetric = %q, want VaultRole", got)
	}

	clusterAdapter := domain.NewVaultClusterRoleAdapter(&vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "cr"},
	})
	if got := roleKindForMetric(clusterAdapter); got != "VaultClusterRole" {
		t.Errorf("cluster roleKindForMetric = %q, want VaultClusterRole", got)
	}
}
