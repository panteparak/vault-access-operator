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
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// TestPolicyReconciler_EmitsReconcileMetric pins IMPROVEMENTS §31: the
// `vault_access_operator_policy_reconcile_total` metric is registered in
// pkg/metrics/metrics.go but had ZERO emission sites in production code
// before this fix — every reconcile silently passed without bumping the
// counter. The fix wraps the BaseReconciler call to emit on completion.
//
// We use a NotFound request because it produces a deterministic success
// path without needing a Vault client or a real resource.
func TestPolicyReconciler_EmitsReconcileMetric_OnNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logr.Discard())
	r := NewPolicyReconciler(c, scheme, handler, logr.Discard(), recorder)

	const ns = "metric-test-ns"
	const result = "success"
	counter := metrics.PolicyReconcileTotal.WithLabelValues("VaultPolicy", ns, result)
	before := testutil.ToFloat64(counter)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile NotFound returned unexpected error: %v", err)
	}

	after := testutil.ToFloat64(counter)
	if after != before+1 {
		t.Errorf("policy_reconcile_total{kind=VaultPolicy, namespace=%s, result=%s} = %v, want %v",
			ns, result, after, before+1)
	}
}

// TestClusterPolicyReconciler_EmitsReconcileMetric mirrors the above but for
// the cluster-scoped variant. The cluster reconciler labels namespace with
// "" (cluster-scoped resources have no namespace).
func TestClusterPolicyReconciler_EmitsReconcileMetric_OnNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	cache := vault.NewClientCache()

	handler := NewHandler(c, cache, nil, logr.Discard())
	r := NewClusterPolicyReconciler(c, scheme, handler, logr.Discard(), recorder)

	counter := metrics.PolicyReconcileTotal.WithLabelValues("VaultClusterPolicy", "", "success")
	before := testutil.ToFloat64(counter)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing"},
	})
	if err != nil {
		t.Fatalf("Reconcile NotFound returned unexpected error: %v", err)
	}

	after := testutil.ToFloat64(counter)
	if after != before+1 {
		t.Errorf("policy_reconcile_total cluster variant = %v, want %v", after, before+1)
	}
}

// TestKindForMetric pins the adapter→label mapping used by the §31 metric
// helpers. Wrong mapping would mix cluster-scoped and namespaced counts into
// the same time series, breaking dashboards that rely on the label.
func TestKindForMetric(t *testing.T) {
	nsAdapter := domain.NewVaultPolicyAdapter(&vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
	})
	if got := kindForMetric(nsAdapter); got != "VaultPolicy" {
		t.Errorf("namespaced kindForMetric = %q, want VaultPolicy", got)
	}

	clusterAdapter := domain.NewVaultClusterPolicyAdapter(&vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cp"},
	})
	if got := kindForMetric(clusterAdapter); got != "VaultClusterPolicy" {
		t.Errorf("cluster kindForMetric = %q, want VaultClusterPolicy", got)
	}
}
