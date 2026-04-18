/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// newClientBuilderWithConnectionRefIndex returns a fake client builder that
// has the `spec.connectionRef` field indexer registered for all four
// dependent CRD kinds. Tests that exercise Cleanup (which calls
// listDependents via client.MatchingFields) need this; tests that don't
// can continue using a plain fake.NewClientBuilder().
//
// Mirrors the production registration in reconciler.registerConnectionRefIndexers.
// Kept in sync with that function — if you add a dependent kind there, add
// it here too, or the fake client will silently return empty lists.
func newClientBuilderWithConnectionRefIndex(scheme *runtime.Scheme) *fake.ClientBuilder {
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&vaultv1alpha1.VaultPolicy{}, IndexFieldConnectionRef,
			func(o client.Object) []string {
				return []string{o.(*vaultv1alpha1.VaultPolicy).Spec.ConnectionRef}
			}).
		WithIndex(&vaultv1alpha1.VaultClusterPolicy{}, IndexFieldConnectionRef,
			func(o client.Object) []string {
				return []string{o.(*vaultv1alpha1.VaultClusterPolicy).Spec.ConnectionRef}
			}).
		WithIndex(&vaultv1alpha1.VaultRole{}, IndexFieldConnectionRef,
			func(o client.Object) []string {
				return []string{o.(*vaultv1alpha1.VaultRole).Spec.ConnectionRef}
			}).
		WithIndex(&vaultv1alpha1.VaultClusterRole{}, IndexFieldConnectionRef,
			func(o client.Object) []string {
				return []string{o.(*vaultv1alpha1.VaultClusterRole).Spec.ConnectionRef}
			})
}
