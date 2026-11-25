//go:build integration

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
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
)

// NewRoleOpsForTest constructs a RoleOps with the given adapter and role data,
// bypassing the normal PrepareContent flow. Only available in integration test
// builds (see build tag above). External callers use this to test WriteToVault
// and ReadbackVerify behavior against a real Vault container without having
// to stand up the full handler/reconciler pipeline.
//
// This helper is intentionally kept out of production builds — the build tag
// ensures it is only compiled when `go test -tags integration` is invoked.
//
// WriteToVault persists status.pendingVaultRoleName before writing (#18
// review finding 1), so the ops carry a fake K8s client holding the role.
func NewRoleOpsForTest(adapter domain.RoleAdapter, authPath string, roleData map[string]interface{}) *RoleOps {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	k8s := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(adapter.GetObject()).WithStatusSubresource(adapter.GetObject()).Build()
	return &RoleOps{
		adapter:  adapter,
		handler:  &Handler{client: k8s},
		authPath: authPath,
		roleData: roleData,
	}
}
