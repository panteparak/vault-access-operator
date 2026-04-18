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
func NewRoleOpsForTest(adapter domain.RoleAdapter, authPath string, roleData map[string]interface{}) *RoleOps {
	return &RoleOps{
		adapter:  adapter,
		authPath: authPath,
		roleData: roleData,
	}
}
