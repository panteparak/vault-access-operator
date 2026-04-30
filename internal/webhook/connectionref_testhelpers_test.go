/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package webhook

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// testConnectionStub returns a minimal VaultConnection named "test-connection".
// Used by webhook tests that care about dependency-check warnings NOT including
// the §36 "missing connectionRef" warning. Pre-seed the fake client with this
// stub so validateWithContext finds a connection and skips the warning.
func testConnectionStub() runtime.Object {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "test-connection"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault.example.com:8200",
		},
	}
}
