/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package dryrun centralises the dry-run annotation check that
// PolicyOps, RoleOps, and (future) other ops use to skip Vault writes
// when a CR carries `vault.platform.io/dry-run=true`.
//
// Originally lived as `isDryRun`/`isRoleDryRun` per-package — extracted
// here once the third call site appeared, mirroring the
// shared/controller/conflict.ShouldAdopt extraction (IMPROVEMENTS §13).
//
// IMPROVEMENTS Missing Features §I.
package dryrun

import (
	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// Annotated is the minimal interface any adapter must satisfy to be
// dry-run-checkable. PolicyAdapter and RoleAdapter both satisfy it via
// their embedded client.Object.
type Annotated interface {
	GetAnnotations() map[string]string
}

// IsActive reports whether the resource carries the dry-run annotation
// set to AnnotationValueTrue. Any other value (including "false", "0",
// or empty) is treated as dry-run OFF — matching the strict-equality
// semantics that PolicyOps and RoleOps tests pin.
//
// A nil adapter or one returning a nil annotation map is OFF (safe
// default — better to write than to silently no-op when the operator
// can't tell intent).
func IsActive(a Annotated) bool {
	if a == nil {
		return false
	}
	return a.GetAnnotations()[vaultv1alpha1.AnnotationDryRun] == vaultv1alpha1.AnnotationValueTrue
}
