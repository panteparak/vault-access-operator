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

// Package driftmode provides utilities for resolving drift detection modes
// across the two-level configuration hierarchy: resource-level and connection-level.
package driftmode

import (
	"context"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// Resolve determines the effective drift mode for a resource by checking:
// 1. Resource-level driftMode (highest priority)
// 2. VaultConnection defaults
// 3. Global default (DriftModeDetect)
//
// This implements a cascading configuration pattern where more specific
// settings override more general ones.
func Resolve(
	ctx context.Context,
	c client.Client,
	resourceDriftMode vaultv1alpha1.DriftMode,
	connectionRef string,
) vaultv1alpha1.DriftMode {
	// 1. Resource-level override takes highest priority
	if resourceDriftMode != "" {
		return resourceDriftMode
	}

	// 2. Check VaultConnection defaults
	if connectionRef != "" && c != nil {
		var conn vaultv1alpha1.VaultConnection
		key := client.ObjectKey{Name: connectionRef}
		err := c.Get(ctx, key, &conn)
		switch {
		case err == nil:
			if conn.Spec.Defaults != nil && conn.Spec.Defaults.DriftMode != "" {
				return conn.Spec.Defaults.DriftMode
			}
		case apierrors.IsNotFound(err):
			// Connection genuinely missing — fall through to global default.
			// Caller will see the missing connection via the dependency
			// check elsewhere.
		default:
			// Transient API-server failure (auth, throttling, network).
			// Surfacing it at V(1) makes the cause findable when an
			// operator notices unexpected drift behavior. We still fall
			// through to the global default — the alternative (returning
			// an error) would force every caller to handle it, but in
			// practice the next reconcile will retry.
			logr.FromContextOrDiscard(ctx).V(1).Info(
				"failed to load VaultConnection for drift-mode resolution; falling back to global default",
				"connection", connectionRef, "error", err.Error(),
				"fallback", string(vaultv1alpha1.DefaultDriftMode),
			)
		}
	}

	// 3. Global default
	return vaultv1alpha1.DefaultDriftMode
}

// ResolveWithConnection is like Resolve but takes a pre-fetched VaultConnection,
// avoiding an additional API call when the connection is already available.
func ResolveWithConnection(
	resourceDriftMode vaultv1alpha1.DriftMode,
	conn *vaultv1alpha1.VaultConnection,
) vaultv1alpha1.DriftMode {
	// 1. Resource-level override takes highest priority
	if resourceDriftMode != "" {
		return resourceDriftMode
	}

	// 2. Check VaultConnection defaults
	if conn != nil && conn.Spec.Defaults != nil && conn.Spec.Defaults.DriftMode != "" {
		return conn.Spec.Defaults.DriftMode
	}

	// 3. Global default
	return vaultv1alpha1.DefaultDriftMode
}

// IsIgnore returns true if the drift mode is "ignore".
// Useful for quickly skipping drift detection logic.
func IsIgnore(mode vaultv1alpha1.DriftMode) bool {
	return mode == vaultv1alpha1.DriftModeIgnore
}

// IsDetect returns true if the drift mode is "detect".
// In this mode, drift is reported but NOT auto-corrected.
func IsDetect(mode vaultv1alpha1.DriftMode) bool {
	return mode == vaultv1alpha1.DriftModeDetect
}

// IsCorrect returns true if the drift mode is "correct".
// In this mode, drift is detected AND auto-corrected.
func IsCorrect(mode vaultv1alpha1.DriftMode) bool {
	return mode == vaultv1alpha1.DriftModeCorrect
}

// ShouldDetect returns true if drift detection should be performed.
// Returns true for both "detect" and "correct" modes.
func ShouldDetect(mode vaultv1alpha1.DriftMode) bool {
	return mode == vaultv1alpha1.DriftModeDetect || mode == vaultv1alpha1.DriftModeCorrect
}

// ShouldCorrect returns true if drift should be auto-corrected.
// Only returns true for "correct" mode.
func ShouldCorrect(mode vaultv1alpha1.DriftMode) bool {
	return mode == vaultv1alpha1.DriftModeCorrect
}
