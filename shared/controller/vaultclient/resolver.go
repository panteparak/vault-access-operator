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

// Package vaultclient provides a shared resolver for obtaining authenticated Vault
// clients via VaultConnection references and the client cache.
package vaultclient

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// Resolve validates that the named VaultConnection exists and is Active,
// then retrieves the corresponding client from the cache.
// resourceID is used for error context (e.g. "namespace/policyName").
func Resolve(
	ctx context.Context, k8sClient client.Client, cache *vault.ClientCache,
	connRef, resourceID string,
) (*vault.Client, error) {
	conn := &vaultv1alpha1.VaultConnection{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: connRef}, conn); err != nil {
		return nil, infraerrors.NewDependencyError(resourceID, "VaultConnection", connRef, "not found")
	}

	if conn.Status.Phase != vaultv1alpha1.PhaseActive {
		return nil, infraerrors.NewDependencyError(
			resourceID, "VaultConnection", connRef,
			fmt.Sprintf("not ready (phase: %s)", conn.Status.Phase),
		)
	}

	// ObservedGeneration gating — ensure connection controller has processed latest spec
	for _, cond := range conn.Status.Conditions {
		if cond.Type == vaultv1alpha1.ConditionTypeReady {
			if cond.ObservedGeneration < conn.Generation {
				return nil, infraerrors.NewDependencyError(
					resourceID, "VaultConnection", connRef,
					fmt.Sprintf("spec update pending (observed generation %d < %d)",
						cond.ObservedGeneration, conn.Generation),
				)
			}
			break
		}
	}

	// Health blocking — ensure Vault is reachable
	if !conn.Status.Healthy {
		return nil, infraerrors.NewDependencyError(
			resourceID, "VaultConnection", connRef,
			fmt.Sprintf("unhealthy: %s", conn.Status.HealthCheckError),
		)
	}

	vaultClient, err := cache.Get(connRef)
	if err != nil {
		return nil, infraerrors.NewDependencyError(resourceID, "VaultConnection", connRef, "client not in cache")
	}

	return vaultClient, nil
}
