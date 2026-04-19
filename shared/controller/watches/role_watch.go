/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package watches

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// PoliciesReferencedByRole returns a MapFunc that, given a VaultRole or
// VaultClusterRole event, enqueues every VaultPolicy / VaultClusterPolicy
// the role's spec references. Used by the policy reconcilers to keep
// `Status.UsedByRoles` (IMPROVEMENTS Missing Features §B) in sync —
// when a role is created, deleted, or has its spec.policies list
// changed, every policy that gained or lost the back-reference needs
// to recompute its UsedByRoles list.
//
// The returned MapFunc handles both VaultRole and VaultClusterRole.
// The discriminator is `obj`'s concrete type at runtime; anything else
// returns nil (the watch only fires on the registered kinds, so this
// is defensive only).
//
// `kindFilter` selects which target kind to enqueue:
//   - "VaultPolicy" — namespaced policies the role references
//   - "VaultClusterPolicy" — cluster policies the role references
//
// Both reconcilers use this MapFunc with their respective filter.
func PoliciesReferencedByRole(kindFilter string) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		logger := log.FromContext(ctx).WithValues("watchTarget", kindFilter)

		var refs []vaultv1alpha1.PolicyReference
		var defaultNamespace string
		switch r := obj.(type) {
		case *vaultv1alpha1.VaultRole:
			refs = r.Spec.Policies
			defaultNamespace = r.Namespace
		case *vaultv1alpha1.VaultClusterRole:
			refs = r.Spec.Policies
			// Cluster role policy refs MUST carry an explicit namespace —
			// no default fallback. The webhook enforces this.
		default:
			return nil
		}

		seen := make(map[types.NamespacedName]struct{}, len(refs))
		var requests []reconcile.Request
		for _, ref := range refs {
			if ref.Kind != kindFilter {
				continue
			}
			ns := ref.Namespace
			if ns == "" && kindFilter == "VaultPolicy" {
				ns = defaultNamespace
			}
			key := types.NamespacedName{Name: ref.Name, Namespace: ns}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			requests = append(requests, reconcile.Request{NamespacedName: key})
		}

		if len(requests) > 0 {
			logger.V(1).Info("enqueuing referenced policies",
				"count", len(requests),
				"sourceKind", obj.GetObjectKind().GroupVersionKind().Kind,
				"sourceName", obj.GetName(),
				"sourceNamespace", obj.GetNamespace(),
			)
		}
		return requests
	}
}
