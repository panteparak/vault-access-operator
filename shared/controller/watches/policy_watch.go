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

package watches

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// RoleRequestsForPolicy returns a MapFunc that enqueues VaultRole reconcile
// requests when a VaultPolicy is created or updated, IF the role has an
// unresolved PolicyBinding referencing that policy (IMPROVEMENTS §27).
//
// Without this watch, a role created before its referenced policy sits in
// `PoliciesResolved=False` state until the next scheduled reconcile (up to
// 30s later) notices the policy now exists. With the watch, the role
// reconciles within milliseconds of the policy's create event.
//
// The filter on `!binding.Resolved` keeps the fan-out tight: a policy
// create triggers reconciliation only for roles that are actually waiting
// on it, not every role in the cluster.
func RoleRequestsForPolicy(k8sClient client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		policyName := obj.GetName()
		policyNamespace := obj.GetNamespace()
		logger := log.FromContext(ctx).
			WithValues("policy", policyName, "policyNamespace", policyNamespace, "watchTarget", "VaultRole")

		var list vaultv1alpha1.VaultRoleList
		if err := k8sClient.List(ctx, &list); err != nil {
			logger.Error(err, "failed to list VaultRoles for policy watch")
			return nil
		}
		var requests []reconcile.Request
		for i := range list.Items {
			r := &list.Items[i]
			if rolePolicyBindingsReference(r.Status.PolicyBindings, policyName, policyNamespace) {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: r.Name, Namespace: r.Namespace},
				})
			}
		}
		if len(requests) > 0 {
			logger.V(1).Info("enqueuing dependent roles", "count", len(requests))
		}
		return requests
	}
}

// ClusterRoleRequestsForPolicy — same but targeting VaultClusterRole.
func ClusterRoleRequestsForPolicy(k8sClient client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		policyName := obj.GetName()
		policyNamespace := obj.GetNamespace()
		logger := log.FromContext(ctx).
			WithValues("policy", policyName, "policyNamespace", policyNamespace, "watchTarget", "VaultClusterRole")

		var list vaultv1alpha1.VaultClusterRoleList
		if err := k8sClient.List(ctx, &list); err != nil {
			logger.Error(err, "failed to list VaultClusterRoles for policy watch")
			return nil
		}
		var requests []reconcile.Request
		for i := range list.Items {
			r := &list.Items[i]
			if rolePolicyBindingsReference(r.Status.PolicyBindings, policyName, policyNamespace) {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: r.Name},
				})
			}
		}
		if len(requests) > 0 {
			logger.V(1).Info("enqueuing dependent cluster roles", "count", len(requests))
		}
		return requests
	}
}

// rolePolicyBindingsReference returns true if any unresolved PolicyBinding in
// the list references the (namespace/name) policy that just changed. Both
// k8sRef forms are matched:
//   - Namespaced VaultPolicy: "VaultPolicy/<namespace>/<name>"
//   - Cluster VaultClusterPolicy: "VaultClusterPolicy/<name>" (empty ns)
//
// We only enqueue for bindings where Resolved=false — the Policy created
// event is only relevant to roles still waiting on it; already-resolved
// bindings don't benefit from a requeue.
func rolePolicyBindingsReference(bindings []vaultv1alpha1.PolicyBinding, policyName, policyNamespace string) bool {
	nsK8sRef := "VaultPolicy/" + policyNamespace + "/" + policyName
	clusterK8sRef := "VaultClusterPolicy/" + policyName
	for i := range bindings {
		if bindings[i].Resolved {
			continue
		}
		ref := bindings[i].K8sRef
		if policyNamespace != "" && ref == nsK8sRef {
			return true
		}
		if policyNamespace == "" && ref == clusterK8sRef {
			return true
		}
	}
	return false
}

// PolicyCreatedOrUpdatedPredicate matches only Create and Update events on
// VaultPolicy / VaultClusterPolicy. We don't care about Delete here — if a
// policy is deleted, the role's `PolicyExists` check on the next sync will
// flip PoliciesResolved back to false and emit a warning condition, which
// is the desired behavior.
var PolicyCreatedOrUpdatedPredicate = predicate.Funcs{
	CreateFunc:  func(_ event.CreateEvent) bool { return true },
	UpdateFunc:  func(_ event.UpdateEvent) bool { return true },
	DeleteFunc:  func(_ event.DeleteEvent) bool { return false },
	GenericFunc: func(_ event.GenericEvent) bool { return false },
}
