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

// Package watches provides cross-resource watch functions for triggering
// dependent reconciliation when upstream resources change.
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

// PolicyRequestsForConnection returns a MapFunc that enqueues VaultPolicy
// reconcile requests when a VaultConnection changes. Only policies referencing
// the changed connection are enqueued.
func PolicyRequestsForConnection(k8sClient client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		connName := obj.GetName()
		logger := log.FromContext(ctx).WithValues("connection", connName, "watchTarget", "VaultPolicy")

		policyList := &vaultv1alpha1.VaultPolicyList{}
		if err := k8sClient.List(ctx, policyList); err != nil {
			logger.Error(err, "failed to list VaultPolicies for connection watch")
			return nil
		}

		var requests []reconcile.Request
		for _, p := range policyList.Items {
			if p.Spec.ConnectionRef == connName {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      p.Name,
						Namespace: p.Namespace,
					},
				})
			}
		}

		if len(requests) > 0 {
			logger.V(1).Info("enqueuing dependent policies", "count", len(requests))
		}
		return requests
	}
}

// ClusterPolicyRequestsForConnection returns a MapFunc that enqueues
// VaultClusterPolicy reconcile requests when a VaultConnection changes.
func ClusterPolicyRequestsForConnection(k8sClient client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		connName := obj.GetName()
		logger := log.FromContext(ctx).WithValues("connection", connName, "watchTarget", "VaultClusterPolicy")

		policyList := &vaultv1alpha1.VaultClusterPolicyList{}
		if err := k8sClient.List(ctx, policyList); err != nil {
			logger.Error(err, "failed to list VaultClusterPolicies for connection watch")
			return nil
		}

		var requests []reconcile.Request
		for _, p := range policyList.Items {
			if p.Spec.ConnectionRef == connName {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name: p.Name,
					},
				})
			}
		}

		if len(requests) > 0 {
			logger.V(1).Info("enqueuing dependent cluster policies", "count", len(requests))
		}
		return requests
	}
}

// RoleRequestsForConnection returns a MapFunc that enqueues VaultRole
// reconcile requests when a VaultConnection changes.
func RoleRequestsForConnection(k8sClient client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		connName := obj.GetName()
		logger := log.FromContext(ctx).WithValues("connection", connName, "watchTarget", "VaultRole")

		roleList := &vaultv1alpha1.VaultRoleList{}
		if err := k8sClient.List(ctx, roleList); err != nil {
			logger.Error(err, "failed to list VaultRoles for connection watch")
			return nil
		}

		var requests []reconcile.Request
		for _, r := range roleList.Items {
			if r.Spec.ConnectionRef == connName {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      r.Name,
						Namespace: r.Namespace,
					},
				})
			}
		}

		if len(requests) > 0 {
			logger.V(1).Info("enqueuing dependent roles", "count", len(requests))
		}
		return requests
	}
}

// ClusterRoleRequestsForConnection returns a MapFunc that enqueues
// VaultClusterRole reconcile requests when a VaultConnection changes.
func ClusterRoleRequestsForConnection(k8sClient client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		connName := obj.GetName()
		logger := log.FromContext(ctx).WithValues("connection", connName, "watchTarget", "VaultClusterRole")

		roleList := &vaultv1alpha1.VaultClusterRoleList{}
		if err := k8sClient.List(ctx, roleList); err != nil {
			logger.Error(err, "failed to list VaultClusterRoles for connection watch")
			return nil
		}

		var requests []reconcile.Request
		for _, r := range roleList.Items {
			if r.Spec.ConnectionRef == connName {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name: r.Name,
					},
				})
			}
		}

		if len(requests) > 0 {
			logger.V(1).Info("enqueuing dependent cluster roles", "count", len(requests))
		}
		return requests
	}
}
