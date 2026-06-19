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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// KVSecretRequestsForConnection returns a MapFunc that enqueues VaultKVSecret
// reconcile requests when a VaultConnection changes. Only secrets referencing
// the changed connection are enqueued — so a connection going Active retries
// any seeds that were blocked waiting on it.
func KVSecretRequestsForConnection(k8sClient client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		connName := obj.GetName()
		logger := log.FromContext(ctx).WithValues("connection", connName, "watchTarget", "VaultKVSecret")

		list := &vaultv1alpha1.VaultKVSecretList{}
		if err := k8sClient.List(ctx, list); err != nil {
			logger.Error(err, "failed to list VaultKVSecrets for connection watch")
			return nil
		}

		var requests []reconcile.Request
		for _, s := range list.Items {
			if s.Spec.ConnectionRef == connName {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: s.Name, Namespace: s.Namespace},
				})
			}
		}

		if len(requests) > 0 {
			logger.V(1).Info("enqueuing dependent kv secrets", "count", len(requests))
		}
		return requests
	}
}
