/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package webhook

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// checkConnectionRefExists returns a webhook warning (not an error) if the
// given connectionRef does NOT resolve to a VaultConnection in the cluster
// (IMPROVEMENTS §36).
//
// Warning, not error, because:
//   - A user may legitimately `kubectl apply -f dir/` where the
//     VaultConnection and VaultPolicy/VaultRole are both being created in
//     the same batch, and the order the API server processes them is
//     undefined. Blocking a policy that references a connection the
//     apiserver hasn't persisted yet would be a footgun.
//   - The reconciler already catches the "connection not found" case and
//     surfaces it via Status.Conditions. The webhook warning is a UX
//     improvement that shortens the feedback loop, not a gate.
//
// Returns an empty slice when the connection exists or when the client is
// nil (tests that don't need dependency validation).
func checkConnectionRefExists(
	ctx context.Context, c client.Client, connectionRef string,
) admission.Warnings {
	if c == nil || connectionRef == "" {
		return nil
	}

	var conn vaultv1alpha1.VaultConnection
	err := c.Get(ctx, types.NamespacedName{Name: connectionRef}, &conn)
	if err == nil {
		return nil
	}
	if apierrors.IsNotFound(err) {
		return admission.Warnings{
			fmt.Sprintf(
				"spec.connectionRef %q does not currently resolve to a VaultConnection. "+
					"If applied in the same batch as the connection this is safe to ignore; "+
					"otherwise the resource will stay in Phase=Error with DependencyReady=False.",
				connectionRef),
		}
	}
	// Other errors (transient API-server issue) are not the user's problem —
	// skip the warning rather than emit a confusing message.
	return nil
}
