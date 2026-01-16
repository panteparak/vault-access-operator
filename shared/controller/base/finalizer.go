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

package base

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// FinalizerManager handles adding and removing finalizers from resources.
// Finalizers ensure that cleanup logic runs before a resource is deleted.
type FinalizerManager struct {
	client        client.Client
	finalizerName string
}

// NewFinalizerManager creates a new FinalizerManager with the given finalizer name.
func NewFinalizerManager(c client.Client, finalizerName string) *FinalizerManager {
	return &FinalizerManager{
		client:        c,
		finalizerName: finalizerName,
	}
}

// HasFinalizer returns true if the resource has the managed finalizer.
func (f *FinalizerManager) HasFinalizer(obj client.Object) bool {
	return controllerutil.ContainsFinalizer(obj, f.finalizerName)
}

// Ensure adds the finalizer to the resource if it doesn't already have it.
// This should be called early in reconciliation to ensure cleanup happens on deletion.
func (f *FinalizerManager) Ensure(ctx context.Context, obj client.Object) error {
	if f.HasFinalizer(obj) {
		return nil
	}

	controllerutil.AddFinalizer(obj, f.finalizerName)
	return f.client.Update(ctx, obj)
}

// Remove removes the finalizer from the resource.
// This should be called after cleanup is complete to allow deletion to proceed.
func (f *FinalizerManager) Remove(ctx context.Context, obj client.Object) error {
	if !f.HasFinalizer(obj) {
		return nil
	}

	controllerutil.RemoveFinalizer(obj, f.finalizerName)
	return f.client.Update(ctx, obj)
}

// FinalizerName returns the name of the finalizer managed by this instance.
func (f *FinalizerManager) FinalizerName() string {
	return f.finalizerName
}
