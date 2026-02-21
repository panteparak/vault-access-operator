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
	"os"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Default requeue durations. These can be overridden via environment variables:
//   - OPERATOR_REQUEUE_SUCCESS_INTERVAL overrides DefaultRequeueSuccess
//   - OPERATOR_REQUEUE_ERROR_INTERVAL overrides DefaultRequeueError
var (
	DefaultRequeueSuccess = 5 * time.Minute
	DefaultRequeueError   = 30 * time.Second
)

func init() {
	if v := os.Getenv("OPERATOR_REQUEUE_SUCCESS_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			DefaultRequeueSuccess = d
		}
	}
	if v := os.Getenv("OPERATOR_REQUEUE_ERROR_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			DefaultRequeueError = d
		}
	}
}

// StatusUpdater is a function that updates the status of a resource.
// Each feature provides its own implementation for its specific status fields.
type StatusUpdater[T client.Object] func(ctx context.Context, resource T, err error) error

// StatusManager handles updating resource status and determining requeue behavior.
type StatusManager[T client.Object] struct {
	client           client.Client
	statusUpdater    StatusUpdater[T]
	requeueOnSuccess time.Duration
	requeueOnError   time.Duration
}

// NewStatusManager creates a new StatusManager with the given status updater function.
func NewStatusManager[T client.Object](c client.Client, updater StatusUpdater[T]) *StatusManager[T] {
	return &StatusManager[T]{
		client:           c,
		statusUpdater:    updater,
		requeueOnSuccess: DefaultRequeueSuccess,
		requeueOnError:   DefaultRequeueError,
	}
}

// WithRequeueOnSuccess sets the requeue duration for successful reconciliations.
func (s *StatusManager[T]) WithRequeueOnSuccess(d time.Duration) *StatusManager[T] {
	s.requeueOnSuccess = d
	return s
}

// WithRequeueOnError sets the requeue duration for failed reconciliations.
func (s *StatusManager[T]) WithRequeueOnError(d time.Duration) *StatusManager[T] {
	s.requeueOnError = d
	return s
}

// Success updates the status to indicate successful reconciliation and returns
// a result that requeues after the success interval.
func (s *StatusManager[T]) Success(ctx context.Context, resource T) (ctrl.Result, error) {
	if s.statusUpdater != nil {
		if err := s.statusUpdater(ctx, resource, nil); err != nil {
			// Log but don't fail - the reconciliation was successful
			return ctrl.Result{RequeueAfter: s.requeueOnSuccess}, nil
		}
	}

	return ctrl.Result{RequeueAfter: s.requeueOnSuccess}, nil
}

// Error updates the status to indicate a failed reconciliation and returns
// a result that requeues after the error interval.
func (s *StatusManager[T]) Error(ctx context.Context, resource T, reconcileErr error) (ctrl.Result, error) {
	if s.statusUpdater != nil {
		_ = s.statusUpdater(ctx, resource, reconcileErr)
	}

	// Return the error for the controller to handle
	return ctrl.Result{RequeueAfter: s.requeueOnError}, reconcileErr
}

// Requeue returns a result that requeues immediately without error.
// Uses a minimal RequeueAfter duration for immediate requeue.
func (s *StatusManager[T]) Requeue() (ctrl.Result, error) {
	return ctrl.Result{RequeueAfter: time.Millisecond}, nil
}

// RequeueAfter returns a result that requeues after the specified duration.
func (s *StatusManager[T]) RequeueAfter(d time.Duration) (ctrl.Result, error) {
	return ctrl.Result{RequeueAfter: d}, nil
}

// Done returns a result indicating no requeue is needed.
func (s *StatusManager[T]) Done() (ctrl.Result, error) {
	return ctrl.Result{}, nil
}
