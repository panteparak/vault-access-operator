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

// Package logger provides structured logging utilities for the vault-access-operator.
// It defines standard log fields and helper functions for consistent logging across
// all controllers and services.
package logger

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Standard log field keys for consistent structured logging across the operator.
// Using consistent keys makes log aggregation and querying much easier.
const (
	// KeyController identifies the controller handling the reconciliation
	KeyController = "controller"

	// KeyResource identifies the resource being reconciled (name)
	KeyResource = "resource"

	// KeyNamespace identifies the namespace of the resource
	KeyNamespace = "namespace"

	// KeyVaultPath identifies the Vault path being accessed
	KeyVaultPath = "vaultPath"

	// KeyVaultPolicy identifies the Vault policy name
	KeyVaultPolicy = "vaultPolicy"

	// KeyVaultRole identifies the Vault role name
	KeyVaultRole = "vaultRole"

	// KeyOperation identifies the operation being performed (create, update, delete)
	KeyOperation = "operation"

	// KeyDuration records the time taken for an operation
	KeyDuration = "duration"

	// KeyReconcileID provides a unique identifier for tracing a reconciliation
	KeyReconcileID = "reconcileID"

	// KeyVaultConnection identifies the VaultConnection reference
	KeyVaultConnection = "vaultConnection"

	// KeyError includes error details
	KeyError = "error"

	// KeyRetryCount tracks retry attempts
	KeyRetryCount = "retryCount"

	// KeyFinalizer identifies finalizer operations
	KeyFinalizer = "finalizer"
)

// Operation types for logging
const (
	OpCreate     = "create"
	OpUpdate     = "update"
	OpDelete     = "delete"
	OpReconcile  = "reconcile"
	OpFinalizer  = "finalizer"
	OpValidate   = "validate"
	OpConnect    = "connect"
	OpDisconnect = "disconnect"
)

// ReconcileLogger wraps a logr.Logger with additional context for reconciliation.
type ReconcileLogger struct {
	logr.Logger
	startTime time.Time
}

// NewReconcileLogger creates a logger with standard reconcile context.
// This should be called at the beginning of each Reconcile function.
func NewReconcileLogger(ctx context.Context, controller string, req ctrl.Request) *ReconcileLogger {
	l := log.FromContext(ctx).WithValues(
		KeyController, controller,
		KeyResource, req.Name,
		KeyNamespace, req.Namespace,
	)

	return &ReconcileLogger{
		Logger:    l,
		startTime: time.Now(),
	}
}

// WithOperation returns a new logger with operation context added.
func (r *ReconcileLogger) WithOperation(op string) *ReconcileLogger {
	return &ReconcileLogger{
		Logger:    r.Logger.WithValues(KeyOperation, op),
		startTime: r.startTime,
	}
}

// WithVaultPath returns a new logger with Vault path context added.
func (r *ReconcileLogger) WithVaultPath(path string) *ReconcileLogger {
	return &ReconcileLogger{
		Logger:    r.Logger.WithValues(KeyVaultPath, path),
		startTime: r.startTime,
	}
}

// WithVaultConnection returns a new logger with VaultConnection reference added.
func (r *ReconcileLogger) WithVaultConnection(name, namespace string) *ReconcileLogger {
	return &ReconcileLogger{
		Logger:    r.Logger.WithValues(KeyVaultConnection, namespace+"/"+name),
		startTime: r.startTime,
	}
}

// WithRetryCount returns a new logger with retry count added.
func (r *ReconcileLogger) WithRetryCount(count int) *ReconcileLogger {
	return &ReconcileLogger{
		Logger:    r.Logger.WithValues(KeyRetryCount, count),
		startTime: r.startTime,
	}
}

// Duration returns the elapsed time since the logger was created.
func (r *ReconcileLogger) Duration() time.Duration {
	return time.Since(r.startTime)
}

// InfoWithDuration logs an info message with the elapsed duration.
func (r *ReconcileLogger) InfoWithDuration(msg string, keysAndValues ...interface{}) {
	r.Info(msg, append(keysAndValues, KeyDuration, r.Duration().String())...)
}

// ErrorWithDuration logs an error with the elapsed duration.
func (r *ReconcileLogger) ErrorWithDuration(err error, msg string, keysAndValues ...interface{}) {
	r.Error(err, msg, append(keysAndValues, KeyDuration, r.Duration().String())...)
}

// V returns a logger at the specified verbosity level.
func (r *ReconcileLogger) V(level int) *ReconcileLogger {
	return &ReconcileLogger{
		Logger:    r.Logger.V(level),
		startTime: r.startTime,
	}
}

// WithValues returns a new logger with additional key-value pairs.
func (r *ReconcileLogger) WithValues(keysAndValues ...interface{}) *ReconcileLogger {
	return &ReconcileLogger{
		Logger:    r.Logger.WithValues(keysAndValues...),
		startTime: r.startTime,
	}
}

// LogReconcileStart logs the start of a reconciliation.
func (r *ReconcileLogger) LogReconcileStart() {
	r.V(1).Info("starting reconciliation")
}

// LogReconcileSuccess logs successful completion of a reconciliation.
func (r *ReconcileLogger) LogReconcileSuccess() {
	r.InfoWithDuration("reconciliation completed successfully")
}

// LogReconcileRequeue logs when a reconciliation is being requeued.
func (r *ReconcileLogger) LogReconcileRequeue(reason string, after time.Duration) {
	r.Info("requeuing reconciliation", "reason", reason, "after", after.String())
}

// LogReconcileError logs a reconciliation error.
func (r *ReconcileLogger) LogReconcileError(err error) {
	r.ErrorWithDuration(err, "reconciliation failed")
}

// LogVaultOperation logs a Vault operation with path and operation type.
func (r *ReconcileLogger) LogVaultOperation(op, path string) {
	r.V(1).Info("performing vault operation", KeyOperation, op, KeyVaultPath, path)
}

// LogVaultOperationSuccess logs successful completion of a Vault operation.
func (r *ReconcileLogger) LogVaultOperationSuccess(op, path string) {
	r.Info("vault operation completed", KeyOperation, op, KeyVaultPath, path)
}

// LogVaultOperationError logs a Vault operation error.
func (r *ReconcileLogger) LogVaultOperationError(err error, op, path string) {
	r.Error(err, "vault operation failed", KeyOperation, op, KeyVaultPath, path)
}

// LogFinalizerAdd logs adding a finalizer.
func (r *ReconcileLogger) LogFinalizerAdd(finalizer string) {
	r.V(1).Info("adding finalizer", KeyFinalizer, finalizer)
}

// LogFinalizerRemove logs removing a finalizer.
func (r *ReconcileLogger) LogFinalizerRemove(finalizer string) {
	r.V(1).Info("removing finalizer", KeyFinalizer, finalizer)
}

// LogStatusUpdate logs a status update.
func (r *ReconcileLogger) LogStatusUpdate(status string) {
	r.V(1).Info("updating status", "status", status)
}

// FromContext extracts a logger from context with standard fields.
// Falls back to a background logger if none is found.
func FromContext(ctx context.Context, keysAndValues ...interface{}) logr.Logger {
	return log.FromContext(ctx, keysAndValues...)
}

// WithOperation adds operation context to an existing logger.
func WithOperation(l logr.Logger, op string) logr.Logger {
	return l.WithValues(KeyOperation, op)
}

// WithVaultPath adds Vault path context to an existing logger.
func WithVaultPath(l logr.Logger, path string) logr.Logger {
	return l.WithValues(KeyVaultPath, path)
}

// WithVaultConnection adds VaultConnection context to an existing logger.
func WithVaultConnection(l logr.Logger, name, namespace string) logr.Logger {
	return l.WithValues(KeyVaultConnection, namespace+"/"+name)
}

// WithDuration adds duration context to an existing logger.
func WithDuration(l logr.Logger, d time.Duration) logr.Logger {
	return l.WithValues(KeyDuration, d.String())
}
