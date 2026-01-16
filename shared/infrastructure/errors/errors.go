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

// Package errors provides domain-specific error types for the operator.
// These errors help distinguish between different failure modes and enable
// appropriate handling strategies (retry, abort, user action required).
package errors

import (
	"errors"
	"fmt"
)

// ConflictError indicates a resource already exists in Vault and is not managed
// by this operator. The operator will not overwrite resources it doesn't own.
type ConflictError struct {
	ResourceType string // e.g., "policy", "role"
	ResourceName string // Name of the conflicting resource
	Message      string // Additional context
}

func (e *ConflictError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("conflict: %s %q already exists: %s", e.ResourceType, e.ResourceName, e.Message)
	}
	return fmt.Sprintf(
		"conflict: %s %q already exists and is not managed by this operator",
		e.ResourceType, e.ResourceName,
	)
}

// NewConflictError creates a ConflictError.
func NewConflictError(resourceType, resourceName, message string) *ConflictError {
	return &ConflictError{
		ResourceType: resourceType,
		ResourceName: resourceName,
		Message:      message,
	}
}

// IsConflictError returns true if the error is a ConflictError.
func IsConflictError(err error) bool {
	var conflictErr *ConflictError
	return errors.As(err, &conflictErr)
}

// ValidationError indicates invalid configuration or input.
// This is a permanent error - retrying won't help without user correction.
type ValidationError struct {
	Field   string // The field that failed validation
	Value   string // The invalid value (may be redacted for sensitive data)
	Message string // Why validation failed
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error on %s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// NewValidationError creates a ValidationError.
func NewValidationError(field, value, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}

// IsValidationError returns true if the error is a ValidationError.
func IsValidationError(err error) bool {
	var validationErr *ValidationError
	return errors.As(err, &validationErr)
}

// TransientError indicates a temporary failure that should be retried.
// Common causes: network issues, Vault unavailable, rate limiting.
type TransientError struct {
	Operation string // What operation was attempted
	Cause     error  // The underlying error
	Retryable bool   // Whether retry is recommended
}

func (e *TransientError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("transient error during %s: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("transient error during %s", e.Operation)
}

// Unwrap returns the underlying cause for errors.As/Is support.
func (e *TransientError) Unwrap() error {
	return e.Cause
}

// NewTransientError creates a TransientError.
func NewTransientError(operation string, cause error) *TransientError {
	return &TransientError{
		Operation: operation,
		Cause:     cause,
		Retryable: true,
	}
}

// IsTransientError returns true if the error is a TransientError.
func IsTransientError(err error) bool {
	var transientErr *TransientError
	return errors.As(err, &transientErr)
}

// NotFoundError indicates a required resource doesn't exist.
// This may be permanent (missing dependency) or transient (not yet created).
type NotFoundError struct {
	ResourceType string // e.g., "VaultConnection", "VaultPolicy"
	ResourceName string // Name of the missing resource
	Namespace    string // Namespace (empty for cluster-scoped)
}

func (e *NotFoundError) Error() string {
	if e.Namespace != "" {
		return fmt.Sprintf("%s %s/%s not found", e.ResourceType, e.Namespace, e.ResourceName)
	}
	return fmt.Sprintf("%s %s not found", e.ResourceType, e.ResourceName)
}

// NewNotFoundError creates a NotFoundError.
func NewNotFoundError(resourceType, name, namespace string) *NotFoundError {
	return &NotFoundError{
		ResourceType: resourceType,
		ResourceName: name,
		Namespace:    namespace,
	}
}

// IsNotFoundError returns true if the error is a NotFoundError.
func IsNotFoundError(err error) bool {
	var notFoundErr *NotFoundError
	return errors.As(err, &notFoundErr)
}

// ConnectionError indicates a failure to connect to or authenticate with Vault.
type ConnectionError struct {
	ConnectionName string // Name of the VaultConnection resource
	Address        string // Vault address that failed
	Cause          error  // The underlying error
}

func (e *ConnectionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("connection %q to %s failed: %v", e.ConnectionName, e.Address, e.Cause)
	}
	return fmt.Sprintf("connection %q to %s failed", e.ConnectionName, e.Address)
}

// Unwrap returns the underlying cause for errors.As/Is support.
func (e *ConnectionError) Unwrap() error {
	return e.Cause
}

// NewConnectionError creates a ConnectionError.
func NewConnectionError(connName, address string, cause error) *ConnectionError {
	return &ConnectionError{
		ConnectionName: connName,
		Address:        address,
		Cause:          cause,
	}
}

// IsConnectionError returns true if the error is a ConnectionError.
func IsConnectionError(err error) bool {
	var connErr *ConnectionError
	return errors.As(err, &connErr)
}

// DependencyError indicates a required dependency is not ready.
// For example, a VaultRole depends on its referenced VaultConnection.
type DependencyError struct {
	Resource       string // Resource that has the dependency
	DependencyType string // Type of the dependency (e.g., "VaultConnection")
	DependencyName string // Name of the missing/unready dependency
	Reason         string // Why the dependency is not satisfied
}

func (e *DependencyError) Error() string {
	return fmt.Sprintf("%s depends on %s %q which is %s",
		e.Resource, e.DependencyType, e.DependencyName, e.Reason)
}

// NewDependencyError creates a DependencyError.
func NewDependencyError(resource, depType, depName, reason string) *DependencyError {
	return &DependencyError{
		Resource:       resource,
		DependencyType: depType,
		DependencyName: depName,
		Reason:         reason,
	}
}

// IsDependencyError returns true if the error is a DependencyError.
func IsDependencyError(err error) bool {
	var depErr *DependencyError
	return errors.As(err, &depErr)
}
