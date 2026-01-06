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

package controller

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ConflictError represents a conflict with an existing Vault resource
type ConflictError struct {
	ResourceType string
	ResourceName string
	Message      string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("conflict: %s %q: %s", e.ResourceType, e.ResourceName, e.Message)
}

// NewConflictError creates a new ConflictError
func NewConflictError(resourceType, resourceName, message string) *ConflictError {
	return &ConflictError{
		ResourceType: resourceType,
		ResourceName: resourceName,
		Message:      message,
	}
}

// ValidationError represents a validation failure
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error for field %q: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// NewValidationError creates a new ValidationError
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
	}
}

// TransientError represents a temporary error that should be retried
type TransientError struct {
	Message string
	Cause   error
}

func (e *TransientError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("transient error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("transient error: %s", e.Message)
}

func (e *TransientError) Unwrap() error {
	return e.Cause
}

// NewTransientError creates a new TransientError
func NewTransientError(message string, cause error) *TransientError {
	return &TransientError{
		Message: message,
		Cause:   cause,
	}
}

// ConnectionNotReadyError indicates the VaultConnection is not ready
type ConnectionNotReadyError struct {
	ConnectionName string
	Message        string
}

func (e *ConnectionNotReadyError) Error() string {
	return fmt.Sprintf("connection %q not ready: %s", e.ConnectionName, e.Message)
}

// NewConnectionNotReadyError creates a new ConnectionNotReadyError
func NewConnectionNotReadyError(connectionName, message string) *ConnectionNotReadyError {
	return &ConnectionNotReadyError{
		ConnectionName: connectionName,
		Message:        message,
	}
}

// PolicyNotFoundError indicates a referenced policy was not found
type PolicyNotFoundError struct {
	PolicyKind string
	PolicyName string
	Namespace  string
}

func (e *PolicyNotFoundError) Error() string {
	if e.Namespace != "" {
		return fmt.Sprintf("policy %s %q not found in namespace %q", e.PolicyKind, e.PolicyName, e.Namespace)
	}
	return fmt.Sprintf("policy %s %q not found", e.PolicyKind, e.PolicyName)
}

// NewPolicyNotFoundError creates a new PolicyNotFoundError
func NewPolicyNotFoundError(kind, name, namespace string) *PolicyNotFoundError {
	return &PolicyNotFoundError{
		PolicyKind: kind,
		PolicyName: name,
		Namespace:  namespace,
	}
}

// IsRetryableError determines if an error should be retried
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// TransientError is always retryable
	var transientErr *TransientError
	if errors.As(err, &transientErr) {
		return true
	}

	// ConnectionNotReadyError is retryable
	var connNotReadyErr *ConnectionNotReadyError
	if errors.As(err, &connNotReadyErr) {
		return true
	}

	// ConflictError is NOT retryable (requires user intervention)
	var conflictErr *ConflictError
	if errors.As(err, &conflictErr) {
		return false
	}

	// ValidationError is NOT retryable (requires spec change)
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return false
	}

	// PolicyNotFoundError is retryable (policy might be created soon)
	var policyNotFoundErr *PolicyNotFoundError
	if errors.As(err, &policyNotFoundErr) {
		return true
	}

	// Network errors are retryable
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// Check for common retryable error patterns in the error message
	errMsg := err.Error()
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"service unavailable",
		"too many requests",
		"rate limit",
		"503",
		"504",
		"429",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(strings.ToLower(errMsg), pattern) {
			return true
		}
	}

	return false
}

// IsConflictError checks if the error is a ConflictError
func IsConflictError(err error) bool {
	var conflictErr *ConflictError
	return errors.As(err, &conflictErr)
}

// IsValidationError checks if the error is a ValidationError
func IsValidationError(err error) bool {
	var validationErr *ValidationError
	return errors.As(err, &validationErr)
}

// IsTransientError checks if the error is a TransientError
func IsTransientError(err error) bool {
	var transientErr *TransientError
	return errors.As(err, &transientErr)
}

// IsConnectionNotReadyError checks if the error is a ConnectionNotReadyError
func IsConnectionNotReadyError(err error) bool {
	var connNotReadyErr *ConnectionNotReadyError
	return errors.As(err, &connNotReadyErr)
}

// IsPolicyNotFoundError checks if the error is a PolicyNotFoundError
func IsPolicyNotFoundError(err error) bool {
	var policyNotFoundErr *PolicyNotFoundError
	return errors.As(err, &policyNotFoundErr)
}
