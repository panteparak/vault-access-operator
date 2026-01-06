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
	"testing"
)

func TestConflictError_Error(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		resourceName string
		message      string
		expected     string
	}{
		{
			name:         "policy conflict",
			resourceType: "policy",
			resourceName: "my-policy",
			message:      "already exists with different owner",
			expected:     `conflict: policy "my-policy": already exists with different owner`,
		},
		{
			name:         "role conflict",
			resourceType: "role",
			resourceName: "admin-role",
			message:      "managed by another operator",
			expected:     `conflict: role "admin-role": managed by another operator`,
		},
		{
			name:         "empty message",
			resourceType: "secret",
			resourceName: "db-creds",
			message:      "",
			expected:     `conflict: secret "db-creds": `,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewConflictError(tt.resourceType, tt.resourceName, tt.message)
			if got := err.Error(); got != tt.expected {
				t.Errorf("ConflictError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		message  string
		expected string
	}{
		{
			name:     "field validation error",
			field:    "spec.policies",
			message:  "at least one policy required",
			expected: `validation error for field "spec.policies": at least one policy required`,
		},
		{
			name:     "nested field validation",
			field:    "spec.connection.address",
			message:  "must be a valid URL",
			expected: `validation error for field "spec.connection.address": must be a valid URL`,
		},
		{
			name:     "empty field (general validation)",
			field:    "",
			message:  "invalid configuration",
			expected: "validation error: invalid configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewValidationError(tt.field, tt.message)
			if got := err.Error(); got != tt.expected {
				t.Errorf("ValidationError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestTransientError_Error(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		cause    error
		expected string
	}{
		{
			name:     "with cause",
			message:  "failed to connect to Vault",
			cause:    errors.New("connection refused"),
			expected: "transient error: failed to connect to Vault: connection refused",
		},
		{
			name:     "without cause",
			message:  "temporary failure",
			cause:    nil,
			expected: "transient error: temporary failure",
		},
		{
			name:     "with wrapped cause",
			message:  "operation failed",
			cause:    fmt.Errorf("wrapped: %w", errors.New("root cause")),
			expected: "transient error: operation failed: wrapped: root cause",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewTransientError(tt.message, tt.cause)
			if got := err.Error(); got != tt.expected {
				t.Errorf("TransientError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestTransientError_Unwrap(t *testing.T) {
	rootCause := errors.New("root cause")
	wrappedCause := fmt.Errorf("wrapped: %w", rootCause)

	tests := []struct {
		name          string
		cause         error
		expectedCause error
	}{
		{
			name:          "unwrap returns cause",
			cause:         rootCause,
			expectedCause: rootCause,
		},
		{
			name:          "unwrap returns wrapped cause",
			cause:         wrappedCause,
			expectedCause: wrappedCause,
		},
		{
			name:          "unwrap returns nil when no cause",
			cause:         nil,
			expectedCause: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewTransientError("test message", tt.cause)
			if got := err.Unwrap(); got != tt.expectedCause {
				t.Errorf("TransientError.Unwrap() = %v, want %v", got, tt.expectedCause)
			}
		})
	}
}

func TestTransientError_ErrorsIs(t *testing.T) {
	rootCause := errors.New("root cause")
	transientErr := NewTransientError("operation failed", rootCause)

	// errors.Is should find the root cause through Unwrap
	if !errors.Is(transientErr, rootCause) {
		t.Error("errors.Is(transientErr, rootCause) = false, want true")
	}
}

func TestConnectionNotReadyError_Error(t *testing.T) {
	tests := []struct {
		name           string
		connectionName string
		message        string
		expected       string
	}{
		{
			name:           "connection initializing",
			connectionName: "vault-primary",
			message:        "still initializing",
			expected:       `connection "vault-primary" not ready: still initializing`,
		},
		{
			name:           "connection unhealthy",
			connectionName: "vault-secondary",
			message:        "health check failed",
			expected:       `connection "vault-secondary" not ready: health check failed`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewConnectionNotReadyError(tt.connectionName, tt.message)
			if got := err.Error(); got != tt.expected {
				t.Errorf("ConnectionNotReadyError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestPolicyNotFoundError_Error(t *testing.T) {
	tests := []struct {
		name       string
		policyKind string
		policyName string
		namespace  string
		expected   string
	}{
		{
			name:       "namespaced policy",
			policyKind: "VaultPolicyBinding",
			policyName: "my-policy",
			namespace:  "default",
			expected:   `policy VaultPolicyBinding "my-policy" not found in namespace "default"`,
		},
		{
			name:       "cluster-scoped policy",
			policyKind: "ClusterVaultPolicy",
			policyName: "global-policy",
			namespace:  "",
			expected:   `policy ClusterVaultPolicy "global-policy" not found`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewPolicyNotFoundError(tt.policyKind, tt.policyName, tt.namespace)
			if got := err.Error(); got != tt.expected {
				t.Errorf("PolicyNotFoundError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestIsRetryableError(t *testing.T) {
	// Create a mock net.Error for testing
	mockNetError := &mockNetError{
		err:       "network error",
		timeout:   true,
		temporary: true,
	}

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "TransientError is retryable",
			err:      NewTransientError("temporary failure", nil),
			expected: true,
		},
		{
			name:     "ConnectionNotReadyError is retryable",
			err:      NewConnectionNotReadyError("vault", "initializing"),
			expected: true,
		},
		{
			name:     "PolicyNotFoundError is retryable",
			err:      NewPolicyNotFoundError("VaultPolicy", "test", "default"),
			expected: true,
		},
		{
			name:     "ConflictError is NOT retryable",
			err:      NewConflictError("policy", "test", "exists"),
			expected: false,
		},
		{
			name:     "ValidationError is NOT retryable",
			err:      NewValidationError("field", "invalid"),
			expected: false,
		},
		{
			name:     "net.Error is retryable",
			err:      mockNetError,
			expected: true,
		},
		{
			name:     "wrapped TransientError is retryable",
			err:      fmt.Errorf("outer: %w", NewTransientError("inner", nil)),
			expected: true,
		},
		{
			name:     "wrapped ConflictError is NOT retryable",
			err:      fmt.Errorf("outer: %w", NewConflictError("policy", "test", "exists")),
			expected: false,
		},
		{
			name:     "error with 'connection refused' pattern",
			err:      errors.New("dial tcp 127.0.0.1:8200: connection refused"),
			expected: true,
		},
		{
			name:     "error with 'connection reset' pattern",
			err:      errors.New("read tcp: connection reset by peer"),
			expected: true,
		},
		{
			name:     "error with 'timeout' pattern",
			err:      errors.New("context deadline exceeded (Client.Timeout)"),
			expected: true,
		},
		{
			name:     "error with 'temporary failure' pattern",
			err:      errors.New("temporary failure in name resolution"),
			expected: true,
		},
		{
			name:     "error with 'service unavailable' pattern",
			err:      errors.New("service unavailable"),
			expected: true,
		},
		{
			name:     "error with 'too many requests' pattern",
			err:      errors.New("too many requests"),
			expected: true,
		},
		{
			name:     "error with 'rate limit' pattern",
			err:      errors.New("rate limit exceeded"),
			expected: true,
		},
		{
			name:     "error with '503' pattern",
			err:      errors.New("HTTP 503: Service Temporarily Unavailable"),
			expected: true,
		},
		{
			name:     "error with '504' pattern",
			err:      errors.New("HTTP 504: Gateway Timeout"),
			expected: true,
		},
		{
			name:     "error with '429' pattern",
			err:      errors.New("HTTP 429: Too Many Requests"),
			expected: true,
		},
		{
			name:     "unknown error is NOT retryable",
			err:      errors.New("some unknown error"),
			expected: false,
		},
		{
			name:     "case insensitive pattern matching",
			err:      errors.New("CONNECTION REFUSED"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRetryableError(tt.err)
			if got != tt.expected {
				t.Errorf("IsRetryableError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsConflictError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ConflictError",
			err:      NewConflictError("policy", "test", "exists"),
			expected: true,
		},
		{
			name:     "wrapped ConflictError",
			err:      fmt.Errorf("outer: %w", NewConflictError("policy", "test", "exists")),
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("not a conflict"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsConflictError(tt.err); got != tt.expected {
				t.Errorf("IsConflictError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ValidationError",
			err:      NewValidationError("field", "invalid"),
			expected: true,
		},
		{
			name:     "wrapped ValidationError",
			err:      fmt.Errorf("outer: %w", NewValidationError("field", "invalid")),
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("not a validation error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidationError(tt.err); got != tt.expected {
				t.Errorf("IsValidationError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "TransientError",
			err:      NewTransientError("temporary", nil),
			expected: true,
		},
		{
			name:     "wrapped TransientError",
			err:      fmt.Errorf("outer: %w", NewTransientError("temporary", nil)),
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("not transient"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTransientError(tt.err); got != tt.expected {
				t.Errorf("IsTransientError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsConnectionNotReadyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ConnectionNotReadyError",
			err:      NewConnectionNotReadyError("vault", "initializing"),
			expected: true,
		},
		{
			name:     "wrapped ConnectionNotReadyError",
			err:      fmt.Errorf("outer: %w", NewConnectionNotReadyError("vault", "initializing")),
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("not connection error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsConnectionNotReadyError(tt.err); got != tt.expected {
				t.Errorf("IsConnectionNotReadyError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsPolicyNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "PolicyNotFoundError",
			err:      NewPolicyNotFoundError("VaultPolicy", "test", "default"),
			expected: true,
		},
		{
			name:     "wrapped PolicyNotFoundError",
			err:      fmt.Errorf("outer: %w", NewPolicyNotFoundError("VaultPolicy", "test", "default")),
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("not policy error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPolicyNotFoundError(tt.err); got != tt.expected {
				t.Errorf("IsPolicyNotFoundError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// mockNetError implements net.Error for testing
type mockNetError struct {
	err       string
	timeout   bool
	temporary bool
}

func (e *mockNetError) Error() string   { return e.err }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

// Ensure mockNetError implements net.Error
var _ net.Error = (*mockNetError)(nil)

func TestErrorWrapping(t *testing.T) {
	// Test that errors can be properly wrapped and unwrapped
	rootCause := errors.New("root cause")

	// Create a chain: TransientError wrapping rootCause
	transientErr := NewTransientError("operation failed", rootCause)

	// Wrap again with fmt.Errorf
	wrappedErr := fmt.Errorf("high level error: %w", transientErr)

	// errors.As should find TransientError
	var foundTransient *TransientError
	if !errors.As(wrappedErr, &foundTransient) {
		t.Error("errors.As() could not find TransientError in wrapped chain")
	}

	// errors.Is should find rootCause
	if !errors.Is(wrappedErr, rootCause) {
		t.Error("errors.Is() could not find rootCause in wrapped chain")
	}

	// Verify the found error has correct fields
	if foundTransient.Message != "operation failed" {
		t.Errorf("Found TransientError.Message = %q, want %q", foundTransient.Message, "operation failed")
	}
	if foundTransient.Cause != rootCause {
		t.Errorf("Found TransientError.Cause = %v, want %v", foundTransient.Cause, rootCause)
	}
}
