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

package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestConflictError(t *testing.T) {
	t.Run("with message", func(t *testing.T) {
		err := NewConflictError("policy", "my-policy", "managed by terraform")
		expected := `conflict: policy "my-policy" already exists: managed by terraform`
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("without message", func(t *testing.T) {
		err := NewConflictError("role", "my-role", "")
		expected := `conflict: role "my-role" already exists and is not managed by this operator`
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("IsConflictError", func(t *testing.T) {
		conflictErr := NewConflictError("policy", "test", "")
		wrappedErr := fmt.Errorf("operation failed: %w", conflictErr)

		if !IsConflictError(conflictErr) {
			t.Error("expected IsConflictError to return true for ConflictError")
		}

		if !IsConflictError(wrappedErr) {
			t.Error("expected IsConflictError to return true for wrapped ConflictError")
		}

		if IsConflictError(errors.New("random error")) {
			t.Error("expected IsConflictError to return false for non-ConflictError")
		}
	})
}

func TestValidationError(t *testing.T) {
	t.Run("with field", func(t *testing.T) {
		err := NewValidationError("spec.rules", "[]", "at least one rule is required")
		expected := "validation error on spec.rules: at least one rule is required"
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("without field", func(t *testing.T) {
		err := &ValidationError{Message: "invalid configuration"}
		expected := "validation error: invalid configuration"
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("IsValidationError", func(t *testing.T) {
		validationErr := NewValidationError("field", "value", "invalid")
		wrappedErr := fmt.Errorf("failed: %w", validationErr)

		if !IsValidationError(validationErr) {
			t.Error("expected IsValidationError to return true for ValidationError")
		}

		if !IsValidationError(wrappedErr) {
			t.Error("expected IsValidationError to return true for wrapped ValidationError")
		}

		if IsValidationError(errors.New("random error")) {
			t.Error("expected IsValidationError to return false for non-ValidationError")
		}
	})
}

func TestTransientError(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := NewTransientError("write policy", cause)
		expected := "transient error during write policy: connection refused"
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &TransientError{Operation: "read secret"}
		expected := "transient error during read secret"
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("Unwrap", func(t *testing.T) {
		cause := errors.New("network timeout")
		err := NewTransientError("connect", cause)

		if !errors.Is(err, cause) {
			t.Error("expected errors.Is to match underlying cause")
		}
	})

	t.Run("IsTransientError", func(t *testing.T) {
		transientErr := NewTransientError("operation", nil)
		wrappedErr := fmt.Errorf("failed: %w", transientErr)

		if !IsTransientError(transientErr) {
			t.Error("expected IsTransientError to return true for TransientError")
		}

		if !IsTransientError(wrappedErr) {
			t.Error("expected IsTransientError to return true for wrapped TransientError")
		}

		if IsTransientError(errors.New("random error")) {
			t.Error("expected IsTransientError to return false for non-TransientError")
		}
	})

	t.Run("Retryable flag", func(t *testing.T) {
		err := NewTransientError("operation", nil)
		if !err.Retryable {
			t.Error("expected new TransientError to be retryable by default")
		}
	})
}

func TestNotFoundError(t *testing.T) {
	t.Run("namespaced resource", func(t *testing.T) {
		err := NewNotFoundError("VaultPolicy", "my-policy", "default")
		expected := "VaultPolicy default/my-policy not found"
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("cluster-scoped resource", func(t *testing.T) {
		err := NewNotFoundError("VaultConnection", "vault-conn", "")
		expected := "VaultConnection vault-conn not found"
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("IsNotFoundError", func(t *testing.T) {
		notFoundErr := NewNotFoundError("VaultPolicy", "test", "default")
		wrappedErr := fmt.Errorf("failed: %w", notFoundErr)

		if !IsNotFoundError(notFoundErr) {
			t.Error("expected IsNotFoundError to return true for NotFoundError")
		}

		if !IsNotFoundError(wrappedErr) {
			t.Error("expected IsNotFoundError to return true for wrapped NotFoundError")
		}

		if IsNotFoundError(errors.New("random error")) {
			t.Error("expected IsNotFoundError to return false for non-NotFoundError")
		}
	})
}

func TestConnectionError(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("TLS handshake failed")
		err := NewConnectionError("vault-conn", "https://vault:8200", cause)
		expected := `connection "vault-conn" to https://vault:8200 failed: TLS handshake failed`
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ConnectionError{ConnectionName: "vault-conn", Address: "https://vault:8200"}
		expected := `connection "vault-conn" to https://vault:8200 failed`
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("Unwrap", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := NewConnectionError("conn", "https://vault:8200", cause)

		if !errors.Is(err, cause) {
			t.Error("expected errors.Is to match underlying cause")
		}
	})

	t.Run("IsConnectionError", func(t *testing.T) {
		connErr := NewConnectionError("conn", "addr", nil)
		wrappedErr := fmt.Errorf("failed: %w", connErr)

		if !IsConnectionError(connErr) {
			t.Error("expected IsConnectionError to return true for ConnectionError")
		}

		if !IsConnectionError(wrappedErr) {
			t.Error("expected IsConnectionError to return true for wrapped ConnectionError")
		}

		if IsConnectionError(errors.New("random error")) {
			t.Error("expected IsConnectionError to return false for non-ConnectionError")
		}
	})
}

func TestDependencyError(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := NewDependencyError("VaultRole/my-role", "VaultConnection", "vault-conn", "not ready")
		expected := `VaultRole/my-role depends on VaultConnection "vault-conn" which is not ready`
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("IsDependencyError", func(t *testing.T) {
		depErr := NewDependencyError("resource", "dep", "name", "reason")
		wrappedErr := fmt.Errorf("failed: %w", depErr)

		if !IsDependencyError(depErr) {
			t.Error("expected IsDependencyError to return true for DependencyError")
		}

		if !IsDependencyError(wrappedErr) {
			t.Error("expected IsDependencyError to return true for wrapped DependencyError")
		}

		if IsDependencyError(errors.New("random error")) {
			t.Error("expected IsDependencyError to return false for non-DependencyError")
		}
	})
}

func TestErrorTypeChecking(t *testing.T) {
	// Test that error type checking works correctly across multiple types
	errs := []error{
		NewConflictError("policy", "test", ""),
		NewValidationError("field", "value", "invalid"),
		NewTransientError("operation", nil),
		NewNotFoundError("VaultPolicy", "test", "default"),
		NewConnectionError("conn", "addr", nil),
		NewDependencyError("resource", "dep", "name", "reason"),
	}

	checks := []struct {
		name  string
		check func(error) bool
		index int // which error should return true
	}{
		{"IsConflictError", IsConflictError, 0},
		{"IsValidationError", IsValidationError, 1},
		{"IsTransientError", IsTransientError, 2},
		{"IsNotFoundError", IsNotFoundError, 3},
		{"IsConnectionError", IsConnectionError, 4},
		{"IsDependencyError", IsDependencyError, 5},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			for i, err := range errs {
				result := check.check(err)
				expected := i == check.index
				if result != expected {
					t.Errorf("%s(%T) = %v, want %v", check.name, err, result, expected)
				}
			}
		})
	}
}
