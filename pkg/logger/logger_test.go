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

package logger

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	testResource  = "test-resource"
	testNamespace = "test-namespace"
)

func TestNewReconcileLogger(t *testing.T) {
	// Setup a test logger
	ctx := log.IntoContext(context.Background(), logr.Discard())

	req := ctrl.Request{}
	req.Name = testResource
	req.Namespace = testNamespace

	logger := NewReconcileLogger(ctx, "TestController", req)

	if logger == nil {
		t.Fatal("expected logger to be non-nil")
		return
	}

	if logger.startTime.IsZero() {
		t.Error("expected startTime to be set")
	}
}

func TestReconcileLoggerWithOperation(t *testing.T) {
	ctx := log.IntoContext(context.Background(), logr.Discard())
	req := ctrl.Request{}
	req.Name = testResource
	req.Namespace = testNamespace

	logger := NewReconcileLogger(ctx, "TestController", req)
	opLogger := logger.WithOperation(OpCreate)

	if opLogger == nil {
		t.Fatal("expected logger with operation to be non-nil")
	}

	// The original logger should be unchanged
	if logger == opLogger {
		t.Error("WithOperation should return a new logger")
	}
}

func TestReconcileLoggerWithVaultPath(t *testing.T) {
	ctx := log.IntoContext(context.Background(), logr.Discard())
	req := ctrl.Request{}
	req.Name = testResource
	req.Namespace = testNamespace

	logger := NewReconcileLogger(ctx, "TestController", req)
	pathLogger := logger.WithVaultPath("secret/data/myapp")

	if pathLogger == nil {
		t.Fatal("expected logger with vault path to be non-nil")
	}
}

func TestReconcileLoggerWithVaultConnection(t *testing.T) {
	ctx := log.IntoContext(context.Background(), logr.Discard())
	req := ctrl.Request{}
	req.Name = testResource
	req.Namespace = testNamespace

	logger := NewReconcileLogger(ctx, "TestController", req)
	connLogger := logger.WithVaultConnection("my-connection", "vault-system")

	if connLogger == nil {
		t.Fatal("expected logger with vault connection to be non-nil")
	}
}

func TestReconcileLoggerWithRetryCount(t *testing.T) {
	ctx := log.IntoContext(context.Background(), logr.Discard())
	req := ctrl.Request{}
	req.Name = testResource
	req.Namespace = testNamespace

	logger := NewReconcileLogger(ctx, "TestController", req)
	retryLogger := logger.WithRetryCount(3)

	if retryLogger == nil {
		t.Fatal("expected logger with retry count to be non-nil")
	}
}

func TestReconcileLoggerDuration(t *testing.T) {
	ctx := log.IntoContext(context.Background(), logr.Discard())
	req := ctrl.Request{}
	req.Name = testResource
	req.Namespace = testNamespace

	logger := NewReconcileLogger(ctx, "TestController", req)

	// Sleep a tiny bit to ensure duration is > 0
	time.Sleep(1 * time.Millisecond)

	duration := logger.Duration()
	if duration <= 0 {
		t.Errorf("expected duration > 0, got %v", duration)
	}
}

func TestReconcileLoggerChaining(t *testing.T) {
	ctx := log.IntoContext(context.Background(), logr.Discard())
	req := ctrl.Request{}
	req.Name = testResource
	req.Namespace = testNamespace

	logger := NewReconcileLogger(ctx, "TestController", req).
		WithOperation(OpCreate).
		WithVaultPath("secret/data/myapp").
		WithRetryCount(1)

	if logger == nil {
		t.Fatal("expected chained logger to be non-nil")
	}
}

func TestReconcileLoggerV(t *testing.T) {
	ctx := log.IntoContext(context.Background(), logr.Discard())
	req := ctrl.Request{}
	req.Name = testResource
	req.Namespace = testNamespace

	logger := NewReconcileLogger(ctx, "TestController", req)
	verboseLogger := logger.V(1)

	if verboseLogger == nil {
		t.Fatal("expected verbose logger to be non-nil")
	}

	// Start time should be preserved
	if verboseLogger.startTime != logger.startTime {
		t.Error("V() should preserve startTime")
	}
}

func TestReconcileLoggerWithValues(t *testing.T) {
	ctx := log.IntoContext(context.Background(), logr.Discard())
	req := ctrl.Request{}
	req.Name = testResource
	req.Namespace = testNamespace

	logger := NewReconcileLogger(ctx, "TestController", req)
	customLogger := logger.WithValues("customKey", "customValue")

	if customLogger == nil {
		t.Fatal("expected logger with custom values to be non-nil")
	}

	// Start time should be preserved
	if customLogger.startTime != logger.startTime {
		t.Error("WithValues() should preserve startTime")
	}
}

func TestHelperFunctions(t *testing.T) {
	baseLogger := logr.Discard()

	t.Run("WithOperation", func(t *testing.T) {
		l := WithOperation(baseLogger, OpCreate)
		// Verify logger is usable by ensuring no panic
		l.Info("test message")
	})

	t.Run("WithVaultPath", func(t *testing.T) {
		l := WithVaultPath(baseLogger, "secret/data/test")
		// Verify logger is usable by ensuring no panic
		l.Info("test message")
	})

	t.Run("WithVaultConnection", func(t *testing.T) {
		l := WithVaultConnection(baseLogger, "conn", "ns")
		// Verify logger is usable by ensuring no panic
		l.Info("test message")
	})

	t.Run("WithDuration", func(t *testing.T) {
		l := WithDuration(baseLogger, 5*time.Second)
		// Verify logger is usable by ensuring no panic
		l.Info("test message")
	})
}

func TestFromContext(t *testing.T) {
	// Test with logger in context
	expectedLogger := logr.Discard()
	ctx := log.IntoContext(context.Background(), expectedLogger)

	l := FromContext(ctx)
	// Verify logger is usable by ensuring no panic
	l.Info("test message")

	// Test with additional key-value pairs
	l = FromContext(ctx, "key", "value")
	// Verify logger is usable by ensuring no panic
	l.Info("test message with values")
}

func TestOperationConstants(t *testing.T) {
	ops := []string{OpCreate, OpUpdate, OpDelete, OpReconcile, OpFinalizer, OpValidate, OpConnect, OpDisconnect}

	for _, op := range ops {
		if op == "" {
			t.Errorf("operation constant should not be empty")
		}
	}
}

func TestKeyConstants(t *testing.T) {
	keys := []string{
		KeyController,
		KeyResource,
		KeyNamespace,
		KeyVaultPath,
		KeyVaultPolicy,
		KeyVaultRole,
		KeyOperation,
		KeyDuration,
		KeyReconcileID,
		KeyVaultConnection,
		KeyError,
		KeyRetryCount,
		KeyFinalizer,
	}

	for _, key := range keys {
		if key == "" {
			t.Errorf("key constant should not be empty")
		}
	}
}
