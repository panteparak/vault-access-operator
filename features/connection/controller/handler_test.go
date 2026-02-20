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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/pkg/vault/token"
	"github.com/panteparak/vault-access-operator/shared/events"
)

// Test constants for commonly used values.
const (
	testConnectionName   = "test-conn"
	testDefaultNamespace = "default"
	testVaultTokenSecret = "vault-token"
	testSecretKey        = "token"
	testVaultToken       = "s.test-token-12345"
	testPreviousError    = "previous error"
)

// createScheme creates a runtime scheme with required types registered.
func createScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = vaultv1alpha1.AddToScheme(scheme)
	return scheme
}

// vaultConnectionOpts contains options for creating a test VaultConnection.
type vaultConnectionOpts struct {
	name            string
	address         string
	secretName      string
	secretNamespace string
	secretKey       string
}

// newVaultConnection creates a VaultConnection for testing with token auth.
func newVaultConnection(opts vaultConnectionOpts) *vaultv1alpha1.VaultConnection {
	// Apply defaults
	if opts.name == "" {
		opts.name = testConnectionName
	}
	if opts.secretName == "" {
		opts.secretName = testVaultTokenSecret
	}
	if opts.secretNamespace == "" {
		opts.secretNamespace = testDefaultNamespace
	}
	if opts.secretKey == "" {
		opts.secretKey = testSecretKey
	}

	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       opts.name,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: opts.address,
			Auth: vaultv1alpha1.AuthConfig{
				Token: &vaultv1alpha1.TokenAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name:      opts.secretName,
						Namespace: opts.secretNamespace,
						Key:       opts.secretKey,
					},
				},
			},
		},
	}
}

// tokenSecretOpts contains options for creating a test token Secret.
type tokenSecretOpts struct {
	namespace string
	key       string
	token     string
}

// newTokenSecret creates a Secret containing a Vault token.
func newTokenSecret(opts tokenSecretOpts) *corev1.Secret {
	// Apply defaults
	if opts.namespace == "" {
		opts.namespace = testDefaultNamespace
	}
	if opts.key == "" {
		opts.key = testSecretKey
	}
	if opts.token == "" {
		opts.token = testVaultToken
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testVaultTokenSecret,
			Namespace: opts.namespace,
		},
		Data: map[string][]byte{
			opts.key: []byte(opts.token),
		},
	}
}

// newMockVaultServer creates a mock Vault server for testing.
func newMockVaultServer(version string, healthErr bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if healthErr {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"initialized": true,
			"sealed":      false,
			"version":     version,
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
}

// TestNewHandler tests that NewHandler creates a handler with all fields set.
func TestNewHandler(t *testing.T) {
	scheme := createScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	if handler == nil {
		t.Fatal("expected handler to be non-nil")
		return // staticcheck: ensure no nil dereference warning
	}

	if handler.client == nil {
		t.Error("expected client to be set")
	}

	if handler.clientCache == nil {
		t.Error("expected clientCache to be set")
	}

	if handler.eventBus == nil {
		t.Error("expected eventBus to be set")
	}
}

// TestNewHandler_NilEventBus tests that NewHandler works with nil EventBus.
func TestNewHandler_NilEventBus(t *testing.T) {
	scheme := createScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	cache := vault.NewClientCache()
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: nil, Log: logger})

	if handler == nil {
		t.Fatal("expected handler to be non-nil")
		return // staticcheck: ensure no nil dereference warning
	}

	if handler.eventBus != nil {
		t.Error("expected eventBus to be nil")
	}
}

// TestSync_Success tests successful sync updates status to Active and stores client in cache.
func TestSync_Success(t *testing.T) {
	// Create mock Vault server
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status is Active
	if conn.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", conn.Status.Phase)
	}

	// Verify VaultVersion is set
	if conn.Status.VaultVersion != "1.15.0" {
		t.Errorf("expected VaultVersion '1.15.0', got %s", conn.Status.VaultVersion)
	}

	// Verify LastHeartbeat is set
	if conn.Status.LastHeartbeat == nil {
		t.Error("expected LastHeartbeat to be set")
	}

	// Verify client is stored in cache
	if !cache.Has("test-conn") {
		t.Error("expected client to be stored in cache")
	}

	// Verify Ready condition is set
	foundReadyCondition := false
	for _, c := range conn.Status.Conditions {
		if c.Type == vaultv1alpha1.ConditionTypeReady {
			foundReadyCondition = true
			if c.Status != metav1.ConditionTrue {
				t.Errorf("expected Ready condition status True, got %s", c.Status)
			}
			if c.Reason != vaultv1alpha1.ReasonSucceeded {
				t.Errorf("expected Ready condition reason Succeeded, got %s", c.Reason)
			}
		}
	}
	if !foundReadyCondition {
		t.Error("expected Ready condition to be set")
	}
}

// TestSync_AuthenticationError tests sync with authentication error returns error and updates status.
func TestSync_AuthenticationError(t *testing.T) {
	scheme := createScheme()
	// Create connection without corresponding secret - authentication will fail
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200", secretName: "nonexistent-secret"})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify status is Error
	if conn.Status.Phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", conn.Status.Phase)
	}

	// Verify Message is set
	if conn.Status.Message == "" {
		t.Error("expected Message to be set")
	}

	// Verify Ready condition is False
	foundReadyCondition := false
	for _, c := range conn.Status.Conditions {
		if c.Type == vaultv1alpha1.ConditionTypeReady {
			foundReadyCondition = true
			if c.Status != metav1.ConditionFalse {
				t.Errorf("expected Ready condition status False, got %s", c.Status)
			}
			if c.Reason != vaultv1alpha1.ReasonFailed {
				t.Errorf("expected Ready condition reason Failed, got %s", c.Reason)
			}
		}
	}
	if !foundReadyCondition {
		t.Error("expected Ready condition to be set")
	}

	// Verify client is NOT stored in cache
	if cache.Has("test-conn") {
		t.Error("expected client to NOT be stored in cache")
	}
}

// TestSync_VaultVersionError tests sync when Vault version retrieval fails.
func TestSync_VaultVersionError(t *testing.T) {
	// Create mock Vault server that returns error on health endpoint
	server := newMockVaultServer("", true)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify status is Error
	if conn.Status.Phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", conn.Status.Phase)
	}
}

// TestSync_WithTLSConfiguration tests sync with TLS configuration.
func TestSync_WithTLSConfiguration(t *testing.T) {
	// Create mock Vault server (TLS would require HTTPS, but we test with SkipVerify)
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})

	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-conn-tls",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: server.URL,
			TLS: &vaultv1alpha1.TLSConfig{
				SkipVerify: true,
			},
			Auth: vaultv1alpha1.AuthConfig{
				Token: &vaultv1alpha1.TokenAuth{
					SecretRef: vaultv1alpha1.SecretKeySelector{
						Name:      "vault-token",
						Namespace: "default",
						Key:       "token",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status is Active
	if conn.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", conn.Status.Phase)
	}

	// Verify client is stored in cache
	if !cache.Has("test-conn-tls") {
		t.Error("expected client to be stored in cache")
	}
}

// TestSync_PublishesConnectionReadyEvent tests that sync publishes ConnectionReady event.
func TestSync_PublishesConnectionReadyEvent(t *testing.T) {
	// Create mock Vault server
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())

	// Subscribe to capture the event
	var receivedEvent events.ConnectionReady
	var eventReceived bool
	var mu sync.Mutex

	events.Subscribe[events.ConnectionReady](bus, func(_ context.Context, e events.ConnectionReady) error {
		mu.Lock()
		receivedEvent = e
		eventReceived = true
		mu.Unlock()
		return nil
	})

	logger := logr.Discard()
	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for async event
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if !eventReceived {
		t.Fatal("expected ConnectionReady event to be published")
	}

	if receivedEvent.ConnectionName != "test-conn" {
		t.Errorf("expected ConnectionName 'test-conn', got %s", receivedEvent.ConnectionName)
	}

	if receivedEvent.VaultAddress != server.URL {
		t.Errorf("expected VaultAddress '%s', got %s", server.URL, receivedEvent.VaultAddress)
	}

	if receivedEvent.VaultVersion != "1.15.0" {
		t.Errorf("expected VaultVersion '1.15.0', got %s", receivedEvent.VaultVersion)
	}
}

// TestSync_NoEventBus tests that sync works without event bus (nil).
func TestSync_NoEventBus(t *testing.T) {
	// Create mock Vault server
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: nil, Log: logger}) // nil EventBus

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status is Active
	if conn.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", conn.Status.Phase)
	}
}

// TestSync_UpdatesPhaseToSyncing tests that sync updates phase to Syncing first.
func TestSync_UpdatesPhaseToSyncing(t *testing.T) {
	// Create mock Vault server
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})
	conn.Status.Phase = vaultv1alpha1.PhasePending // Start with Pending

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After successful sync, phase should be Active (went through Syncing)
	if conn.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", conn.Status.Phase)
	}
}

// TestCleanup_RemovesClientFromCache tests that cleanup removes client from cache.
func TestCleanup_RemovesClientFromCache(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	// Pre-populate the cache with a mock client
	vaultClient, _ := vault.NewClient(vault.ClientConfig{Address: "http://localhost:8200"})
	cache.Set("test-conn", vaultClient)

	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	// Verify client is in cache before cleanup
	if !cache.Has("test-conn") {
		t.Fatal("expected client to be in cache before cleanup")
	}

	ctx := context.Background()
	err := handler.Cleanup(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify client is removed from cache
	if cache.Has("test-conn") {
		t.Error("expected client to be removed from cache after cleanup")
	}
}

// TestCleanup_UpdatesStatusToDeleting tests that cleanup updates status to Deleting.
func TestCleanup_UpdatesStatusToDeleting(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})
	conn.Status.Phase = vaultv1alpha1.PhaseActive // Start with Active

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Cleanup(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status is Deleting
	if conn.Status.Phase != vaultv1alpha1.PhaseDeleting {
		t.Errorf("expected phase Deleting, got %s", conn.Status.Phase)
	}
}

// TestCleanup_PublishesConnectionDisconnectedEvent tests cleanup publishes ConnectionDisconnected event.
func TestCleanup_PublishesConnectionDisconnectedEvent(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())

	// Subscribe to capture the event
	var receivedEvent events.ConnectionDisconnected
	var eventReceived bool
	var mu sync.Mutex

	events.Subscribe[events.ConnectionDisconnected](bus, func(_ context.Context, e events.ConnectionDisconnected) error {
		mu.Lock()
		receivedEvent = e
		eventReceived = true
		mu.Unlock()
		return nil
	})

	logger := logr.Discard()
	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Cleanup(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for async event
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if !eventReceived {
		t.Fatal("expected ConnectionDisconnected event to be published")
	}

	if receivedEvent.ConnectionName != "test-conn" {
		t.Errorf("expected ConnectionName 'test-conn', got %s", receivedEvent.ConnectionName)
	}

	if receivedEvent.Reason != "resource deleted" {
		t.Errorf("expected Reason 'resource deleted', got %s", receivedEvent.Reason)
	}
}

// TestCleanup_NoEventBus tests that cleanup works without event bus (nil).
func TestCleanup_NoEventBus(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: nil, Log: logger}) // nil EventBus

	ctx := context.Background()
	err := handler.Cleanup(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status is Deleting
	if conn.Status.Phase != vaultv1alpha1.PhaseDeleting {
		t.Errorf("expected phase Deleting, got %s", conn.Status.Phase)
	}
}

// TestSetCondition_NewCondition tests setting a new condition.
func TestSetCondition_NewCondition(t *testing.T) {
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-conn",
			Generation: 1,
		},
	}

	handler := &Handler{}

	handler.setCondition(conn, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Connected to Vault")

	if len(conn.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conn.Status.Conditions))
	}

	c := conn.Status.Conditions[0]
	if c.Type != vaultv1alpha1.ConditionTypeReady {
		t.Errorf("expected condition type %s, got %s", vaultv1alpha1.ConditionTypeReady, c.Type)
	}

	if c.Status != metav1.ConditionTrue {
		t.Errorf("expected condition status True, got %s", c.Status)
	}

	if c.Reason != vaultv1alpha1.ReasonSucceeded {
		t.Errorf("expected condition reason %s, got %s", vaultv1alpha1.ReasonSucceeded, c.Reason)
	}

	if c.Message != "Connected to Vault" {
		t.Errorf("expected condition message 'Connected to Vault', got %s", c.Message)
	}

	if c.ObservedGeneration != 1 {
		t.Errorf("expected ObservedGeneration 1, got %d", c.ObservedGeneration)
	}

	if c.LastTransitionTime.IsZero() {
		t.Error("expected LastTransitionTime to be set")
	}
}

// TestSetCondition_UpdateExistingCondition_SameStatus tests updating an existing condition
// with same status (only updates reason/message).
func TestSetCondition_UpdateExistingCondition_SameStatus(t *testing.T) {
	originalTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-conn",
			Generation: 2,
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Conditions: []vaultv1alpha1.Condition{
				{
					Type:               vaultv1alpha1.ConditionTypeReady,
					Status:             metav1.ConditionTrue,
					LastTransitionTime: originalTime,
					Reason:             "OldReason",
					Message:            "Old message",
					ObservedGeneration: 1,
				},
			},
		},
	}

	handler := &Handler{}

	// Update with same status but different reason/message
	handler.setCondition(conn, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "New message")

	if len(conn.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conn.Status.Conditions))
	}

	c := conn.Status.Conditions[0]

	// Status should remain the same
	if c.Status != metav1.ConditionTrue {
		t.Errorf("expected condition status True, got %s", c.Status)
	}

	// Reason should be updated
	if c.Reason != vaultv1alpha1.ReasonSucceeded {
		t.Errorf("expected condition reason %s, got %s", vaultv1alpha1.ReasonSucceeded, c.Reason)
	}

	// Message should be updated
	if c.Message != "New message" {
		t.Errorf("expected condition message 'New message', got %s", c.Message)
	}

	// ObservedGeneration should be updated
	if c.ObservedGeneration != 2 {
		t.Errorf("expected ObservedGeneration 2, got %d", c.ObservedGeneration)
	}

	// LastTransitionTime should NOT be updated when status is the same
	if !c.LastTransitionTime.Equal(&originalTime) {
		t.Error("expected LastTransitionTime to remain unchanged when status is the same")
	}
}

// TestSetCondition_UpdateExistingCondition_DifferentStatus tests updating an existing condition
// with different status (updates all fields including LastTransitionTime).
func TestSetCondition_UpdateExistingCondition_DifferentStatus(t *testing.T) {
	originalTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-conn",
			Generation: 2,
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Conditions: []vaultv1alpha1.Condition{
				{
					Type:               vaultv1alpha1.ConditionTypeReady,
					Status:             metav1.ConditionTrue,
					LastTransitionTime: originalTime,
					Reason:             vaultv1alpha1.ReasonSucceeded,
					Message:            "Connected",
					ObservedGeneration: 1,
				},
			},
		},
	}

	handler := &Handler{}

	// Update with different status
	handler.setCondition(conn, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
		vaultv1alpha1.ReasonFailed, "Connection failed")

	if len(conn.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conn.Status.Conditions))
	}

	c := conn.Status.Conditions[0]

	// Status should be updated
	if c.Status != metav1.ConditionFalse {
		t.Errorf("expected condition status False, got %s", c.Status)
	}

	// Reason should be updated
	if c.Reason != vaultv1alpha1.ReasonFailed {
		t.Errorf("expected condition reason %s, got %s", vaultv1alpha1.ReasonFailed, c.Reason)
	}

	// Message should be updated
	if c.Message != "Connection failed" {
		t.Errorf("expected condition message 'Connection failed', got %s", c.Message)
	}

	// ObservedGeneration should be updated
	if c.ObservedGeneration != 2 {
		t.Errorf("expected ObservedGeneration 2, got %d", c.ObservedGeneration)
	}

	// LastTransitionTime should be updated when status changes
	if c.LastTransitionTime.Equal(&originalTime) {
		t.Error("expected LastTransitionTime to be updated when status changes")
	}
}

// TestSetCondition_MultipleConditions tests setting multiple different condition types.
func TestSetCondition_MultipleConditions(t *testing.T) {
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-conn",
			Generation: 1,
		},
	}

	handler := &Handler{}

	// Set first condition
	handler.setCondition(conn, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Ready")

	// Set second condition (different type)
	handler.setCondition(conn, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "Synced")

	if len(conn.Status.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(conn.Status.Conditions))
	}

	// Verify both conditions exist
	foundReady := false
	foundSynced := false
	for _, c := range conn.Status.Conditions {
		if c.Type == vaultv1alpha1.ConditionTypeReady {
			foundReady = true
		}
		if c.Type == vaultv1alpha1.ConditionTypeSynced {
			foundSynced = true
		}
	}

	if !foundReady {
		t.Error("expected Ready condition to be present")
	}

	if !foundSynced {
		t.Error("expected Synced condition to be present")
	}
}

// TestSync_SecretKeyNotFound tests sync when secret key is not found.
func TestSync_SecretKeyNotFound(t *testing.T) {
	scheme := createScheme()
	// Create secret with different key than expected
	secret := newTokenSecret(tokenSecretOpts{key: "wrong-key"})
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify status is Error
	if conn.Status.Phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", conn.Status.Phase)
	}
}

// TestSync_DefaultSecretNamespace tests that default namespace is used when not specified.
func TestSync_DefaultSecretNamespace(t *testing.T) {
	// Create mock Vault server
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	// Create secret in default namespace
	secret := newTokenSecret(tokenSecretOpts{})
	// Create connection with empty namespace (should default to "default")
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL, secretNamespace: ""})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status is Active (secret was found using default namespace)
	if conn.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", conn.Status.Phase)
	}
}

// TestSync_NoAuthMethodConfigured tests sync when no auth method is configured.
func TestSync_NoAuthMethodConfigured(t *testing.T) {
	scheme := createScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-conn",
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "http://localhost:8200",
			Auth:    vaultv1alpha1.AuthConfig{}, // No auth method configured
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify status is Error
	if conn.Status.Phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", conn.Status.Phase)
	}

	// Verify error message mentions no authentication method
	if conn.Status.Message == "" {
		t.Error("expected error message to be set")
	}
}

// TestSync_StatusMessageCleared tests that status message is cleared on successful sync.
func TestSync_StatusMessageCleared(t *testing.T) {
	// Create mock Vault server
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})
	conn.Status.Phase = vaultv1alpha1.PhaseError
	conn.Status.Message = "Previous error message"

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status message is cleared
	if conn.Status.Message != "" {
		t.Errorf("expected empty status message, got %s", conn.Status.Message)
	}
}

// TestCleanup_CleanupWithoutClientInCache tests cleanup when client is not in cache.
func TestCleanup_CleanupWithoutClientInCache(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	// Do NOT pre-populate the cache

	bus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logger})

	ctx := context.Background()
	err := handler.Cleanup(ctx, conn)

	// Cleanup should succeed even if client is not in cache
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status is Deleting
	if conn.Status.Phase != vaultv1alpha1.PhaseDeleting {
		t.Errorf("expected phase Deleting, got %s", conn.Status.Phase)
	}
}

// --- Phase 6: Ordered cascading deletion tests ---

func TestCleanup_BlockedByDependentPolicies(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})

	// Create a VaultPolicy that references this connection
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: testConnectionName,
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/data/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, policy).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(HandlerConfig{Client: k8sClient, ClientCache: cache, EventBus: bus, Log: logr.Discard()})

	ctx := context.Background()
	err := handler.Cleanup(ctx, conn)

	if err == nil {
		t.Fatal("expected error when dependents exist")
	}
	if !strings.Contains(err.Error(), "deletion blocked") {
		t.Errorf("expected 'deletion blocked' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "VaultPolicy/default/test-policy") {
		t.Errorf("expected dependent listed in error, got: %v", err)
	}
}

func TestCleanup_NoDependents(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})

	// No dependent resources
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(HandlerConfig{Client: k8sClient, ClientCache: cache, EventBus: bus, Log: logr.Discard()})

	ctx := context.Background()
	err := handler.Cleanup(ctx, conn)

	if err != nil {
		t.Fatalf("expected no error when no dependents, got: %v", err)
	}
	if conn.Status.Phase != vaultv1alpha1.PhaseDeleting {
		t.Errorf("expected phase Deleting, got %s", conn.Status.Phase)
	}
}

func TestCleanup_BlockedByMixedDependents(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})

	// Create a VaultPolicy and a VaultRole referencing this connection
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-policy",
			Namespace: "production",
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: testConnectionName,
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/data/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-role",
			Namespace: "staging",
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   testConnectionName,
			ServiceAccounts: []string{"app"},
			Policies:        []vaultv1alpha1.PolicyReference{{Name: "default"}},
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn, policy, role).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(HandlerConfig{Client: k8sClient, ClientCache: cache, EventBus: bus, Log: logr.Discard()})

	ctx := context.Background()
	err := handler.Cleanup(ctx, conn)

	if err == nil {
		t.Fatal("expected error when dependents exist")
	}
	if !strings.Contains(err.Error(), "2 dependent resource(s)") {
		t.Errorf("expected '2 dependent resource(s)' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "VaultPolicy/production/my-policy") {
		t.Errorf("expected VaultPolicy listed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "VaultRole/staging/my-role") {
		t.Errorf("expected VaultRole listed, got: %v", err)
	}
}

// --- Enhanced mock Vault server for getOrRenewClient tests ---

// mockVaultServerOpts configures the multi-endpoint mock Vault server.
type mockVaultServerOpts struct {
	version       string
	healthErr     bool
	renewErr      bool
	renewLeaseTTL int // lease_duration in renew-self response
}

// newMultiEndpointVaultServer creates a mock Vault server that handles
// /v1/sys/health and /v1/auth/token/renew-self with configurable behavior.
func newMultiEndpointVaultServer(opts mockVaultServerOpts) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/sys/health"):
			if opts.healthErr {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"initialized": true,
				"sealed":      false,
				"version":     opts.version,
			})

		case strings.HasSuffix(r.URL.Path, "/v1/auth/token/renew-self"):
			if opts.renewErr {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"errors": []string{"permission denied"},
				})
				return
			}
			ttl := opts.renewLeaseTTL
			if ttl == 0 {
				ttl = 3600
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.renewed-token",
					"lease_duration": ttl,
					"renewable":      true,
				},
			})

		default:
			// Default health response for any other path
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"initialized": true,
				"sealed":      false,
				"version":     opts.version,
			})
		}
	}))
}

// newCachedVaultClient creates an authenticated vault.Client for cache pre-population.
func newCachedVaultClient(
	t *testing.T, address string,
	expiration time.Time, ttl time.Duration,
) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: address})
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	c.SetAuthenticated(true)
	c.SetTokenExpiration(expiration)
	c.SetTokenTTL(ttl)
	c.SetToken(testVaultToken)
	return c
}

// --- getOrRenewClient tests ---

// TestGetOrRenewClient_CacheHit_FreshToken tests that a cached client with
// a fresh token (well within TTL) is reused without renewal.
func TestGetOrRenewClient_CacheHit_FreshToken(t *testing.T) {
	server := newMultiEndpointVaultServer(mockVaultServerOpts{version: "1.15.0"})
	defer server.Close()

	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()

	// Pre-populate cache: token expires in 1 hour, TTL is 1 hour
	// remaining (1h) > threshold (0.25 * 1h = 15min) → fresh
	cachedClient := newCachedVaultClient(
		t, server.URL, time.Now().Add(time.Hour), time.Hour,
	)
	cache.Set(testConnectionName, cachedClient)

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if renewed {
		t.Error("expected renewed=false for fresh token")
	}
	// Should return the exact same cached client
	if client != cachedClient {
		t.Error("expected to return the cached client instance")
	}
}

// TestGetOrRenewClient_CacheHit_RenewalThreshold tests that a cached client
// approaching TTL expiration triggers a renewal via RenewSelf.
func TestGetOrRenewClient_CacheHit_RenewalThreshold(t *testing.T) {
	server := newMultiEndpointVaultServer(mockVaultServerOpts{
		version:       "1.15.0",
		renewLeaseTTL: 3600, // 1 hour renewed TTL
	})
	defer server.Close()

	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()

	// Pre-populate cache: token expires in 10 minutes, TTL is 1 hour
	// remaining (10min) < threshold (0.25 * 1h = 15min) → needs renewal
	cachedClient := newCachedVaultClient(
		t, server.URL, time.Now().Add(10*time.Minute), time.Hour,
	)
	cache.Set(testConnectionName, cachedClient)

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !renewed {
		t.Error("expected renewed=true when token is within renewal threshold")
	}
	// Should return the same cached client (renewed in-place)
	if client != cachedClient {
		t.Error("expected to return the same cached client after renewal")
	}
}

// TestGetOrRenewClient_CacheHit_RenewalFails_ReAuth tests that when token
// renewal fails, the handler falls back to full re-authentication.
func TestGetOrRenewClient_CacheHit_RenewalFails_ReAuth(t *testing.T) {
	server := newMultiEndpointVaultServer(mockVaultServerOpts{
		version:  "1.15.0",
		renewErr: true, // Renewal will fail
	})
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()

	// Pre-populate cache: within renewal threshold
	cachedClient := newCachedVaultClient(
		t, server.URL, time.Now().Add(10*time.Minute), time.Hour,
	)
	cache.Set(testConnectionName, cachedClient)

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !renewed {
		t.Error("expected renewed=true (wasReauth) when renewal fails and re-auth succeeds")
	}
	// Should return a NEW client, not the cached one
	if client == cachedClient {
		t.Error("expected a new client after re-authentication, got cached client")
	}
}

// TestGetOrRenewClient_CacheHit_TokenExpired_ReAuth tests that an expired
// cached token triggers full re-authentication.
func TestGetOrRenewClient_CacheHit_TokenExpired_ReAuth(t *testing.T) {
	server := newMultiEndpointVaultServer(mockVaultServerOpts{version: "1.15.0"})
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()

	// Pre-populate cache: token already expired (5 minutes ago)
	cachedClient := newCachedVaultClient(
		t, server.URL, time.Now().Add(-5*time.Minute), time.Hour,
	)
	cache.Set(testConnectionName, cachedClient)

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !renewed {
		t.Error("expected renewed=true (wasReauth) when token is expired")
	}
	// Should return a NEW client
	if client == cachedClient {
		t.Error("expected a new client after re-authentication, got cached client")
	}
}

// TestGetOrRenewClient_CacheHit_StaticToken tests that a cached client
// with no expiration info (e.g., static token) is reused directly.
func TestGetOrRenewClient_CacheHit_StaticToken(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()

	// Pre-populate cache: zero expiration and zero TTL = static token
	cachedClient := newCachedVaultClient(
		t, "http://localhost:8200", time.Time{}, 0,
	)
	cache.Set(testConnectionName, cachedClient)

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if renewed {
		t.Error("expected renewed=false for static token")
	}
	if client != cachedClient {
		t.Error("expected to return the cached client for static token")
	}
}

// TestGetOrRenewClient_CacheHit_AddressMismatch tests that when the cached
// client's address differs from the connection spec, a new client is created.
func TestGetOrRenewClient_CacheHit_AddressMismatch(t *testing.T) {
	server := newMultiEndpointVaultServer(mockVaultServerOpts{version: "1.15.0"})
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	// Connection points to the mock server
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()

	// Pre-populate cache: client points to a DIFFERENT address
	cachedClient := newCachedVaultClient(
		t, "http://old-vault:8200",
		time.Now().Add(time.Hour), time.Hour,
	)
	cache.Set(testConnectionName, cachedClient)

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Address mismatch means the cached client wasn't used
	// wasReauth = true because cachedClient existed and was authenticated
	if !renewed {
		t.Error("expected renewed=true (wasReauth) due to address mismatch")
	}
	if client == cachedClient {
		t.Error("expected a new client when address changed")
	}
}

// TestGetOrRenewClient_CacheMiss_FreshAuth tests that when no client exists
// in cache, a new one is built and authenticated.
func TestGetOrRenewClient_CacheMiss_FreshAuth(t *testing.T) {
	server := newMultiEndpointVaultServer(mockVaultServerOpts{version: "1.15.0"})
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	// Cache is empty - no pre-population

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if renewed {
		t.Error("expected renewed=false for first-time auth (no prior cached client)")
	}
	if client == nil {
		t.Error("expected non-nil client from fresh auth")
	}
}

// TestGetOrRenewClient_CacheMiss_AuthError tests error propagation when
// buildAndAuthenticateClient fails (e.g., secret not found).
func TestGetOrRenewClient_CacheMiss_AuthError(t *testing.T) {
	scheme := createScheme()
	// No secret created → authentication will fail
	conn := newVaultConnection(vaultConnectionOpts{
		address:    "http://localhost:8200",
		secretName: "nonexistent-secret",
	})

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err == nil {
		t.Fatal("expected error when secret is missing, got nil")
	}
	if renewed {
		t.Error("expected renewed=false on error")
	}
	if client != nil {
		t.Error("expected nil client on error")
	}
}

// --- Phase oscillation tests ---

// TestSync_ErrorPhaseResetToSyncing documents that Error phase is reset to
// Syncing at the start of each Sync() call (handler.go:105-106), then set
// back to Error by handleSyncError. The final phase after a failed sync is
// always Error, but there's a transient Syncing state in between.
func TestSync_ErrorPhaseResetToSyncing(t *testing.T) {
	scheme := createScheme()
	// No secret → auth will fail
	conn := newVaultConnection(vaultConnectionOpts{
		address:    "http://localhost:8200",
		secretName: "nonexistent-secret",
	})
	conn.Status.Phase = vaultv1alpha1.PhaseError // Start in Error phase
	conn.Status.Message = testPreviousError

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err == nil {
		t.Fatal("expected error when secret is missing")
	}

	// After failed sync, phase should be Error again
	// (it was temporarily set to Syncing by line 105-106, then
	// back to Error by handleSyncError)
	if conn.Status.Phase != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error after failed sync, got %s",
			conn.Status.Phase)
	}
}

// TestSync_ActivePhaseNotResetToSyncing verifies that Sync() does NOT reset
// the phase to Syncing when it's already Active (handler.go:105 condition).
func TestSync_ActivePhaseNotResetToSyncing(t *testing.T) {
	server := newMultiEndpointVaultServer(mockVaultServerOpts{version: "1.15.0"})
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})
	conn.Status.Phase = vaultv1alpha1.PhaseActive // Start in Active phase

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		EventBus:    bus,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Phase should remain Active (the condition on line 105 skips
	// resetting when already Active or Syncing)
	if conn.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", conn.Status.Phase)
	}
}

// --- Health monitoring tests ---

// TestSync_SetsHealthyStatusOnSuccess tests that successful sync sets healthy status.
func TestSync_SetsHealthyStatusOnSuccess(t *testing.T) {
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logr.Discard()})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify health status fields
	if !conn.Status.Healthy {
		t.Error("expected Healthy to be true")
	}

	if conn.Status.LastHealthCheck == nil {
		t.Error("expected LastHealthCheck to be set")
	}

	if conn.Status.LastHealthyTime == nil {
		t.Error("expected LastHealthyTime to be set")
	}

	if conn.Status.HealthCheckError != "" {
		t.Errorf("expected empty HealthCheckError, got %s", conn.Status.HealthCheckError)
	}

	if conn.Status.ConsecutiveFails != 0 {
		t.Errorf("expected ConsecutiveFails to be 0, got %d", conn.Status.ConsecutiveFails)
	}
}

// TestSync_SetsUnhealthyStatusOnHealthCheckError tests that health check failure sets unhealthy status.
func TestSync_SetsUnhealthyStatusOnHealthCheckError(t *testing.T) {
	// Create mock Vault server that returns error
	server := newMockVaultServer("", true)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logr.Discard()})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify health status fields
	if conn.Status.Healthy {
		t.Error("expected Healthy to be false")
	}

	if conn.Status.LastHealthCheck == nil {
		t.Error("expected LastHealthCheck to be set")
	}

	// LastHealthyTime should NOT be set on failure
	if conn.Status.LastHealthyTime != nil {
		t.Error("expected LastHealthyTime to be nil on health check failure")
	}

	if conn.Status.HealthCheckError == "" {
		t.Error("expected HealthCheckError to be set")
	}

	if conn.Status.ConsecutiveFails != 1 {
		t.Errorf("expected ConsecutiveFails to be 1, got %d", conn.Status.ConsecutiveFails)
	}
}

// TestSync_IncrementsConsecutiveFailsOnRepeatedFailures tests that consecutive failures are tracked.
func TestSync_IncrementsConsecutiveFailsOnRepeatedFailures(t *testing.T) {
	// Create mock Vault server that returns error
	server := newMockVaultServer("", true)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})
	// Simulate previous failures
	conn.Status.ConsecutiveFails = 3

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logr.Discard()})

	ctx := context.Background()
	_ = handler.Sync(ctx, conn)

	// Should increment from 3 to 4
	if conn.Status.ConsecutiveFails != 4 {
		t.Errorf("expected ConsecutiveFails to be 4, got %d", conn.Status.ConsecutiveFails)
	}
}

// TestSync_ResetsConsecutiveFailsOnSuccess tests that consecutive fails reset on success.
func TestSync_ResetsConsecutiveFailsOnSuccess(t *testing.T) {
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})
	// Simulate previous failures
	conn.Status.ConsecutiveFails = 5
	conn.Status.HealthCheckError = testPreviousError
	conn.Status.Healthy = false

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logr.Discard()})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should reset to 0
	if conn.Status.ConsecutiveFails != 0 {
		t.Errorf("expected ConsecutiveFails to be 0, got %d", conn.Status.ConsecutiveFails)
	}

	// Error should be cleared
	if conn.Status.HealthCheckError != "" {
		t.Errorf("expected HealthCheckError to be empty, got %s", conn.Status.HealthCheckError)
	}

	// Should be healthy now
	if !conn.Status.Healthy {
		t.Error("expected Healthy to be true")
	}
}

// TestSync_UpdatesLastHealthyTimeOnSuccess tests that LastHealthyTime is updated on success.
func TestSync_UpdatesLastHealthyTimeOnSuccess(t *testing.T) {
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	// Set previous LastHealthyTime to verify it gets updated
	oldTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	conn.Status.LastHealthyTime = &oldTime

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(HandlerConfig{Client: client, ClientCache: cache, EventBus: bus, Log: logr.Discard()})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// LastHealthyTime should be updated to a more recent time
	if conn.Status.LastHealthyTime == nil {
		t.Fatal("expected LastHealthyTime to be set")
	}

	if !conn.Status.LastHealthyTime.After(oldTime.Time) {
		t.Error("expected LastHealthyTime to be updated to a more recent time")
	}
}

// TestUpdateHealthStatus_Healthy tests updateHealthStatus with healthy=true.
func TestUpdateHealthStatus_Healthy(t *testing.T) {
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-conn",
			Generation: 1,
		},
	}
	// Set previous unhealthy state
	conn.Status.Healthy = false
	conn.Status.ConsecutiveFails = 5
	conn.Status.HealthCheckError = testPreviousError

	handler := &Handler{}
	handler.updateHealthStatus(conn, true, "")

	if !conn.Status.Healthy {
		t.Error("expected Healthy to be true")
	}

	if conn.Status.ConsecutiveFails != 0 {
		t.Errorf("expected ConsecutiveFails to be 0, got %d", conn.Status.ConsecutiveFails)
	}

	if conn.Status.HealthCheckError != "" {
		t.Errorf("expected HealthCheckError to be empty, got %s", conn.Status.HealthCheckError)
	}

	if conn.Status.LastHealthyTime == nil {
		t.Error("expected LastHealthyTime to be set")
	}
}

// TestUpdateHealthStatus_Unhealthy tests updateHealthStatus with healthy=false.
func TestUpdateHealthStatus_Unhealthy(t *testing.T) {
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-conn",
			Generation: 1,
		},
	}
	// Set previous state
	conn.Status.ConsecutiveFails = 2

	handler := &Handler{}
	handler.updateHealthStatus(conn, false, "connection refused")

	if conn.Status.Healthy {
		t.Error("expected Healthy to be false")
	}

	if conn.Status.ConsecutiveFails != 3 {
		t.Errorf("expected ConsecutiveFails to be 3, got %d", conn.Status.ConsecutiveFails)
	}

	if conn.Status.HealthCheckError != "connection refused" {
		t.Errorf("expected HealthCheckError to be 'connection refused', got %s", conn.Status.HealthCheckError)
	}
}

// TestHandleSyncError_SetsHealthStatus tests that handleSyncError updates health status.
func TestHandleSyncError_SetsHealthStatus(t *testing.T) {
	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: "http://localhost:8200"})

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	handler := NewHandler(HandlerConfig{Client: client, ClientCache: vault.NewClientCache(), Log: logr.Discard()})

	ctx := context.Background()
	testErr := fmt.Errorf("test error")
	_ = handler.handleSyncError(ctx, conn, testErr)

	// Verify health status is set
	if conn.Status.Healthy {
		t.Error("expected Healthy to be false after error")
	}

	if conn.Status.LastHealthCheck == nil {
		t.Error("expected LastHealthCheck to be set after error")
	}

	if conn.Status.ConsecutiveFails != 1 {
		t.Errorf("expected ConsecutiveFails to be 1, got %d", conn.Status.ConsecutiveFails)
	}
}

// --- RenewalStrategyReauth tests ---

// mockTokenProvider implements token.TokenProvider for testing.
type mockTokenProvider struct{}

func (m *mockTokenProvider) GetToken(_ context.Context, _ token.GetTokenOptions) (*token.TokenInfo, error) {
	return &token.TokenInfo{
		Token:          "mock-sa-jwt-token",
		ExpirationTime: time.Now().Add(time.Hour),
		IssuedAt:       time.Now(),
	}, nil
}

// newK8sAuthVaultServer creates a mock Vault server that additionally handles
// the Kubernetes auth login endpoint (POST /v1/auth/kubernetes/login).
func newK8sAuthVaultServer(opts mockVaultServerOpts) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/sys/health"):
			if opts.healthErr {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"initialized": true,
				"sealed":      false,
				"version":     opts.version,
			})

		case strings.HasSuffix(r.URL.Path, "/v1/auth/token/renew-self"):
			if opts.renewErr {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"errors": []string{"permission denied"},
				})
				return
			}
			ttl := opts.renewLeaseTTL
			if ttl == 0 {
				ttl = 3600
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.renewed-token",
					"lease_duration": ttl,
					"renewable":      true,
				},
			})

		case strings.HasSuffix(r.URL.Path, "/v1/auth/kubernetes/login"):
			// Mock K8s auth login — returns a valid client token
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.k8s-auth-token",
					"lease_duration": 3600,
					"renewable":      true,
				},
			})

		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"initialized": true,
				"sealed":      false,
				"version":     opts.version,
			})
		}
	}))
}

// TestGetOrRenewClient_RenewalStrategyReauth tests that when RenewalStrategyReauth
// is configured, the handler skips RenewSelf and goes straight to re-authentication.
func TestGetOrRenewClient_RenewalStrategyReauth(t *testing.T) {
	server := newK8sAuthVaultServer(mockVaultServerOpts{
		version:       "1.15.0",
		renewLeaseTTL: 3600,
	})
	defer server.Close()

	scheme := createScheme()

	// Create connection with ONLY Kubernetes auth and RenewalStrategyReauth
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testConnectionName,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: server.URL,
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{
					Role:            "test-role",
					RenewalStrategy: vaultv1alpha1.RenewalStrategyReauth,
				},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()

	// Pre-populate cache: token within renewal threshold (10min remaining, 1h TTL)
	cachedClient := newCachedVaultClient(
		t, server.URL, time.Now().Add(10*time.Minute), time.Hour,
	)
	cache.Set(testConnectionName, cachedClient)

	handler := NewHandler(HandlerConfig{
		Client:        k8sClient,
		ClientCache:   cache,
		TokenProvider: &mockTokenProvider{},
		Log:           logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !renewed {
		t.Error("expected renewed=true (wasReauth) when reauth strategy is used")
	}
	// With reauth strategy, it should skip RenewSelf and create a new client
	if client == cachedClient {
		t.Error("expected a new client (re-authenticated), not the cached client")
	}
}

// TestGetOrRenewClient_RenewalStrategyRenew_Default tests the default renewal
// strategy (renew) still works as expected — RenewSelf is called.
func TestGetOrRenewClient_RenewalStrategyRenew_Default(t *testing.T) {
	server := newMultiEndpointVaultServer(mockVaultServerOpts{
		version:       "1.15.0",
		renewLeaseTTL: 3600,
	})
	defer server.Close()

	scheme := createScheme()

	// Connection with Kubernetes auth and default/explicit RenewalStrategyRenew
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testConnectionName,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: server.URL,
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{
					Role:            "test-role",
					RenewalStrategy: vaultv1alpha1.RenewalStrategyRenew,
				},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()

	// Pre-populate cache: within renewal threshold
	cachedClient := newCachedVaultClient(
		t, server.URL, time.Now().Add(10*time.Minute), time.Hour,
	)
	cache.Set(testConnectionName, cachedClient)

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !renewed {
		t.Error("expected renewed=true for renew strategy with RenewSelf")
	}
	// With renew strategy, RenewSelf updates in-place → same client instance
	if client != cachedClient {
		t.Error("expected same cached client after RenewSelf renewal")
	}
}

// TestGetOrRenewClient_RenewalStrategyReauth_NilKubernetes tests that when
// Kubernetes auth is nil, the renewal proceeds normally (shouldTryRenew=true).
func TestGetOrRenewClient_RenewalStrategyReauth_NilKubernetes(t *testing.T) {
	server := newMultiEndpointVaultServer(mockVaultServerOpts{
		version:       "1.15.0",
		renewLeaseTTL: 3600,
	})
	defer server.Close()

	scheme := createScheme()
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})
	// Default newVaultConnection uses Token auth, Kubernetes is nil

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()

	// Pre-populate cache: within renewal threshold
	cachedClient := newCachedVaultClient(
		t, server.URL, time.Now().Add(10*time.Minute), time.Hour,
	)
	cache.Set(testConnectionName, cachedClient)

	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	client, renewed, err := handler.getOrRenewClient(ctx, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !renewed {
		t.Error("expected renewed=true (should try RenewSelf when Kubernetes is nil)")
	}
	// RenewSelf updates in-place → same client instance
	if client != cachedClient {
		t.Error("expected same cached client after RenewSelf")
	}
}

// TestSync_RecoveryFromErrorPhase tests that a connection can recover from
// PhaseError back to PhaseActive when the underlying issue is resolved.
func TestSync_RecoveryFromErrorPhase(t *testing.T) {
	server := newMockVaultServer("1.15.0", false)
	defer server.Close()

	scheme := createScheme()
	secret := newTokenSecret(tokenSecretOpts{})
	conn := newVaultConnection(vaultConnectionOpts{address: server.URL})

	// Start in Error phase with previous failure state
	conn.Status.Phase = vaultv1alpha1.PhaseError
	conn.Status.Message = testPreviousError
	conn.Status.ConsecutiveFails = 3
	conn.Status.HealthCheckError = "previous vault unreachable"
	conn.Status.Healthy = false

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, conn).
		WithStatusSubresource(conn).
		Build()

	cache := vault.NewClientCache()
	bus := events.NewEventBus(logr.Discard())
	handler := NewHandler(HandlerConfig{
		Client:      k8sClient,
		ClientCache: cache,
		EventBus:    bus,
		Log:         logr.Discard(),
	})

	ctx := context.Background()
	err := handler.Sync(ctx, conn)

	if err != nil {
		t.Fatalf("expected recovery to succeed, got error: %v", err)
	}
	if conn.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected PhaseActive after recovery, got %s", conn.Status.Phase)
	}
	if !conn.Status.Healthy {
		t.Error("expected Healthy=true after recovery")
	}
	if conn.Status.ConsecutiveFails != 0 {
		t.Errorf("expected ConsecutiveFails=0 after recovery, got %d", conn.Status.ConsecutiveFails)
	}
	if conn.Status.HealthCheckError != "" {
		t.Errorf("expected empty HealthCheckError after recovery, got %q", conn.Status.HealthCheckError)
	}
}
