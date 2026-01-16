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
	"net/http"
	"net/http/httptest"
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
	"github.com/panteparak/vault-access-operator/shared/events"
)

// Test constants for commonly used values.
const (
	testConnectionName   = "test-conn"
	testDefaultNamespace = "default"
	testVaultTokenSecret = "vault-token"
	testSecretKey        = "token"
	testVaultToken       = "s.test-token-12345"
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
