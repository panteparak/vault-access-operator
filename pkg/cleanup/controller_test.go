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

package cleanup

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// mockVaultClient implements the VaultClient interface for testing
type mockVaultClient struct {
	deletePolicyErr error
	deleteRoleErr   error
	deletedPolicies []string
	deletedRoles    []string
	mu              sync.Mutex
}

func (m *mockVaultClient) DeletePolicy(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deletePolicyErr != nil {
		return m.deletePolicyErr
	}
	m.deletedPolicies = append(m.deletedPolicies, name)
	return nil
}

func (m *mockVaultClient) DeleteKubernetesAuthRole(ctx context.Context, authPath, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteRoleErr != nil {
		return m.deleteRoleErr
	}
	m.deletedRoles = append(m.deletedRoles, authPath+"/"+name)
	return nil
}

// mockClientCache implements the ClientCache interface for testing
type mockClientCache struct {
	client *mockVaultClient
	getErr error
}

func (m *mockClientCache) Get(name string) (VaultClient, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.client, nil
}

func newTestLogger() logr.Logger {
	return zap.New(zap.UseDevMode(true))
}

func TestNewController(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	clientCache := &mockClientCache{client: &mockVaultClient{}}

	cfg := ControllerConfig{
		Queue:       queue,
		ClientCache: clientCache,
		Log:         newTestLogger(),
	}

	c := NewController(cfg)

	if c == nil {
		t.Fatal("NewController returned nil")
	}
	if c.interval != DefaultRetryInterval {
		t.Errorf("Expected default interval %v, got %v", DefaultRetryInterval, c.interval)
	}
	if c.maxAttempts != DefaultMaxAttempts {
		t.Errorf("Expected default maxAttempts %d, got %d", DefaultMaxAttempts, c.maxAttempts)
	}
}

func TestNewController_WithCustomConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	clientCache := &mockClientCache{client: &mockVaultClient{}}

	cfg := ControllerConfig{
		Queue:       queue,
		ClientCache: clientCache,
		Interval:    10 * time.Minute,
		MaxAttempts: 5,
		Log:         newTestLogger(),
	}

	c := NewController(cfg)

	if c.interval != 10*time.Minute {
		t.Errorf("Expected interval 10m, got %v", c.interval)
	}
	if c.maxAttempts != 5 {
		t.Errorf("Expected maxAttempts 5, got %d", c.maxAttempts)
	}
}

func TestController_ProcessItem_Policy_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	mockClient := &mockVaultClient{}
	clientCache := &mockClientCache{client: mockClient}

	c := &Controller{
		queue:       queue,
		clientCache: clientCache,
		maxAttempts: 10,
		log:         newTestLogger(),
	}

	item := Item{
		ID:             "test-id",
		ResourceType:   ResourceTypePolicy,
		VaultName:      "test-policy",
		ConnectionName: "vault-connection",
	}

	ctx := context.Background()
	err := c.processItem(ctx, item)

	if err != nil {
		t.Errorf("processItem failed: %v", err)
	}

	if len(mockClient.deletedPolicies) != 1 {
		t.Errorf("Expected 1 deleted policy, got %d", len(mockClient.deletedPolicies))
	}
	if mockClient.deletedPolicies[0] != "test-policy" {
		t.Errorf("Expected deleted policy 'test-policy', got %s", mockClient.deletedPolicies[0])
	}
}

func TestController_ProcessItem_Role_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	mockClient := &mockVaultClient{}
	clientCache := &mockClientCache{client: mockClient}

	c := &Controller{
		queue:       queue,
		clientCache: clientCache,
		maxAttempts: 10,
		log:         newTestLogger(),
	}

	item := Item{
		ID:             "test-id",
		ResourceType:   ResourceTypeRole,
		VaultName:      "test-role",
		ConnectionName: "vault-connection",
		AuthPath:       "kubernetes",
	}

	ctx := context.Background()
	err := c.processItem(ctx, item)

	if err != nil {
		t.Errorf("processItem failed: %v", err)
	}

	if len(mockClient.deletedRoles) != 1 {
		t.Errorf("Expected 1 deleted role, got %d", len(mockClient.deletedRoles))
	}
	if mockClient.deletedRoles[0] != "kubernetes/test-role" {
		t.Errorf("Expected deleted role 'kubernetes/test-role', got %s", mockClient.deletedRoles[0])
	}
}

func TestController_ProcessItem_PolicyDeleteError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	mockClient := &mockVaultClient{deletePolicyErr: errors.New("vault unreachable")}
	clientCache := &mockClientCache{client: mockClient}

	c := &Controller{
		queue:       queue,
		clientCache: clientCache,
		maxAttempts: 10,
		log:         newTestLogger(),
	}

	item := Item{
		ID:             "test-id",
		ResourceType:   ResourceTypePolicy,
		VaultName:      "test-policy",
		ConnectionName: "vault-connection",
	}

	ctx := context.Background()
	err := c.processItem(ctx, item)

	if err == nil {
		t.Error("Expected error, got nil")
	}
	if err.Error() != "vault unreachable" {
		t.Errorf("Expected error 'vault unreachable', got %s", err.Error())
	}
}

func TestController_ProcessItem_ClientCacheError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	clientCache := &mockClientCache{getErr: errors.New("connection not found")}

	c := &Controller{
		queue:       queue,
		clientCache: clientCache,
		maxAttempts: 10,
		log:         newTestLogger(),
	}

	item := Item{
		ID:             "test-id",
		ResourceType:   ResourceTypePolicy,
		VaultName:      "test-policy",
		ConnectionName: "unknown-connection",
	}

	ctx := context.Background()
	err := c.processItem(ctx, item)

	if err == nil {
		t.Error("Expected error, got nil")
	}
	if err.Error() != "connection not found" {
		t.Errorf("Expected error 'connection not found', got %s", err.Error())
	}
}

func TestController_ProcessItem_UnknownResourceType(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	mockClient := &mockVaultClient{}
	clientCache := &mockClientCache{client: mockClient}

	c := &Controller{
		queue:       queue,
		clientCache: clientCache,
		maxAttempts: 10,
		log:         newTestLogger(),
	}

	item := Item{
		ID:             "test-id",
		ResourceType:   "unknown",
		VaultName:      "test-resource",
		ConnectionName: "vault-connection",
	}

	ctx := context.Background()
	err := c.processItem(ctx, item)

	// Unknown resource types should not error - they're just skipped
	if err != nil {
		t.Errorf("Expected no error for unknown resource type, got: %v", err)
	}
}

func TestController_ProcessQueue_SuccessfulCleanup(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	mockClient := &mockVaultClient{}
	clientCache := &mockClientCache{client: mockClient}

	c := &Controller{
		queue:       queue,
		clientCache: clientCache,
		maxAttempts: 10,
		log:         newTestLogger(),
		interval:    time.Second,
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
	}

	ctx := context.Background()

	// Enqueue an item
	item := NewPolicyCleanupItem("test-policy", "vault-connection", "default", "my-policy", "error")
	err := queue.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}

	// Process queue
	c.processQueue(ctx)

	// Item should be removed (successful cleanup)
	size, _ := queue.Size(ctx)
	if size != 0 {
		t.Errorf("Expected queue size 0 after successful cleanup, got %d", size)
	}

	// Verify policy was deleted
	if len(mockClient.deletedPolicies) != 1 {
		t.Errorf("Expected 1 deleted policy, got %d", len(mockClient.deletedPolicies))
	}
}

func TestController_ProcessQueue_FailedCleanup(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	mockClient := &mockVaultClient{deletePolicyErr: errors.New("vault error")}
	clientCache := &mockClientCache{client: mockClient}

	c := &Controller{
		queue:       queue,
		clientCache: clientCache,
		maxAttempts: 10,
		log:         newTestLogger(),
		interval:    time.Second,
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
	}

	ctx := context.Background()

	// Enqueue an item
	item := NewPolicyCleanupItem("test-policy", "vault-connection", "default", "my-policy", "initial error")
	err := queue.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}

	// Process queue
	c.processQueue(ctx)

	// Item should still be in queue with updated attempt count
	items, _ := queue.List(ctx)
	if len(items) != 1 {
		t.Fatalf("Expected 1 item in queue, got %d", len(items))
	}

	if items[0].Attempts != 2 {
		t.Errorf("Expected Attempts 2, got %d", items[0].Attempts)
	}
	if items[0].LastError != "vault error" {
		t.Errorf("Expected LastError 'vault error', got %s", items[0].LastError)
	}
}

func TestController_ProcessQueue_MaxAttemptsExceeded(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	mockClient := &mockVaultClient{}
	clientCache := &mockClientCache{client: mockClient}

	c := &Controller{
		queue:       queue,
		clientCache: clientCache,
		maxAttempts: 5,
		log:         newTestLogger(),
		interval:    time.Second,
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
	}

	ctx := context.Background()

	// Enqueue an item that has already exceeded max attempts
	item := Item{
		ResourceType:   ResourceTypePolicy,
		VaultName:      "test-policy",
		ConnectionName: "vault-connection",
		K8sNamespace:   "default",
		K8sName:        "my-policy",
		FailedAt:       time.Now(),
		LastAttemptAt:  time.Now(),
		Attempts:       10, // Already exceeded max
		LastError:      "persistent error",
	}
	err := queue.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}

	// Process queue
	c.processQueue(ctx)

	// Item should be removed (max attempts exceeded)
	size, _ := queue.Size(ctx)
	if size != 0 {
		t.Errorf("Expected queue size 0 after max attempts exceeded, got %d", size)
	}

	// No policy deletion attempted since max attempts already exceeded
	if len(mockClient.deletedPolicies) != 0 {
		t.Errorf("Expected 0 deleted policies (max attempts exceeded), got %d", len(mockClient.deletedPolicies))
	}
}

func TestController_ProcessQueue_EmptyQueue(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	mockClient := &mockVaultClient{}
	clientCache := &mockClientCache{client: mockClient}

	c := &Controller{
		queue:       queue,
		clientCache: clientCache,
		maxAttempts: 10,
		log:         newTestLogger(),
		interval:    time.Second,
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
	}

	ctx := context.Background()

	// Process empty queue - should not panic
	c.processQueue(ctx)

	// No errors means success for empty queue
	if len(mockClient.deletedPolicies) != 0 {
		t.Errorf("Expected 0 deleted policies for empty queue, got %d", len(mockClient.deletedPolicies))
	}
}

func TestController_NeedsLeaderElection(t *testing.T) {
	c := &Controller{}
	if !c.NeedsLeaderElection() {
		t.Error("Expected NeedsLeaderElection to return true")
	}
}

func TestController_Start_ContextCancellation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	mockClient := &mockVaultClient{}
	clientCache := &mockClientCache{client: mockClient}

	c := NewController(ControllerConfig{
		Queue:       queue,
		ClientCache: clientCache,
		Interval:    100 * time.Millisecond, // Short interval for testing
		Log:         newTestLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	// Cancel after a short delay
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Wait for Start to return
	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Errorf("Expected context.Canceled error, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("Start did not return after context cancellation")
	}
}

func TestController_Stop(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	queue := NewQueue(fakeClient, "test-namespace")
	mockClient := &mockVaultClient{}
	clientCache := &mockClientCache{client: mockClient}

	c := NewController(ControllerConfig{
		Queue:       queue,
		ClientCache: clientCache,
		Interval:    100 * time.Millisecond,
		Log:         newTestLogger(),
	})

	ctx := context.Background()

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Stop should block until controller is stopped
	done := make(chan struct{})
	go func() {
		c.Stop()
		close(done)
	}()

	// Wait for Stop to complete
	select {
	case <-done:
		// Success
	case <-time.After(time.Second):
		t.Error("Stop did not complete within timeout")
	}

	// Verify Start returned nil (not context error since we used Stop)
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Expected nil error from Start after Stop, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("Start did not return after Stop")
	}
}
