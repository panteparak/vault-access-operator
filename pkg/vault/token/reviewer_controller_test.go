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

package token

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

const (
	testConnName           = "test-conn"
	testVaultAuthMountPath = "kubernetes"
)

// --- Mocks ---

type mockReviewerTokenProvider struct {
	getTokenFunc func(ctx context.Context, opts GetTokenOptions) (*TokenInfo, error)
}

func (m *mockReviewerTokenProvider) GetToken(ctx context.Context, opts GetTokenOptions) (*TokenInfo, error) {
	if m.getTokenFunc != nil {
		return m.getTokenFunc(ctx, opts)
	}
	return nil, fmt.Errorf("getTokenFunc not set")
}

type mockVaultAuthConfigUpdater struct {
	updateFunc func(ctx context.Context, mountPath, jwt string) error
}

func (m *mockVaultAuthConfigUpdater) UpdateKubernetesAuthConfig(
	ctx context.Context, mountPath, tokenReviewerJWT string,
) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, mountPath, tokenReviewerJWT)
	}
	return nil
}

type mockReviewerEventPublisher struct {
	publishFunc func(ctx context.Context, event interface{}) error
}

func (m *mockReviewerEventPublisher) Publish(ctx context.Context, event interface{}) error {
	if m.publishFunc != nil {
		return m.publishFunc(ctx, event)
	}
	return nil
}

// --- Helpers ---

func newTestReviewerController() (*reviewerControllerImpl, *mockReviewerTokenProvider) {
	provider := &mockReviewerTokenProvider{}
	eventBus := &mockReviewerEventPublisher{}
	ctrl := NewTokenReviewerController(provider, eventBus, logr.Discard())
	return ctrl.(*reviewerControllerImpl), provider
}

func testReviewerConfig() *ReviewerConfig {
	return &ReviewerConfig{
		ServiceAccount: ServiceAccountRef{
			Namespace: "kube-system",
			Name:      "vault-reviewer",
		},
		Duration:        24 * time.Hour,
		RefreshInterval: 12 * time.Hour,
		VaultAuthPath:   testVaultAuthMountPath,
	}
}

// --- Tests ---

func TestReviewerController_Register_Success(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	err := ctrl.Register(testConnName, testReviewerConfig())
	if err != nil {
		t.Fatalf("Register() returned unexpected error: %v", err)
	}

	ctrl.mu.RLock()
	state, exists := ctrl.connections[testConnName]
	ctrl.mu.RUnlock()

	if !exists {
		t.Fatal("expected connection to be registered")
	}
	if state.config == nil {
		t.Fatal("expected config to be set")
	}
	if state.status == nil {
		t.Fatal("expected status to be initialized")
	}
	if state.status.ConnectionName != testConnName {
		t.Errorf("status.ConnectionName = %q, want %q", state.status.ConnectionName, testConnName)
	}
	if !state.status.Enabled {
		t.Error("status.Enabled = false, want true")
	}
}

func TestReviewerController_Register_EmptyName(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	err := ctrl.Register("", testReviewerConfig())
	if err == nil {
		t.Fatal("Register() with empty name should return error")
	}
}

func TestReviewerController_Register_NilConfig(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	err := ctrl.Register(testConnName, nil)
	if err == nil {
		t.Fatal("Register() with nil config should return error")
	}
}

func TestReviewerController_Unregister(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	if err := ctrl.Register(testConnName, testReviewerConfig()); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	ctrl.Unregister(testConnName)

	ctrl.mu.RLock()
	_, exists := ctrl.connections[testConnName]
	ctrl.mu.RUnlock()

	if exists {
		t.Error("expected connection to be unregistered")
	}

	// Unregistering a non-existent connection should not panic.
	ctrl.Unregister("non-existent")
}

func TestReviewerController_SetVaultClient_Success(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	if err := ctrl.Register(testConnName, testReviewerConfig()); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	vaultClient := &mockVaultAuthConfigUpdater{}
	ctrl.SetVaultClient(testConnName, vaultClient)

	ctrl.mu.RLock()
	state := ctrl.connections[testConnName]
	ctrl.mu.RUnlock()

	if state.vaultClient == nil {
		t.Error("expected vault client to be set")
	}
}

func TestReviewerController_SetVaultClient_NotRegistered(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	// SetVaultClient on a non-registered connection should not panic;
	// it silently does nothing (no error return in the interface).
	vaultClient := &mockVaultAuthConfigUpdater{}
	ctrl.SetVaultClient("non-existent", vaultClient)

	ctrl.mu.RLock()
	_, exists := ctrl.connections["non-existent"]
	ctrl.mu.RUnlock()

	if exists {
		t.Error("SetVaultClient should not create an entry for non-registered connection")
	}
}

func TestReviewerController_Refresh_Success(t *testing.T) {
	ctrl, provider := newTestReviewerController()

	now := time.Now()
	expiration := now.Add(24 * time.Hour)

	var capturedOpts GetTokenOptions
	provider.getTokenFunc = func(ctx context.Context, opts GetTokenOptions) (*TokenInfo, error) {
		capturedOpts = opts
		return &TokenInfo{
			Token:          "test-reviewer-jwt",
			ExpirationTime: expiration,
			IssuedAt:       now,
		}, nil
	}

	var capturedMountPath, capturedJWT string
	vaultClient := &mockVaultAuthConfigUpdater{
		updateFunc: func(ctx context.Context, mountPath, jwt string) error {
			capturedMountPath = mountPath
			capturedJWT = jwt
			return nil
		},
	}

	if err := ctrl.Register(testConnName, testReviewerConfig()); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	ctrl.SetVaultClient(testConnName, vaultClient)

	err := ctrl.Refresh(context.Background(), testConnName)
	if err != nil {
		t.Fatalf("Refresh() returned unexpected error: %v", err)
	}

	// Verify GetToken was called WITHOUT audiences (critical for token reviewer).
	if len(capturedOpts.Audiences) != 0 {
		t.Errorf("GetToken should be called with no audiences, got %v", capturedOpts.Audiences)
	}
	if capturedOpts.ServiceAccount.Name != "vault-reviewer" {
		t.Errorf("ServiceAccount.Name = %q, want %q", capturedOpts.ServiceAccount.Name, "vault-reviewer")
	}
	if capturedOpts.ServiceAccount.Namespace != "kube-system" {
		t.Errorf("ServiceAccount.Namespace = %q, want %q", capturedOpts.ServiceAccount.Namespace, "kube-system")
	}

	// Verify UpdateKubernetesAuthConfig was called with correct args.
	if capturedMountPath != testVaultAuthMountPath {
		t.Errorf("mountPath = %q, want %q", capturedMountPath, testVaultAuthMountPath)
	}
	if capturedJWT != "test-reviewer-jwt" {
		t.Errorf("jwt = %q, want %q", capturedJWT, "test-reviewer-jwt")
	}

	// Verify status was updated.
	status := ctrl.GetStatus(testConnName)
	if status == nil {
		t.Fatal("GetStatus() returned nil after successful refresh")
	}
	if status.Error != "" {
		t.Errorf("status.Error = %q, want empty", status.Error)
	}
	if status.LastRefresh.IsZero() {
		t.Error("status.LastRefresh should not be zero after refresh")
	}
	if status.NextRefresh.IsZero() {
		t.Error("status.NextRefresh should not be zero after refresh")
	}
	if !status.ExpirationTime.Equal(expiration) {
		t.Errorf("status.ExpirationTime = %v, want %v", status.ExpirationTime, expiration)
	}
}

func TestReviewerController_Refresh_NotRegistered(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	err := ctrl.Refresh(context.Background(), "non-existent")
	if err == nil {
		t.Fatal("Refresh() on non-registered connection should return error")
	}
}

func TestReviewerController_Refresh_NoVaultClient(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	if err := ctrl.Register(testConnName, testReviewerConfig()); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	// Do not set vault client.
	err := ctrl.Refresh(context.Background(), testConnName)
	if err == nil {
		t.Fatal("Refresh() without vault client should return error")
	}
}

func TestReviewerController_Refresh_GetTokenFails(t *testing.T) {
	ctrl, provider := newTestReviewerController()

	provider.getTokenFunc = func(ctx context.Context, opts GetTokenOptions) (*TokenInfo, error) {
		return nil, fmt.Errorf("token request failed")
	}

	vaultClient := &mockVaultAuthConfigUpdater{}

	if err := ctrl.Register(testConnName, testReviewerConfig()); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	ctrl.SetVaultClient(testConnName, vaultClient)

	err := ctrl.Refresh(context.Background(), testConnName)
	if err == nil {
		t.Fatal("Refresh() should return error when GetToken fails")
	}

	// Verify status records the error.
	status := ctrl.GetStatus(testConnName)
	if status == nil {
		t.Fatal("GetStatus() returned nil")
	}
	if status.Error == "" {
		t.Error("status.Error should be set after failure")
	}
	if status.NextRefresh.IsZero() {
		t.Error("status.NextRefresh should be set for retry after failure")
	}
}

func TestReviewerController_Refresh_UpdateConfigFails(t *testing.T) {
	ctrl, provider := newTestReviewerController()

	provider.getTokenFunc = func(ctx context.Context, opts GetTokenOptions) (*TokenInfo, error) {
		return &TokenInfo{
			Token:          "test-jwt",
			ExpirationTime: time.Now().Add(24 * time.Hour),
			IssuedAt:       time.Now(),
		}, nil
	}

	vaultClient := &mockVaultAuthConfigUpdater{
		updateFunc: func(ctx context.Context, mountPath, jwt string) error {
			return fmt.Errorf("vault update failed")
		},
	}

	if err := ctrl.Register(testConnName, testReviewerConfig()); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	ctrl.SetVaultClient(testConnName, vaultClient)

	err := ctrl.Refresh(context.Background(), testConnName)
	if err == nil {
		t.Fatal("Refresh() should return error when UpdateKubernetesAuthConfig fails")
	}

	// Verify status records the error.
	status := ctrl.GetStatus(testConnName)
	if status == nil {
		t.Fatal("GetStatus() returned nil")
	}
	if status.Error == "" {
		t.Error("status.Error should be set after failure")
	}
}

func TestReviewerController_GetStatus_Registered(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	if err := ctrl.Register(testConnName, testReviewerConfig()); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	status := ctrl.GetStatus(testConnName)
	if status == nil {
		t.Fatal("GetStatus() returned nil for registered connection")
	}
	if status.ConnectionName != testConnName {
		t.Errorf("status.ConnectionName = %q, want %q", status.ConnectionName, testConnName)
	}
	if !status.Enabled {
		t.Error("status.Enabled = false, want true")
	}

	// Verify it returns a copy (modifying the returned status should not affect internal state).
	status.ConnectionName = "modified"
	original := ctrl.GetStatus(testConnName)
	if original.ConnectionName != testConnName {
		t.Error("GetStatus() should return a copy, not a reference to internal state")
	}
}

func TestReviewerController_GetStatus_Unregistered(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	status := ctrl.GetStatus("non-existent")
	if status != nil {
		t.Errorf("GetStatus() for unregistered connection should return nil, got %+v", status)
	}
}

func TestReviewerController_Start_ContextCancellation(t *testing.T) {
	ctrl, _ := newTestReviewerController()

	// Use a very short check interval so we don't wait long.
	ctrl.checkInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- ctrl.Start(ctx)
	}()

	// Let the ticker fire at least once, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start() should return nil on context cancellation, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not return after context cancellation")
	}
}
