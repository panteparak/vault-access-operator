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
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockTokenProvider struct {
	getTokenFunc func(ctx context.Context, opts GetTokenOptions) (*TokenInfo, error)
}

func (m *mockTokenProvider) GetToken(ctx context.Context, opts GetTokenOptions) (*TokenInfo, error) {
	if m.getTokenFunc != nil {
		return m.getTokenFunc(ctx, opts)
	}
	return &TokenInfo{Token: "mock-jwt"}, nil
}

type mockVaultAuthenticator struct {
	authK8sFunc func(ctx context.Context, jwt, role, mountPath string) (*AuthResult, error)
	renewFunc   func(ctx context.Context) (*AuthResult, error)
}

func (m *mockVaultAuthenticator) AuthenticateKubernetes(
	ctx context.Context, jwt, role, mountPath string,
) (*AuthResult, error) {
	if m.authK8sFunc != nil {
		return m.authK8sFunc(ctx, jwt, role, mountPath)
	}
	return &AuthResult{
		ClientToken:    "vault-token",
		TokenTTL:       time.Hour,
		Renewable:      true,
		ExpirationTime: time.Now().Add(time.Hour),
		Policies:       []string{"default"},
	}, nil
}

func (m *mockVaultAuthenticator) RenewSelf(ctx context.Context) (*AuthResult, error) {
	if m.renewFunc != nil {
		return m.renewFunc(ctx)
	}
	return &AuthResult{
		ClientToken:    "renewed-token",
		TokenTTL:       time.Hour,
		Renewable:      true,
		ExpirationTime: time.Now().Add(time.Hour),
		Policies:       []string{"default"},
	}, nil
}

type mockEventPublisher struct {
	publishFunc func(ctx context.Context, event interface{}) error
}

func (m *mockEventPublisher) Publish(ctx context.Context, event interface{}) error {
	if m.publishFunc != nil {
		return m.publishFunc(ctx, event)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestController(
	provider TokenProvider,
	auth VaultAuthenticator,
	eventBus EventPublisher,
) *lifecycleControllerImpl {
	lc := NewLifecycleController(provider, auth, eventBus, logr.Discard())
	return lc.(*lifecycleControllerImpl)
}

func validConfig() *LifecycleConfig {
	return &LifecycleConfig{
		VaultAddress:  "https://vault.example.com",
		VaultRole:     "my-role",
		VaultAuthPath: "kubernetes",
		ServiceAccount: ServiceAccountRef{
			Namespace: "default",
			Name:      "my-sa",
		},
		TokenDuration:    time.Hour,
		RenewalThreshold: 0.75,
		RenewalStrategy:  RenewalStrategyRenew,
	}
}

// ---------------------------------------------------------------------------
// Tests: Register
// ---------------------------------------------------------------------------

func TestLifecycleController_Register_Success(t *testing.T) {
	ctrl := newTestController(&mockTokenProvider{}, &mockVaultAuthenticator{}, &mockEventPublisher{})

	err := ctrl.Register("test-conn", validConfig(), nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	status := ctrl.GetStatus("test-conn")
	if status == nil {
		t.Fatal("expected status to be non-nil after registration")
	}
	if status.ConnectionName != "test-conn" {
		t.Errorf("expected ConnectionName %q, got %q", "test-conn", status.ConnectionName)
	}
	if status.Authenticated {
		t.Error("expected Authenticated to be false after registration")
	}
}

func TestLifecycleController_Register_EmptyName(t *testing.T) {
	ctrl := newTestController(&mockTokenProvider{}, &mockVaultAuthenticator{}, &mockEventPublisher{})

	err := ctrl.Register("", validConfig(), nil)
	if err == nil {
		t.Fatal("expected error for empty connection name, got nil")
	}
}

func TestLifecycleController_Register_NilConfig(t *testing.T) {
	ctrl := newTestController(&mockTokenProvider{}, &mockVaultAuthenticator{}, &mockEventPublisher{})

	err := ctrl.Register("test-conn", nil, nil)
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

func TestLifecycleController_Register_Duplicate(t *testing.T) {
	ctrl := newTestController(&mockTokenProvider{}, &mockVaultAuthenticator{}, &mockEventPublisher{})

	err := ctrl.Register("test-conn", validConfig(), nil)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// The implementation is idempotent: re-registering the same name
	// overwrites the previous entry without error.
	err = ctrl.Register("test-conn", validConfig(), nil)
	if err != nil {
		t.Fatalf("duplicate registration should succeed (idempotent), got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: Unregister
// ---------------------------------------------------------------------------

func TestLifecycleController_Unregister_Success(t *testing.T) {
	ctrl := newTestController(&mockTokenProvider{}, &mockVaultAuthenticator{}, &mockEventPublisher{})

	_ = ctrl.Register("test-conn", validConfig(), nil)
	ctrl.Unregister("test-conn")

	status := ctrl.GetStatus("test-conn")
	if status != nil {
		t.Fatal("expected nil status after unregister")
	}
}

func TestLifecycleController_Unregister_Idempotent(t *testing.T) {
	ctrl := newTestController(&mockTokenProvider{}, &mockVaultAuthenticator{}, &mockEventPublisher{})

	// Unregistering a non-existing connection should not panic or error.
	ctrl.Unregister("does-not-exist")
}

// ---------------------------------------------------------------------------
// Tests: Authenticate
// ---------------------------------------------------------------------------

func TestLifecycleController_Authenticate_Success(t *testing.T) {
	provider := &mockTokenProvider{
		getTokenFunc: func(_ context.Context, opts GetTokenOptions) (*TokenInfo, error) {
			return &TokenInfo{
				Token:          "sa-jwt-token",
				ExpirationTime: time.Now().Add(time.Hour),
				IssuedAt:       time.Now(),
			}, nil
		},
	}

	auth := &mockVaultAuthenticator{
		authK8sFunc: func(_ context.Context, jwt, role, mountPath string) (*AuthResult, error) {
			if jwt != "sa-jwt-token" {
				t.Errorf("expected jwt %q, got %q", "sa-jwt-token", jwt)
			}
			return &AuthResult{
				ClientToken:    "vault-client-token",
				TokenTTL:       time.Hour,
				Renewable:      true,
				ExpirationTime: time.Now().Add(time.Hour),
				Policies:       []string{"default", "my-policy"},
				Accessor:       "accessor-123",
			}, nil
		},
	}

	ctrl := newTestController(provider, auth, &mockEventPublisher{})
	_ = ctrl.Register("test-conn", validConfig(), nil)

	result, err := ctrl.Authenticate(context.Background(), "test-conn")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ClientToken != "vault-client-token" {
		t.Errorf("expected ClientToken %q, got %q", "vault-client-token", result.ClientToken)
	}

	status := ctrl.GetStatus("test-conn")
	if status == nil {
		t.Fatal("expected non-nil status")
	}
	if !status.Authenticated {
		t.Error("expected Authenticated to be true after successful auth")
	}
	if status.RenewalCount != 0 {
		t.Errorf("expected RenewalCount 0, got %d", status.RenewalCount)
	}
}

func TestLifecycleController_Authenticate_NotRegistered(t *testing.T) {
	ctrl := newTestController(&mockTokenProvider{}, &mockVaultAuthenticator{}, &mockEventPublisher{})

	_, err := ctrl.Authenticate(context.Background(), "unknown-conn")
	if err == nil {
		t.Fatal("expected error for unregistered connection, got nil")
	}
}

func TestLifecycleController_Authenticate_GetTokenFails(t *testing.T) {
	provider := &mockTokenProvider{
		getTokenFunc: func(_ context.Context, _ GetTokenOptions) (*TokenInfo, error) {
			return nil, fmt.Errorf("token request denied")
		},
	}

	ctrl := newTestController(provider, &mockVaultAuthenticator{}, &mockEventPublisher{})
	_ = ctrl.Register("test-conn", validConfig(), nil)

	_, err := ctrl.Authenticate(context.Background(), "test-conn")
	if err == nil {
		t.Fatal("expected error when GetToken fails, got nil")
	}
}

func TestLifecycleController_Authenticate_AuthFails(t *testing.T) {
	provider := &mockTokenProvider{
		getTokenFunc: func(_ context.Context, _ GetTokenOptions) (*TokenInfo, error) {
			return &TokenInfo{Token: "jwt"}, nil
		},
	}
	auth := &mockVaultAuthenticator{
		authK8sFunc: func(_ context.Context, _, _, _ string) (*AuthResult, error) {
			return nil, fmt.Errorf("vault auth failed: 403 permission denied")
		},
	}

	ctrl := newTestController(provider, auth, &mockEventPublisher{})
	_ = ctrl.Register("test-conn", validConfig(), nil)

	_, err := ctrl.Authenticate(context.Background(), "test-conn")
	if err == nil {
		t.Fatal("expected error when Vault auth fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetStatus
// ---------------------------------------------------------------------------

func TestLifecycleController_GetStatus_Registered(t *testing.T) {
	ctrl := newTestController(&mockTokenProvider{}, &mockVaultAuthenticator{}, &mockEventPublisher{})
	_ = ctrl.Register("test-conn", validConfig(), nil)

	status := ctrl.GetStatus("test-conn")
	if status == nil {
		t.Fatal("expected non-nil status for registered connection")
	}
	if status.ConnectionName != "test-conn" {
		t.Errorf("expected ConnectionName %q, got %q", "test-conn", status.ConnectionName)
	}

	// Verify it's a copy by mutating the returned status.
	status.Authenticated = true
	original := ctrl.GetStatus("test-conn")
	if original.Authenticated {
		t.Error("GetStatus should return a copy, but mutation was reflected")
	}
}

func TestLifecycleController_GetStatus_Unregistered(t *testing.T) {
	ctrl := newTestController(&mockTokenProvider{}, &mockVaultAuthenticator{}, &mockEventPublisher{})

	status := ctrl.GetStatus("does-not-exist")
	if status != nil {
		t.Fatalf("expected nil status for unregistered connection, got %+v", status)
	}
}

// ---------------------------------------------------------------------------
// Tests: Start / context cancellation
// ---------------------------------------------------------------------------

func TestLifecycleController_Start_ContextCancellation(t *testing.T) {
	ctrl := newTestController(&mockTokenProvider{}, &mockVaultAuthenticator{}, &mockEventPublisher{})
	ctrl.checkInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- ctrl.Start(ctx)
	}()

	// Let the ticker fire at least once, then cancel.
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error on context cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

// ---------------------------------------------------------------------------
// Tests: checkRenewals / renewConnection
// ---------------------------------------------------------------------------

func TestLifecycleController_CheckRenewals_RenewStrategy(t *testing.T) {
	renewCalled := make(chan struct{}, 1)

	auth := &mockVaultAuthenticator{
		renewFunc: func(_ context.Context) (*AuthResult, error) {
			select {
			case renewCalled <- struct{}{}:
			default:
			}
			return &AuthResult{
				ClientToken:    "renewed-token",
				TokenTTL:       time.Hour,
				Renewable:      true,
				ExpirationTime: time.Now().Add(time.Hour),
				Policies:       []string{"default"},
			}, nil
		},
	}

	ctrl := newTestController(&mockTokenProvider{}, auth, &mockEventPublisher{})
	ctrl.checkInterval = 10 * time.Millisecond

	cfg := validConfig()
	cfg.RenewalStrategy = RenewalStrategyRenew
	_ = ctrl.Register("test-conn", cfg, nil)

	// Simulate an authenticated connection with NextRenewal in the past.
	ctrl.mu.Lock()
	state := ctrl.connections["test-conn"]
	state.status.Authenticated = true
	state.status.NextRenewal = time.Now().Add(-time.Second)
	state.lastResult = &AuthResult{
		ClientToken:    "old-token",
		ExpirationTime: time.Now().Add(10 * time.Minute),
	}
	ctrl.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ctrl.Start(ctx) //nolint:errcheck

	select {
	case <-renewCalled:
		// Success: RenewSelf was called.
	case <-time.After(2 * time.Second):
		t.Fatal("expected RenewSelf to be called, but timed out")
	}

	// Verify renewal count was incremented.
	status := ctrl.GetStatus("test-conn")
	if status == nil {
		t.Fatal("expected non-nil status")
	}
	if status.RenewalCount < 1 {
		t.Errorf("expected RenewalCount >= 1, got %d", status.RenewalCount)
	}
}

func TestLifecycleController_CheckRenewals_ReauthStrategy(t *testing.T) {
	getTokenCalled := make(chan struct{}, 1)
	authK8sCalled := make(chan struct{}, 1)

	provider := &mockTokenProvider{
		getTokenFunc: func(_ context.Context, _ GetTokenOptions) (*TokenInfo, error) {
			select {
			case getTokenCalled <- struct{}{}:
			default:
			}
			return &TokenInfo{
				Token:          "new-sa-jwt",
				ExpirationTime: time.Now().Add(time.Hour),
				IssuedAt:       time.Now(),
			}, nil
		},
	}

	auth := &mockVaultAuthenticator{
		authK8sFunc: func(_ context.Context, _, _, _ string) (*AuthResult, error) {
			select {
			case authK8sCalled <- struct{}{}:
			default:
			}
			return &AuthResult{
				ClientToken:    "reauth-token",
				TokenTTL:       time.Hour,
				Renewable:      true,
				ExpirationTime: time.Now().Add(time.Hour),
				Policies:       []string{"default"},
			}, nil
		},
		renewFunc: func(_ context.Context) (*AuthResult, error) {
			t.Error("RenewSelf should not be called with reauth strategy")
			return nil, fmt.Errorf("should not be called")
		},
	}

	ctrl := newTestController(provider, auth, &mockEventPublisher{})
	ctrl.checkInterval = 10 * time.Millisecond

	cfg := validConfig()
	cfg.RenewalStrategy = RenewalStrategyReauth
	_ = ctrl.Register("test-conn", cfg, nil)

	// Simulate an authenticated connection with NextRenewal in the past.
	ctrl.mu.Lock()
	state := ctrl.connections["test-conn"]
	state.status.Authenticated = true
	state.status.NextRenewal = time.Now().Add(-time.Second)
	state.lastResult = &AuthResult{
		ClientToken:    "old-token",
		ExpirationTime: time.Now().Add(10 * time.Minute),
	}
	ctrl.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ctrl.Start(ctx) //nolint:errcheck

	select {
	case <-getTokenCalled:
		// GetToken was called (re-auth path).
	case <-time.After(2 * time.Second):
		t.Fatal("expected GetToken to be called for reauth, but timed out")
	}

	select {
	case <-authK8sCalled:
		// AuthenticateKubernetes was called (re-auth path).
	case <-time.After(2 * time.Second):
		t.Fatal("expected AuthenticateKubernetes to be called for reauth, but timed out")
	}
}

func TestLifecycleController_OnRefreshCallback(t *testing.T) {
	var mu sync.Mutex
	var callbackName string
	var callbackResult *AuthResult
	callbackCalled := make(chan struct{}, 1)

	callback := func(name string, result *AuthResult) {
		mu.Lock()
		defer mu.Unlock()
		callbackName = name
		callbackResult = result
		select {
		case callbackCalled <- struct{}{}:
		default:
		}
	}

	expectedToken := "renewed-via-callback"
	auth := &mockVaultAuthenticator{
		renewFunc: func(_ context.Context) (*AuthResult, error) {
			return &AuthResult{
				ClientToken:    expectedToken,
				TokenTTL:       time.Hour,
				Renewable:      true,
				ExpirationTime: time.Now().Add(time.Hour),
				Policies:       []string{"default"},
			}, nil
		},
	}

	ctrl := newTestController(&mockTokenProvider{}, auth, &mockEventPublisher{})
	ctrl.checkInterval = 10 * time.Millisecond

	cfg := validConfig()
	cfg.RenewalStrategy = RenewalStrategyRenew
	_ = ctrl.Register("callback-conn", cfg, callback)

	// Simulate an authenticated connection with NextRenewal in the past.
	ctrl.mu.Lock()
	state := ctrl.connections["callback-conn"]
	state.status.Authenticated = true
	state.status.NextRenewal = time.Now().Add(-time.Second)
	state.lastResult = &AuthResult{
		ClientToken:    "old-token",
		ExpirationTime: time.Now().Add(10 * time.Minute),
	}
	ctrl.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ctrl.Start(ctx) //nolint:errcheck

	select {
	case <-callbackCalled:
		mu.Lock()
		defer mu.Unlock()
		if callbackName != "callback-conn" {
			t.Errorf("expected callback connection name %q, got %q", "callback-conn", callbackName)
		}
		if callbackResult == nil {
			t.Fatal("expected non-nil AuthResult in callback")
		}
		if callbackResult.ClientToken != expectedToken {
			t.Errorf("expected callback ClientToken %q, got %q", expectedToken, callbackResult.ClientToken)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected onRefresh callback to be invoked, but timed out")
	}
}
