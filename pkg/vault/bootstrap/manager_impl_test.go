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

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-logr/logr"

	"github.com/panteparak/vault-access-operator/pkg/vault/token"
)

// mockClusterDiscovery is a test double for K8sClusterDiscovery.
type mockClusterDiscovery struct {
	config *KubernetesClusterConfig
	err    error
	called bool
}

func (m *mockClusterDiscovery) GetClusterConfig(
	_ context.Context,
) (*KubernetesClusterConfig, error) {
	m.called = true
	return m.config, m.err
}

// newTestManager creates a managerImpl with the given mock discovery.
// tokenProvider is nil because getK8sConfig doesn't use it.
func newTestManager(discovery K8sClusterDiscovery) *managerImpl {
	return &managerImpl{
		tokenProvider:    nil,
		clusterDiscovery: discovery,
		log:              logr.Discard(),
	}
}

// TestGetK8sConfig_FullOverride verifies that when both Host and CACert
// are provided in the override, auto-discovery is NOT called and the
// override is returned unchanged.
func TestGetK8sConfig_FullOverride(t *testing.T) {
	discovery := &mockClusterDiscovery{
		config: &KubernetesClusterConfig{
			Host:   "https://auto-host:6443",
			CACert: "auto-ca-cert",
		},
	}
	mgr := newTestManager(discovery)

	override := &KubernetesClusterConfig{
		Host:   "https://override-host:6443",
		CACert: "override-ca-cert",
	}

	result, err := mgr.getK8sConfig(context.Background(), override)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if discovery.called {
		t.Error("auto-discovery should NOT be called when full override is provided")
	}
	if result.Host != "https://override-host:6443" {
		t.Errorf("Host = %q, want %q", result.Host, "https://override-host:6443")
	}
	if result.CACert != "override-ca-cert" {
		t.Errorf("CACert = %q, want %q", result.CACert, "override-ca-cert")
	}
	// Verify we got back the same pointer (no copy)
	if result != override {
		t.Error("expected the same override pointer to be returned")
	}
}

// TestGetK8sConfig_NoOverride verifies that when overrideConfig is nil,
// the auto-discovered configuration is returned.
func TestGetK8sConfig_NoOverride(t *testing.T) {
	discovery := &mockClusterDiscovery{
		config: &KubernetesClusterConfig{
			Host:   "https://auto-host:6443",
			CACert: "auto-ca-cert",
		},
	}
	mgr := newTestManager(discovery)

	result, err := mgr.getK8sConfig(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !discovery.called {
		t.Error("auto-discovery should be called when no override is provided")
	}
	if result.Host != "https://auto-host:6443" {
		t.Errorf("Host = %q, want %q", result.Host, "https://auto-host:6443")
	}
	if result.CACert != "auto-ca-cert" {
		t.Errorf("CACert = %q, want %q", result.CACert, "auto-ca-cert")
	}
}

// TestGetK8sConfig_PartialOverride_HostOnly verifies that when only Host
// is provided in the override, CACert comes from auto-discovery.
func TestGetK8sConfig_PartialOverride_HostOnly(t *testing.T) {
	discovery := &mockClusterDiscovery{
		config: &KubernetesClusterConfig{
			Host:   "https://auto-host:6443",
			CACert: "auto-ca-cert",
		},
	}
	mgr := newTestManager(discovery)

	override := &KubernetesClusterConfig{
		Host:   "https://override-host:6443",
		CACert: "", // empty — should be filled from auto-discovery
	}

	result, err := mgr.getK8sConfig(context.Background(), override)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !discovery.called {
		t.Error("auto-discovery should be called for partial override")
	}
	if result.Host != "https://override-host:6443" {
		t.Errorf("Host = %q, want %q (from override)",
			result.Host, "https://override-host:6443")
	}
	if result.CACert != "auto-ca-cert" {
		t.Errorf("CACert = %q, want %q (from auto-discovery)",
			result.CACert, "auto-ca-cert")
	}
}

// TestGetK8sConfig_PartialOverride_CACertOnly verifies that when only
// CACert is provided in the override, Host comes from auto-discovery.
func TestGetK8sConfig_PartialOverride_CACertOnly(t *testing.T) {
	discovery := &mockClusterDiscovery{
		config: &KubernetesClusterConfig{
			Host:   "https://auto-host:6443",
			CACert: "auto-ca-cert",
		},
	}
	mgr := newTestManager(discovery)

	override := &KubernetesClusterConfig{
		Host:   "", // empty — should be filled from auto-discovery
		CACert: "override-ca-cert",
	}

	result, err := mgr.getK8sConfig(context.Background(), override)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !discovery.called {
		t.Error("auto-discovery should be called for partial override")
	}
	if result.Host != "https://auto-host:6443" {
		t.Errorf("Host = %q, want %q (from auto-discovery)",
			result.Host, "https://auto-host:6443")
	}
	if result.CACert != "override-ca-cert" {
		t.Errorf("CACert = %q, want %q (from override)",
			result.CACert, "override-ca-cert")
	}
}

// TestGetK8sConfig_AutoDiscoveryError verifies that when auto-discovery
// fails, the error is propagated correctly.
func TestGetK8sConfig_AutoDiscoveryError(t *testing.T) {
	discoveryErr := fmt.Errorf("cluster unreachable")
	discovery := &mockClusterDiscovery{
		config: nil,
		err:    discoveryErr,
	}
	mgr := newTestManager(discovery)

	// Test with nil override (forces auto-discovery)
	result, err := mgr.getK8sConfig(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on error, got %+v", result)
	}

	expectedMsg := "failed to auto-discover cluster config: cluster unreachable"
	if err.Error() != expectedMsg {
		t.Errorf("error = %q, want %q", err.Error(), expectedMsg)
	}

	// Test with partial override (also forces auto-discovery)
	discovery.called = false
	partialOverride := &KubernetesClusterConfig{
		Host: "https://override-host:6443",
		// CACert empty → triggers auto-discovery
	}
	result, err = mgr.getK8sConfig(context.Background(), partialOverride)
	if err == nil {
		t.Fatal("expected error for partial override with discovery failure, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on error, got %+v", result)
	}
	if !discovery.called {
		t.Error("auto-discovery should be called for partial override")
	}
}

// fakeBootstrapClient is a minimal VaultBootstrapClient used by the
// surfacing tests below. Each function pointer is optional; nil means
// "succeed silently". Set authTestErr / revokeErr to inject failures.
type fakeBootstrapClient struct {
	authEnabled        bool
	currentToken       string
	authTestErr        error
	revokeErr          error
	revokeSelfCalled   bool
	authTestCalled     bool
	configWriteErr     error
	roleWriteErr       error
	enableAuthErr      error
	isAuthEnabledErr   error
	isAuthEnabledValue bool
}

func (f *fakeBootstrapClient) EnableAuth(_ context.Context, _, _ string) error {
	f.authEnabled = true
	return f.enableAuthErr
}
func (f *fakeBootstrapClient) IsAuthEnabled(_ context.Context, _ string) (bool, error) {
	return f.isAuthEnabledValue, f.isAuthEnabledErr
}
func (f *fakeBootstrapClient) WriteKubernetesAuthConfig(
	_ context.Context, _ string, _ map[string]interface{},
) error {
	return f.configWriteErr
}
func (f *fakeBootstrapClient) WriteKubernetesRole(
	_ context.Context, _, _ string, _ map[string]interface{},
) error {
	return f.roleWriteErr
}
func (f *fakeBootstrapClient) RevokeToken(_ context.Context, _ string) error { return nil }
func (f *fakeBootstrapClient) RevokeSelf(_ context.Context) error {
	f.revokeSelfCalled = true
	return f.revokeErr
}
func (f *fakeBootstrapClient) AuthenticateKubernetesWithToken(
	_ context.Context, _, _, _ string,
) error {
	f.authTestCalled = true
	return f.authTestErr
}
func (f *fakeBootstrapClient) Token() string     { return f.currentToken }
func (f *fakeBootstrapClient) SetToken(t string) { f.currentToken = t }

// fakeTokenProvider is a minimal token.TokenProvider returning a fixed JWT.
type fakeTokenProvider struct{}

func (f *fakeTokenProvider) GetToken(
	_ context.Context, _ token.GetTokenOptions,
) (*token.TokenInfo, error) {
	return &token.TokenInfo{Token: "fake-jwt"}, nil
}

// newSurfacingTestManager builds a manager with the mock dependencies.
func newSurfacingTestManager() *managerImpl {
	return &managerImpl{
		tokenProvider: &fakeTokenProvider{},
		clusterDiscovery: &mockClusterDiscovery{
			config: &KubernetesClusterConfig{
				Host:   "https://k8s:6443",
				CACert: "ca-cert",
			},
		},
		log: logr.Discard(),
	}
}

// TestBootstrap_RevokeError_SurfacedInResult pins the contract that a
// RevokeSelf failure must populate Result.BootstrapRevokeError instead
// of being silently logged-and-dropped. Without this propagation the
// connection handler had no way to surface "bootstrap completed but
// the long-lived bootstrap token wasn't revoked" to operators.
func TestBootstrap_RevokeError_SurfacedInResult(t *testing.T) {
	mgr := newSurfacingTestManager()
	client := &fakeBootstrapClient{
		currentToken: "bootstrap-token",
		revokeErr:    errors.New("vault: forbidden"),
	}

	cfg := &Config{
		BootstrapToken: "bootstrap-token",
		AuthMethodName: "kubernetes",
		OperatorRole:   "operator",
		OperatorPolicy: "operator",
		OperatorServiceAccount: token.ServiceAccountRef{
			Name:      "operator-sa",
			Namespace: "vault-system",
		},
		AutoRevoke: true,
	}

	result, err := mgr.Bootstrap(context.Background(), client, cfg)
	if err != nil {
		t.Fatalf("Bootstrap returned error: %v", err)
	}
	if !client.revokeSelfCalled {
		t.Fatal("RevokeSelf should have been called when AutoRevoke=true")
	}
	if result.BootstrapRevoked {
		t.Error("BootstrapRevoked should be false when RevokeSelf failed")
	}
	if result.BootstrapRevokeError == "" {
		t.Error("BootstrapRevokeError should capture the revocation error")
	}
	if result.BootstrapRevokeError != "vault: forbidden" {
		t.Errorf("BootstrapRevokeError = %q, want %q",
			result.BootstrapRevokeError, "vault: forbidden")
	}
}

// TestBootstrap_K8sAuthTestError_SurfacedInResult pins the same contract
// for the K8s auth test failure path. Pre-fix, the error was logged once
// at Error level and discarded — the connection handler had no signal
// to set a status condition with the cause.
func TestBootstrap_K8sAuthTestError_SurfacedInResult(t *testing.T) {
	mgr := newSurfacingTestManager()
	client := &fakeBootstrapClient{
		currentToken: "bootstrap-token",
		authTestErr:  errors.New("permission denied: invalid role"),
	}

	cfg := &Config{
		BootstrapToken: "bootstrap-token",
		AuthMethodName: "kubernetes",
		OperatorRole:   "operator",
		OperatorPolicy: "operator",
		OperatorServiceAccount: token.ServiceAccountRef{
			Name:      "operator-sa",
			Namespace: "vault-system",
		},
		AutoRevoke: false,
	}

	result, err := mgr.Bootstrap(context.Background(), client, cfg)
	if err != nil {
		t.Fatalf("Bootstrap returned error: %v", err)
	}
	if !client.authTestCalled {
		t.Fatal("AuthenticateKubernetesWithToken should have been called")
	}
	if result.K8sAuthTestPassed {
		t.Error("K8sAuthTestPassed should be false when test errored")
	}
	if result.K8sAuthTestError == "" {
		t.Error("K8sAuthTestError should capture the test failure")
	}
}

// TestBootstrap_AllSucceeded_NoErrorsInResult is the happy-path control
// — both error fields stay empty when nothing failed. Guards against
// the surfacing code accidentally populating the fields on success.
func TestBootstrap_AllSucceeded_NoErrorsInResult(t *testing.T) {
	mgr := newSurfacingTestManager()
	client := &fakeBootstrapClient{currentToken: "bootstrap-token"}

	cfg := &Config{
		BootstrapToken: "bootstrap-token",
		AuthMethodName: "kubernetes",
		OperatorRole:   "operator",
		OperatorPolicy: "operator",
		OperatorServiceAccount: token.ServiceAccountRef{
			Name:      "operator-sa",
			Namespace: "vault-system",
		},
		AutoRevoke: true,
	}

	result, err := mgr.Bootstrap(context.Background(), client, cfg)
	if err != nil {
		t.Fatalf("Bootstrap returned error: %v", err)
	}
	if result.BootstrapRevokeError != "" {
		t.Errorf("BootstrapRevokeError should be empty on success, got %q",
			result.BootstrapRevokeError)
	}
	if result.K8sAuthTestError != "" {
		t.Errorf("K8sAuthTestError should be empty on success, got %q",
			result.K8sAuthTestError)
	}
	if !result.BootstrapRevoked {
		t.Error("BootstrapRevoked should be true on successful revoke")
	}
	if !result.K8sAuthTestPassed {
		t.Error("K8sAuthTestPassed should be true on successful test")
	}
}
