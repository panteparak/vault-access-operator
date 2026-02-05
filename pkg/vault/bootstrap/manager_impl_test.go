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
	"fmt"
	"testing"

	"github.com/go-logr/logr"
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
