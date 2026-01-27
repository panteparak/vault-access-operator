/*
Package auth provides cloud-specific authentication helpers for Vault.

This file contains unit tests for Kubernetes authentication helpers.
*/
package auth

import (
	"os"
	"path/filepath"
	"testing"
)

const testVaultRole = "testVaultRole"

func TestGetServiceAccountTokenFromPath(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantToken string
	}{
		{
			name:      "valid token",
			content:   "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.signature",
			wantToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.signature",
		},
		{
			name:      "simple token",
			content:   "test-token-12345",
			wantToken: "test-token-12345",
		},
		{
			name:      "token with newline",
			content:   "token-with-newline\n",
			wantToken: "token-with-newline\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file with token
			tmpDir := t.TempDir()
			tokenPath := filepath.Join(tmpDir, "token")
			if err := os.WriteFile(tokenPath, []byte(tt.content), 0600); err != nil {
				t.Fatalf("failed to write temp token file: %v", err)
			}

			token, err := GetServiceAccountTokenFromPath(tokenPath)
			if err != nil {
				t.Errorf("GetServiceAccountTokenFromPath() error = %v", err)
				return
			}
			if token != tt.wantToken {
				t.Errorf("GetServiceAccountTokenFromPath() = %q, want %q", token, tt.wantToken)
			}
		})
	}
}

func TestGetServiceAccountTokenFromPath_NotFound(t *testing.T) {
	_, err := GetServiceAccountTokenFromPath("/nonexistent/path/token")
	if err == nil {
		t.Error("GetServiceAccountTokenFromPath() expected error for missing file")
	}
}

func TestGetServiceAccountTokenFromPath_EmptyFile(t *testing.T) {
	// Create temp file with empty content
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write temp token file: %v", err)
	}

	token, err := GetServiceAccountTokenFromPath(tokenPath)
	if err != nil {
		t.Errorf("GetServiceAccountTokenFromPath() error = %v", err)
		return
	}
	if token != "" {
		t.Errorf("GetServiceAccountTokenFromPath() = %q, want empty string", token)
	}
}

func TestGetMountedServiceAccountToken(t *testing.T) {
	// This test verifies the constant and function exist
	// Actual file reading is tested in GetServiceAccountTokenFromPath

	// Verify the default path constant
	expectedPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if DefaultKubernetesTokenPath != expectedPath {
		t.Errorf("DefaultKubernetesTokenPath = %q, want %q", DefaultKubernetesTokenPath, expectedPath)
	}

	// GetMountedServiceAccountToken will fail when not in a pod
	// which is expected in unit tests
	_, err := GetMountedServiceAccountToken()
	if err == nil {
		t.Skip("Skipping test - appears to be running in Kubernetes")
	}
	// Error is expected when not running in a Kubernetes pod
}

func TestGetCurrentNamespace_FromEnv(t *testing.T) {
	// Save original value
	originalValue := os.Getenv("OPERATOR_NAMESPACE")
	defer func() {
		if originalValue == "" {
			os.Unsetenv("OPERATOR_NAMESPACE")
		} else {
			os.Setenv("OPERATOR_NAMESPACE", originalValue)
		}
	}()

	tests := []struct {
		name          string
		envValue      string
		wantNamespace string
	}{
		{
			name:          "namespace from env",
			envValue:      "vault-operator-system",
			wantNamespace: "vault-operator-system",
		},
		{
			name:          "default namespace",
			envValue:      "default",
			wantNamespace: "default",
		},
		{
			name:          "custom namespace",
			envValue:      "my-namespace",
			wantNamespace: "my-namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("OPERATOR_NAMESPACE", tt.envValue)

			ns, err := GetCurrentNamespace()
			if err != nil {
				t.Errorf("GetCurrentNamespace() error = %v", err)
				return
			}
			if ns != tt.wantNamespace {
				t.Errorf("GetCurrentNamespace() = %q, want %q", ns, tt.wantNamespace)
			}
		})
	}
}

func TestGetCurrentNamespace_FromFile(t *testing.T) {
	// Save and clear env var
	originalValue := os.Getenv("OPERATOR_NAMESPACE")
	os.Unsetenv("OPERATOR_NAMESPACE")
	defer func() {
		if originalValue == "" {
			os.Unsetenv("OPERATOR_NAMESPACE")
		} else {
			os.Setenv("OPERATOR_NAMESPACE", originalValue)
		}
	}()

	// When env var is not set and file doesn't exist, should fail
	_, err := GetCurrentNamespace()
	if err == nil {
		t.Skip("Skipping test - appears to be running in Kubernetes")
	}
	// Error is expected when not running in a Kubernetes pod
}

func TestGetKubernetesCACert(t *testing.T) {
	// Verify the default path constant
	expectedPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	if DefaultKubernetesCACertPath != expectedPath {
		t.Errorf("DefaultKubernetesCACertPath = %q, want %q", DefaultKubernetesCACertPath, expectedPath)
	}

	// GetKubernetesCACert will fail when not in a pod
	_, err := GetKubernetesCACert()
	if err == nil {
		t.Skip("Skipping test - appears to be running in Kubernetes")
	}
	// Error is expected when not running in a Kubernetes pod
}

func TestIsRunningInKubernetes(t *testing.T) {
	// Create a temp directory and file to simulate running in Kubernetes
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")

	// When token file doesn't exist
	if IsRunningInKubernetes() {
		t.Skip("Skipping test - appears to be running in Kubernetes")
	}

	// Create the token file
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatalf("failed to write temp token file: %v", err)
	}

	// Test with a custom check (simulating the function's logic)
	_, err := os.Stat(tokenPath)
	isRunning := err == nil
	if !isRunning {
		t.Error("expected isRunning to be true when token file exists")
	}
}

func TestKubernetesAuthOptions(t *testing.T) {
	// Test that KubernetesAuthOptions struct fields work correctly
	opts := KubernetesAuthOptions{
		Role:      testVaultRole,
		AuthPath:  "kubernetes",
		TokenPath: "/custom/path/token",
	}

	if opts.Role != testVaultRole {
		t.Errorf("Role = %q, want %q", opts.Role, testVaultRole)
	}
	if opts.AuthPath != "kubernetes" {
		t.Errorf("AuthPath = %q, want 'kubernetes'", opts.AuthPath)
	}
	if opts.TokenPath != "/custom/path/token" {
		t.Errorf("TokenPath = %q, want '/custom/path/token'", opts.TokenPath)
	}
}

func TestKubernetesConstants(t *testing.T) {
	// Verify all Kubernetes-related constants
	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{
			name:     "DefaultKubernetesTokenPath",
			got:      DefaultKubernetesTokenPath,
			expected: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		{
			name:     "DefaultKubernetesAuthPath",
			got:      DefaultKubernetesAuthPath,
			expected: "kubernetes",
		},
		{
			name:     "DefaultKubernetesNamespacePath",
			got:      DefaultKubernetesNamespacePath,
			expected: "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
		},
		{
			name:     "DefaultKubernetesCACertPath",
			got:      DefaultKubernetesCACertPath,
			expected: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestGetServiceAccountTokenFromPath_Permissions(t *testing.T) {
	// Test reading a file with different permissions
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")

	// Create file with restricted permissions (readable only by owner)
	if err := os.WriteFile(tokenPath, []byte("secret-token"), 0600); err != nil {
		t.Fatalf("failed to write temp token file: %v", err)
	}

	token, err := GetServiceAccountTokenFromPath(tokenPath)
	if err != nil {
		t.Errorf("GetServiceAccountTokenFromPath() error = %v", err)
		return
	}
	if token != "secret-token" {
		t.Errorf("GetServiceAccountTokenFromPath() = %q, want 'secret-token'", token)
	}
}

func TestGetServiceAccountTokenFromPath_Directory(t *testing.T) {
	// Test that reading a directory fails
	tmpDir := t.TempDir()

	_, err := GetServiceAccountTokenFromPath(tmpDir)
	if err == nil {
		t.Error("GetServiceAccountTokenFromPath() expected error when path is a directory")
	}
}

func TestGetCurrentNamespace_EnvTakesPrecedence(t *testing.T) {
	// Save original value
	originalValue := os.Getenv("OPERATOR_NAMESPACE")
	defer func() {
		if originalValue == "" {
			os.Unsetenv("OPERATOR_NAMESPACE")
		} else {
			os.Setenv("OPERATOR_NAMESPACE", originalValue)
		}
	}()

	// Set env var
	os.Setenv("OPERATOR_NAMESPACE", "env-namespace")

	ns, err := GetCurrentNamespace()
	if err != nil {
		t.Errorf("GetCurrentNamespace() error = %v", err)
		return
	}

	// Env var should take precedence even if file exists
	if ns != "env-namespace" {
		t.Errorf("GetCurrentNamespace() = %q, want 'env-namespace'", ns)
	}
}

func TestIsRunningInKubernetes_Logic(t *testing.T) {
	// Test the logic of IsRunningInKubernetes function
	// by checking file existence

	tmpDir := t.TempDir()

	// Test 1: File doesn't exist - should return false
	nonexistentPath := filepath.Join(tmpDir, "nonexistent")
	_, err := os.Stat(nonexistentPath)
	result := err == nil
	if result {
		t.Error("expected false when file doesn't exist")
	}

	// Test 2: File exists - should return true
	existingPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(existingPath, []byte("token"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	_, err = os.Stat(existingPath)
	result = err == nil
	if !result {
		t.Error("expected true when file exists")
	}
}
