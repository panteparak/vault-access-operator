/*
Package auth provides cloud-specific authentication helpers for Vault.

This file implements Kubernetes service account authentication helpers,
providing utilities for reading and managing service account tokens.
*/
package auth

import (
	"fmt"
	"os"
)

const (
	// DefaultKubernetesTokenPath is the default path for mounted service account tokens
	DefaultKubernetesTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// DefaultKubernetesAuthPath is the default mount path for Kubernetes auth in Vault
	DefaultKubernetesAuthPath = "kubernetes"

	// DefaultKubernetesNamespacePath is the path to the mounted namespace file
	DefaultKubernetesNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	// DefaultKubernetesCACertPath is the path to the mounted CA certificate
	DefaultKubernetesCACertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// KubernetesAuthOptions contains options for Kubernetes authentication
type KubernetesAuthOptions struct {
	// Role is the Vault role to authenticate as
	Role string

	// AuthPath is the mount path for Kubernetes auth (default: "kubernetes")
	AuthPath string

	// TokenPath is the path to the service account token file
	TokenPath string
}

// GetMountedServiceAccountToken reads the JWT from the default mounted
// service account token path. This is the most common way to get a token
// for Kubernetes auth when running inside a pod.
func GetMountedServiceAccountToken() (string, error) {
	return GetServiceAccountTokenFromPath(DefaultKubernetesTokenPath)
}

// GetServiceAccountTokenFromPath reads a service account token from a custom path.
// Use this when the token is mounted at a non-default location.
func GetServiceAccountTokenFromPath(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token from %s: %w", path, err)
	}
	return string(data), nil
}

// GetCurrentNamespace returns the namespace of the current pod.
// It first checks the OPERATOR_NAMESPACE environment variable,
// then falls back to the mounted namespace file.
func GetCurrentNamespace() (string, error) {
	// Check environment variable first
	if ns := os.Getenv("OPERATOR_NAMESPACE"); ns != "" {
		return ns, nil
	}

	// Fall back to mounted namespace file
	data, err := os.ReadFile(DefaultKubernetesNamespacePath)
	if err != nil {
		return "", fmt.Errorf("failed to read namespace from %s: %w", DefaultKubernetesNamespacePath, err)
	}
	return string(data), nil
}

// GetKubernetesCACert reads the Kubernetes CA certificate from the mounted path.
// This is used when configuring Vault's Kubernetes auth backend.
func GetKubernetesCACert() (string, error) {
	data, err := os.ReadFile(DefaultKubernetesCACertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read CA cert from %s: %w", DefaultKubernetesCACertPath, err)
	}
	return string(data), nil
}

// IsRunningInKubernetes checks if the code is running inside a Kubernetes pod
// by checking for the existence of the service account token file.
func IsRunningInKubernetes() bool {
	_, err := os.Stat(DefaultKubernetesTokenPath)
	return err == nil
}
