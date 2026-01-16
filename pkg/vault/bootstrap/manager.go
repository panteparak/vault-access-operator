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
)

// Manager orchestrates the one-time Vault Kubernetes auth setup.
//
// # Responsibilities
//
//   - Enable auth/kubernetes method
//   - Configure Kubernetes cluster details
//   - Set up token_reviewer_jwt
//   - Create operator role
//   - Test K8s auth works
//   - Revoke bootstrap token
//
// # Thread Safety
//
// Bootstrap should only be called once per connection. The manager itself
// is thread-safe but concurrent bootstraps for the same connection are not supported.
//
// # Usage
//
//	manager := NewManager(k8sClientset, tokenProvider, log)
//	result, err := manager.Bootstrap(ctx, vaultClient, config)
//	if err != nil {
//	    // Bootstrap failed - check status and retry
//	    return err
//	}
//	// Bootstrap complete - switch to K8s auth
type Manager interface {
	// Bootstrap performs the full setup sequence.
	// Returns Result with details of what was configured.
	//
	// The vaultClient must be authenticated with the bootstrap token.
	Bootstrap(ctx context.Context, vaultClient VaultBootstrapClient, config *Config) (*Result, error)
}

// VaultBootstrapClient is the Vault client interface needed for bootstrap.
// This allows for mocking in tests.
type VaultBootstrapClient interface {
	// EnableAuth enables an auth method at the given path.
	EnableAuth(ctx context.Context, path, methodType string) error

	// IsAuthEnabled checks if an auth method is enabled at the given path.
	IsAuthEnabled(ctx context.Context, path string) (bool, error)

	// WriteKubernetesAuthConfig writes the Kubernetes auth configuration.
	WriteKubernetesAuthConfig(ctx context.Context, mountPath string, config map[string]interface{}) error

	// WriteKubernetesRole creates or updates a Kubernetes auth role.
	WriteKubernetesRole(ctx context.Context, mountPath, roleName string, config map[string]interface{}) error

	// RevokeToken revokes the specified token.
	RevokeToken(ctx context.Context, token string) error

	// RevokeSelf revokes the current token.
	RevokeSelf(ctx context.Context) error

	// AuthenticateKubernetesWithToken authenticates using Kubernetes auth with a provided JWT.
	// Used to test that K8s auth works after setup.
	AuthenticateKubernetesWithToken(ctx context.Context, role, mountPath, jwt string) error
}

// K8sClusterDiscovery provides Kubernetes cluster information.
// This allows for auto-discovering cluster details from within the cluster.
type K8sClusterDiscovery interface {
	// GetClusterConfig returns the Kubernetes cluster configuration.
	// If running in-cluster, this auto-discovers the details.
	GetClusterConfig(ctx context.Context) (*KubernetesClusterConfig, error)
}
