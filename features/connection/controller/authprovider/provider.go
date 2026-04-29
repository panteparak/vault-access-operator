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

// Package authprovider defines the AuthProvider strategy for authenticating
// a Vault client against a configured auth method. Each auth method
// (Kubernetes, Token, AppRole, JWT, OIDC, AWS, GCP) is implemented as a
// distinct Provider, and the Registry dispatches to the first provider
// whose Applies returns true.
//
// The registry's iteration order defines the priority when multiple auth
// methods are configured on a single VaultConnection. No webhook enforces
// single-auth-method, so this priority is a semantic contract.
package authprovider

import (
	"context"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// VaultAuthenticator is the narrow interface providers use to complete
// authentication against Vault. It exposes only the Authenticate* methods
// from *vault.Client that providers actually need.
type VaultAuthenticator interface {
	AuthenticateToken(token string) error
	AuthenticateKubernetesWithToken(ctx context.Context, role, mountPath, jwt string) error
	AuthenticateAppRole(ctx context.Context, roleID, secretID, mountPath string) error
	AuthenticateJWT(ctx context.Context, role, mountPath, jwt string) error
	AuthenticateOIDC(ctx context.Context, role, mountPath, jwt string) error
	AuthenticateAWS(ctx context.Context, role, mountPath string, loginData map[string]interface{}) error
	AuthenticateGCP(ctx context.Context, role, mountPath, signedJWT string) error
}

// SecretReader reads values from Kubernetes Secrets referenced by the
// VaultConnection spec. Providers depend on this interface rather than on
// a controller-runtime client so they can be tested without K8s machinery.
type SecretReader interface {
	GetSecretData(ctx context.Context, ref *vaultv1alpha1.SecretKeySelector) (string, error)
}

// Provider encapsulates a single Vault authentication strategy.
//
// Applies reports whether this provider should handle the given auth
// configuration. Implementations must inspect only their own field on
// AuthConfig; they must not look at siblings.
//
// Authenticate performs the auth login against vc. Implementations may
// return wrapped errors; the caller adds the outer context.
type Provider interface {
	Applies(auth vaultv1alpha1.AuthConfig) bool
	Authenticate(ctx context.Context, vc VaultAuthenticator, conn *vaultv1alpha1.VaultConnection) error
}

// Registry dispatches to the first provider whose Applies returns true.
// The order of providers passed to NewRegistry defines the priority.
type Registry struct {
	providers []Provider
}

// NewRegistry returns a Registry that dispatches to the given providers
// in order. The caller owns the priority: the first provider whose
// Applies returns true handles the auth, the rest are ignored.
func NewRegistry(providers ...Provider) *Registry {
	return &Registry{providers: providers}
}

// Authenticate routes to the first applicable provider.
// Returns ErrNoProviderMatched if no provider applies.
func (r *Registry) Authenticate(
	ctx context.Context,
	vc VaultAuthenticator,
	conn *vaultv1alpha1.VaultConnection,
) error {
	for _, p := range r.providers {
		if p.Applies(conn.Spec.Auth) {
			return p.Authenticate(ctx, vc, conn)
		}
	}
	return ErrNoProviderMatched
}
