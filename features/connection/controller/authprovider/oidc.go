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

package authprovider

import (
	"context"
	"fmt"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault/token"
)

// OIDCProvider authenticates using Vault's OIDC auth method (workload
// identity federation — EKS OIDC, Azure AD, GKE, etc.).
type OIDCProvider struct {
	secrets SecretReader
	tokens  token.TokenProvider
}

// NewOIDCProvider returns a Provider that authenticates via OIDC auth.
func NewOIDCProvider(secrets SecretReader, tokens token.TokenProvider) *OIDCProvider {
	return &OIDCProvider{secrets: secrets, tokens: tokens}
}

func (p *OIDCProvider) Applies(auth vaultv1alpha1.AuthConfig) bool {
	return auth.OIDC != nil
}

func (p *OIDCProvider) Authenticate(
	ctx context.Context, vc VaultAuthenticator, conn *vaultv1alpha1.VaultConnection,
) error {
	cfg := conn.Spec.Auth.OIDC

	jwt, err := p.resolveJWT(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to get OIDC token: %w", err)
	}

	authPath := cfg.AuthPath
	if authPath == "" {
		authPath = defaultOIDCPath
	}
	return vc.AuthenticateOIDC(ctx, cfg.Role, authPath, jwt)
}

func (p *OIDCProvider) resolveJWT(ctx context.Context, cfg *vaultv1alpha1.OIDCAuth) (string, error) {
	if cfg.JWTSecretRef != nil {
		return p.secrets.GetSecretData(ctx, cfg.JWTSecretRef)
	}

	useSA := true
	if cfg.UseServiceAccountToken != nil {
		useSA = *cfg.UseServiceAccountToken
	}
	if !useSA {
		return "", fmt.Errorf("OIDC auth requires either jwtSecretRef or useServiceAccountToken=true")
	}

	if p.tokens == nil {
		return "", fmt.Errorf("token provider not configured for OIDC auth")
	}

	duration := token.DefaultTokenDuration
	if cfg.TokenDuration.Duration > 0 {
		duration = cfg.TokenDuration.Duration
	}

	audiences := cfg.Audiences
	if len(audiences) == 0 && cfg.ProviderURL != "" {
		audiences = []string{cfg.ProviderURL}
	}
	if len(audiences) == 0 {
		audiences = []string{defaultJWTAudience}
	}

	info, err := p.tokens.GetToken(ctx, token.GetTokenOptions{
		ServiceAccount: token.ServiceAccountRef{
			Name:      operatorServiceAccountName(),
			Namespace: operatorNamespace(),
		},
		Duration:  duration,
		Audiences: audiences,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get OIDC token from TokenRequest: %w", err)
	}
	return info.Token, nil
}
