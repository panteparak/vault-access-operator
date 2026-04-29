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

// JWTProvider authenticates using Vault's JWT auth method.
// The JWT is either loaded from a K8s Secret or minted via TokenRequest API.
type JWTProvider struct {
	secrets SecretReader
	tokens  token.TokenProvider
}

// NewJWTProvider returns a Provider that authenticates via JWT auth.
func NewJWTProvider(secrets SecretReader, tokens token.TokenProvider) *JWTProvider {
	return &JWTProvider{secrets: secrets, tokens: tokens}
}

func (p *JWTProvider) Applies(auth vaultv1alpha1.AuthConfig) bool {
	return auth.JWT != nil
}

func (p *JWTProvider) Authenticate(
	ctx context.Context, vc VaultAuthenticator, conn *vaultv1alpha1.VaultConnection,
) error {
	cfg := conn.Spec.Auth.JWT

	jwt, err := p.resolveJWT(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to get JWT: %w", err)
	}

	authPath := cfg.AuthPath
	if authPath == "" {
		authPath = defaultJWTPath
	}
	return vc.AuthenticateJWT(ctx, cfg.Role, authPath, jwt)
}

func (p *JWTProvider) resolveJWT(ctx context.Context, cfg *vaultv1alpha1.JWTAuth) (string, error) {
	if cfg.JWTSecretRef != nil {
		return p.secrets.GetSecretData(ctx, cfg.JWTSecretRef)
	}

	if p.tokens == nil {
		return "", fmt.Errorf("token provider not configured for JWT auth")
	}

	duration := token.DefaultTokenDuration
	if cfg.TokenDuration.Duration > 0 {
		duration = cfg.TokenDuration.Duration
	}

	audiences := cfg.Audiences
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
		return "", fmt.Errorf("failed to get JWT from TokenRequest: %w", err)
	}
	return info.Token, nil
}
