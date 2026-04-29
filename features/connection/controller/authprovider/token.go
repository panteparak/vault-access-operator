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
)

// TokenProvider authenticates using a static Vault token loaded from a
// Kubernetes Secret referenced by AuthConfig.Token.SecretRef.
type TokenProvider struct {
	secrets SecretReader
}

// NewTokenProvider returns a Provider that authenticates via static token.
func NewTokenProvider(secrets SecretReader) *TokenProvider {
	return &TokenProvider{secrets: secrets}
}

func (p *TokenProvider) Applies(auth vaultv1alpha1.AuthConfig) bool {
	return auth.Token != nil
}

func (p *TokenProvider) Authenticate(
	ctx context.Context, vc VaultAuthenticator, conn *vaultv1alpha1.VaultConnection,
) error {
	tokenValue, err := p.secrets.GetSecretData(ctx, &conn.Spec.Auth.Token.SecretRef)
	if err != nil {
		return fmt.Errorf("failed to get token from secret: %w", err)
	}
	return vc.AuthenticateToken(tokenValue)
}
