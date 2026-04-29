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

// KubernetesProvider authenticates using Vault's Kubernetes auth method.
// Tokens are acquired via the TokenProvider (typically the K8s TokenRequest
// API) rather than reading mounted service account tokens from disk.
type KubernetesProvider struct {
	tokens token.TokenProvider
}

// NewKubernetesProvider returns a Provider that authenticates via K8s auth.
func NewKubernetesProvider(tokens token.TokenProvider) *KubernetesProvider {
	return &KubernetesProvider{tokens: tokens}
}

func (p *KubernetesProvider) Applies(auth vaultv1alpha1.AuthConfig) bool {
	return auth.Kubernetes != nil
}

func (p *KubernetesProvider) Authenticate(
	ctx context.Context, vc VaultAuthenticator, conn *vaultv1alpha1.VaultConnection,
) error {
	if p.tokens == nil {
		return fmt.Errorf("token provider not configured")
	}
	k8s := conn.Spec.Auth.Kubernetes
	authPath := k8s.AuthPath
	if authPath == "" {
		authPath = defaultKubernetesPath
	}

	duration := token.DefaultTokenDuration
	if k8s.TokenDuration.Duration > 0 {
		duration = k8s.TokenDuration.Duration
	}

	tokenInfo, err := p.tokens.GetToken(ctx, token.GetTokenOptions{
		ServiceAccount: token.ServiceAccountRef{
			Name:      operatorServiceAccountName(),
			Namespace: operatorNamespace(),
		},
		Duration:  duration,
		Audiences: []string{token.DefaultAudience},
	})
	if err != nil {
		return fmt.Errorf("failed to get service account token: %w", err)
	}

	return vc.AuthenticateKubernetesWithToken(ctx, k8s.Role, authPath, tokenInfo.Token)
}
