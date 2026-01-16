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

package token

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// TokenRequestProvider uses the Kubernetes TokenRequest API to acquire tokens.
// This is the recommended approach for obtaining service account tokens.
//
// # Advantages
//
//   - Fine-grained control over token lifetime
//   - Audience scoping for security
//   - Tokens are bound to specific purposes
//   - Explicit expiration tracking
//
// # Requirements
//
//   - Kubernetes 1.20+ (TokenRequest API GA)
//   - RBAC: create serviceaccounts/token in target namespace
//
// # Usage
//
//	provider := NewTokenRequestProvider(clientset, log)
//	info, err := provider.GetToken(ctx, GetTokenOptions{
//	    ServiceAccount: ServiceAccountRef{Namespace: "default", Name: "my-sa"},
//	    Duration:       time.Hour,
//	    Audiences:      []string{"vault"},
//	})
type TokenRequestProvider struct {
	clientset kubernetes.Interface
	log       logr.Logger
}

// NewTokenRequestProvider creates a new TokenRequestProvider.
func NewTokenRequestProvider(clientset kubernetes.Interface, log logr.Logger) *TokenRequestProvider {
	return &TokenRequestProvider{
		clientset: clientset,
		log:       log.WithName("tokenrequest-provider"),
	}
}

// GetToken uses the Kubernetes TokenRequest API to create a new token.
// The token is scoped to the specified audiences and has the requested duration.
func (p *TokenRequestProvider) GetToken(ctx context.Context, opts GetTokenOptions) (*TokenInfo, error) {
	if opts.ServiceAccount.Namespace == "" || opts.ServiceAccount.Name == "" {
		return nil, fmt.Errorf("service account namespace and name are required")
	}

	// Apply defaults
	duration := opts.Duration
	if duration == 0 {
		duration = DefaultTokenDuration
	}

	audiences := opts.Audiences
	if len(audiences) == 0 {
		audiences = []string{DefaultAudience}
	}

	p.log.V(1).Info("requesting token via TokenRequest API",
		"namespace", opts.ServiceAccount.Namespace,
		"serviceAccount", opts.ServiceAccount.Name,
		"duration", duration,
		"audiences", audiences,
	)

	// Convert duration to seconds for the API
	expirationSeconds := int64(duration.Seconds())

	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: &expirationSeconds,
		},
	}

	result, err := p.clientset.CoreV1().ServiceAccounts(opts.ServiceAccount.Namespace).
		CreateToken(ctx, opts.ServiceAccount.Name, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create token for %s/%s: %w",
			opts.ServiceAccount.Namespace, opts.ServiceAccount.Name, err)
	}

	info := &TokenInfo{
		Token:          result.Status.Token,
		ExpirationTime: result.Status.ExpirationTimestamp.Time,
		IssuedAt:       result.CreationTimestamp.Time,
		Audiences:      audiences,
	}

	p.log.V(1).Info("successfully acquired token via TokenRequest API",
		"expiresAt", info.ExpirationTime,
		"issuedAt", info.IssuedAt,
	)

	return info, nil
}

// Ensure TokenRequestProvider implements TokenProvider.
var _ TokenProvider = (*TokenRequestProvider)(nil)
