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
	"github.com/panteparak/vault-access-operator/pkg/vault/auth"
)

// AWSLoginDataFunc generates the signed STS login payload for Vault's AWS
// IAM auth method. Defaults to auth.GenerateAWSIAMLoginData; tests inject
// an in-process fake to avoid hitting AWS.
type AWSLoginDataFunc func(ctx context.Context, opts auth.AWSAuthOptions) (map[string]interface{}, error)

// AWSProvider authenticates using Vault's AWS IAM auth method.
type AWSProvider struct {
	generate AWSLoginDataFunc
}

// NewAWSProvider returns a Provider that authenticates via AWS IAM auth.
// If generate is nil, auth.GenerateAWSIAMLoginData is used (production path).
func NewAWSProvider(generate AWSLoginDataFunc) *AWSProvider {
	if generate == nil {
		generate = auth.GenerateAWSIAMLoginData
	}
	return &AWSProvider{generate: generate}
}

func (p *AWSProvider) Applies(a vaultv1alpha1.AuthConfig) bool {
	return a.AWS != nil
}

func (p *AWSProvider) Authenticate(
	ctx context.Context, vc VaultAuthenticator, conn *vaultv1alpha1.VaultConnection,
) error {
	cfg := conn.Spec.Auth.AWS

	loginData, err := p.generate(ctx, auth.AWSAuthOptions{
		Region:                 cfg.Region,
		STSEndpoint:            cfg.STSEndpoint,
		IAMServerIDHeaderValue: cfg.IAMServerIDHeaderValue,
		Role:                   cfg.Role,
	})
	if err != nil {
		return fmt.Errorf("failed to generate AWS login data: %w", err)
	}

	authPath := cfg.AuthPath
	if authPath == "" {
		authPath = defaultAWSPath
	}
	return vc.AuthenticateAWS(ctx, cfg.Role, authPath, loginData)
}
