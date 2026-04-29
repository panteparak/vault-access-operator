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

// GCPSigners abstracts the GCP IAM and GCE identity JWT generation so the
// AuthenticateGCP flow can be tested without reaching out to Google.
type GCPSigners interface {
	GenerateIAMJWT(ctx context.Context, opts auth.GCPAuthOptions) (string, error)
	GenerateGCELoginData(ctx context.Context, opts auth.GCPAuthOptions) (map[string]interface{}, error)
}

// DefaultGCPSigners delegates to the production auth package implementations.
type DefaultGCPSigners struct{}

func (DefaultGCPSigners) GenerateIAMJWT(ctx context.Context, opts auth.GCPAuthOptions) (string, error) {
	return auth.GenerateGCPIAMJWT(ctx, opts)
}

func (DefaultGCPSigners) GenerateGCELoginData(
	ctx context.Context, opts auth.GCPAuthOptions,
) (map[string]interface{}, error) {
	return auth.GenerateGCPGCELoginData(ctx, opts)
}

// GCPProvider authenticates using Vault's GCP IAM auth method,
// supporting both "iam" and "gce" auth types.
type GCPProvider struct {
	secrets SecretReader
	signers GCPSigners
}

// NewGCPProvider returns a Provider that authenticates via GCP auth.
func NewGCPProvider(secrets SecretReader, signers GCPSigners) *GCPProvider {
	if signers == nil {
		signers = DefaultGCPSigners{}
	}
	return &GCPProvider{secrets: secrets, signers: signers}
}

func (p *GCPProvider) Applies(a vaultv1alpha1.AuthConfig) bool {
	return a.GCP != nil
}

func (p *GCPProvider) Authenticate(
	ctx context.Context, vc VaultAuthenticator, conn *vaultv1alpha1.VaultConnection,
) error {
	cfg := conn.Spec.Auth.GCP

	var credentialsJSON []byte
	if cfg.CredentialsSecretRef != nil {
		creds, err := p.secrets.GetSecretData(ctx, cfg.CredentialsSecretRef)
		if err != nil {
			return fmt.Errorf("failed to get GCP credentials from secret: %w", err)
		}
		credentialsJSON = []byte(creds)
	}

	opts := auth.GCPAuthOptions{
		AuthType:            cfg.AuthType,
		ServiceAccountEmail: cfg.ServiceAccountEmail,
		Role:                cfg.Role,
		CredentialsJSON:     credentialsJSON,
	}

	signedJWT, err := p.signJWT(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to generate GCP signed JWT: %w", err)
	}

	authPath := cfg.AuthPath
	if authPath == "" {
		authPath = defaultGCPPath
	}
	return vc.AuthenticateGCP(ctx, cfg.Role, authPath, signedJWT)
}

func (p *GCPProvider) signJWT(ctx context.Context, opts auth.GCPAuthOptions) (string, error) {
	if opts.AuthType == "" || opts.AuthType == "iam" {
		return p.signers.GenerateIAMJWT(ctx, opts)
	}

	loginData, err := p.signers.GenerateGCELoginData(ctx, opts)
	if err != nil {
		return "", err
	}
	jwt, ok := loginData["jwt"].(string)
	if !ok {
		return "", fmt.Errorf("GCE login data missing JWT")
	}
	return jwt, nil
}
