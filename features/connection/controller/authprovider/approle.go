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

// AppRoleProvider authenticates using Vault's AppRole method.
// RoleID is taken from the CRD spec; SecretID is resolved from a K8s Secret.
type AppRoleProvider struct {
	secrets SecretReader
}

// NewAppRoleProvider returns a Provider that authenticates via AppRole.
func NewAppRoleProvider(secrets SecretReader) *AppRoleProvider {
	return &AppRoleProvider{secrets: secrets}
}

func (p *AppRoleProvider) Applies(auth vaultv1alpha1.AuthConfig) bool {
	return auth.AppRole != nil
}

func (p *AppRoleProvider) Authenticate(
	ctx context.Context, vc VaultAuthenticator, conn *vaultv1alpha1.VaultConnection,
) error {
	cfg := conn.Spec.Auth.AppRole
	secretID, err := p.secrets.GetSecretData(ctx, &cfg.SecretIDRef)
	if err != nil {
		return fmt.Errorf("failed to get secret ID from secret: %w", err)
	}
	mountPath := cfg.MountPath
	if mountPath == "" {
		mountPath = defaultAppRolePath
	}
	return vc.AuthenticateAppRole(ctx, cfg.RoleID, secretID, mountPath)
}
