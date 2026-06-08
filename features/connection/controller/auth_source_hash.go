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

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

// computeAuthSourceHash fingerprints the auth material a VaultConnection
// resolves to right now, so the reconciler can tell when the cached
// client was built against an out-of-date source (e.g. the user rotated
// the token in the referenced Secret).
//
// The hash MUST include every input that, if changed, would require a
// re-authenticate to stay valid. For Secret-backed methods (Token,
// AppRole, JWT/OIDC with JWTSecretRef) that's the Secret content. For
// dynamic methods (Kubernetes via TokenRequest, AWS STS, GCP IAM, or
// JWT/OIDC with the TokenRequest fallback) the per-call token rotates
// freely under a stable identity, so the hash captures only the
// identity (role + mount path) — re-hashing the rotating bearer would
// evict the cache on every reconcile and defeat the cache.
//
// Returns an error if the source can't be read (e.g., referenced Secret
// missing); callers should treat that as an auth failure rather than
// fall back to the cached client.
func (h *Handler) computeAuthSourceHash(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection,
) (string, error) {
	hasher := sha256.New()
	write := func(key, value string) {
		// Length-prefixed encoding prevents collisions across fields:
		// (key=ab, val=cde) vs (key=abc, val=de) hash differently.
		fmt.Fprintf(hasher, "%d:%s=%d:%s|", len(key), key, len(value), value)
	}

	// Address is part of the fingerprint: pointing the same connection at
	// a different Vault server (e.g., DR cluster) must force re-auth even
	// when the auth method config is otherwise identical.
	write("addr", conn.Spec.Address)

	auth := conn.Spec.Auth
	switch {
	case auth.Kubernetes != nil:
		cfg := auth.Kubernetes
		write("method", "kubernetes")
		write("role", cfg.Role)
		write("authPath", authPathOrDefault(cfg.AuthPath, defaultKubernetesAuthPath))
	case auth.Token != nil:
		tokenValue, err := h.getSecretData(ctx, &auth.Token.SecretRef)
		if err != nil {
			return "", err
		}
		write("method", "token")
		write("secret", tokenValue)
	case auth.AppRole != nil:
		cfg := auth.AppRole
		secretID, err := h.getSecretData(ctx, &cfg.SecretIDRef)
		if err != nil {
			return "", err
		}
		write("method", "approle")
		write("roleId", cfg.RoleID)
		write("secretId", secretID)
		write("mountPath", authPathOrDefault(cfg.MountPath, "approle"))
	case auth.JWT != nil:
		cfg := auth.JWT
		write("method", "jwt")
		write("role", cfg.Role)
		write("authPath", authPathOrDefault(cfg.AuthPath, "jwt"))
		if cfg.JWTSecretRef != nil {
			jwt, err := h.getSecretData(ctx, cfg.JWTSecretRef)
			if err != nil {
				return "", err
			}
			write("jwt", jwt)
		}
	case auth.OIDC != nil:
		cfg := auth.OIDC
		write("method", "oidc")
		write("role", cfg.Role)
		write("authPath", authPathOrDefault(cfg.AuthPath, "oidc"))
		if cfg.JWTSecretRef != nil {
			jwt, err := h.getSecretData(ctx, cfg.JWTSecretRef)
			if err != nil {
				return "", err
			}
			write("jwt", jwt)
		}
	case auth.AWS != nil:
		cfg := auth.AWS
		write("method", "aws")
		write("role", cfg.Role)
		write("authPath", authPathOrDefault(cfg.AuthPath, "aws"))
	case auth.GCP != nil:
		cfg := auth.GCP
		write("method", "gcp")
		write("role", cfg.Role)
		write("authPath", authPathOrDefault(cfg.AuthPath, "gcp"))
	default:
		return "", fmt.Errorf("no auth method configured")
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// authPathOrDefault returns the configured path with the default
// substituted when empty. Mirrors the per-strategy fallback in
// authStrategies so a CR that omits AuthPath hashes the same as one
// that sets it explicitly to the default — otherwise an admin
// rewriting the CR to make the default explicit would force a
// spurious re-auth.
func authPathOrDefault(path, defaultPath string) string {
	if strings.TrimSpace(path) == "" {
		return defaultPath
	}
	return path
}
