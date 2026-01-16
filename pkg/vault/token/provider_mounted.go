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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

// DefaultServiceAccountTokenPath is the default location for the mounted SA token.
const DefaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// MountedTokenProvider reads tokens from a mounted file.
// This is the legacy approach - tokens are projected into the pod filesystem.
//
// # Limitations
//
//   - Token lifetime is controlled by Kubernetes, not the application
//   - Token is shared across all uses (no audience scoping)
//   - Expiration must be parsed from the JWT itself
//
// # When to Use
//
// Use MountedTokenProvider when:
//   - Running in environments where TokenRequest API is unavailable
//   - Token lifetime requirements match the default projection
//   - Simplicity is preferred over fine-grained control
type MountedTokenProvider struct {
	tokenPath string
	log       logr.Logger
}

// NewMountedTokenProvider creates a new MountedTokenProvider.
// If tokenPath is empty, it defaults to DefaultServiceAccountTokenPath.
func NewMountedTokenProvider(tokenPath string, log logr.Logger) *MountedTokenProvider {
	if tokenPath == "" {
		tokenPath = DefaultServiceAccountTokenPath
	}
	return &MountedTokenProvider{
		tokenPath: tokenPath,
		log:       log.WithName("mounted-token-provider"),
	}
}

// GetToken reads the service account token from the mounted file.
// The Duration option is ignored for mounted tokens - the token's actual
// expiration is determined by Kubernetes token projection settings.
func (p *MountedTokenProvider) GetToken(ctx context.Context, opts GetTokenOptions) (*TokenInfo, error) {
	p.log.V(1).Info("reading mounted token", "path", p.tokenPath)

	tokenBytes, err := os.ReadFile(p.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token from %s: %w", p.tokenPath, err)
	}

	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return nil, fmt.Errorf("token file %s is empty", p.tokenPath)
	}

	// Parse JWT to extract expiration
	info, err := p.parseJWT(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	p.log.V(1).Info("successfully read mounted token",
		"expiresAt", info.ExpirationTime,
		"issuedAt", info.IssuedAt,
	)

	return info, nil
}

// parseJWT extracts claims from the JWT token without verification.
// We don't verify the signature since Vault will do that.
func (p *MountedTokenProvider) parseJWT(token string) (*TokenInfo, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims struct {
		Exp int64    `json:"exp"`
		Iat int64    `json:"iat"`
		Aud []string `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	info := &TokenInfo{
		Token:          token,
		ExpirationTime: time.Unix(claims.Exp, 0),
		IssuedAt:       time.Unix(claims.Iat, 0),
		Audiences:      claims.Aud,
	}

	return info, nil
}

// Ensure MountedTokenProvider implements TokenProvider.
var _ TokenProvider = (*MountedTokenProvider)(nil)
