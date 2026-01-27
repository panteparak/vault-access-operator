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

package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTFixtures provides utilities for creating test JWTs with various configurations.
// These are useful for testing JWT/OIDC authentication without requiring a real identity provider.
type JWTFixtures struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

// NewJWTFixtures creates a new JWTFixtures instance with a generated RSA key pair.
func NewJWTFixtures() (*JWTFixtures, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &JWTFixtures{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      "test-key-1",
	}, nil
}

// JWTOptions configures JWT generation
type JWTOptions struct {
	// Issuer claim (iss)
	Issuer string
	// Subject claim (sub)
	Subject string
	// Audience claim (aud) - can be string or []string
	Audience interface{}
	// Expiration duration from now
	ExpiresIn time.Duration
	// IssuedAt time (defaults to now)
	IssuedAt time.Time
	// Custom claims to add
	CustomClaims map[string]interface{}
}

// DefaultJWTOptions returns reasonable defaults for JWT generation
func DefaultJWTOptions() JWTOptions {
	return JWTOptions{
		Issuer:    "https://kubernetes.default.svc.cluster.local",
		Subject:   "system:serviceaccount:default:default",
		Audience:  "vault",
		ExpiresIn: 1 * time.Hour,
		IssuedAt:  time.Now(),
	}
}

// CreateJWT generates a signed JWT with the given options.
// Returns the compact serialized JWT string (header.payload.signature).
func (f *JWTFixtures) CreateJWT(opts JWTOptions) (string, error) {
	now := opts.IssuedAt
	if now.IsZero() {
		now = time.Now()
	}

	claims := jwt.MapClaims{
		"iss": opts.Issuer,
		"sub": opts.Subject,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(opts.ExpiresIn).Unix(),
	}

	// Handle audience (can be string or []string)
	switch aud := opts.Audience.(type) {
	case string:
		claims["aud"] = aud
	case []string:
		claims["aud"] = aud
	}

	// Add custom claims
	for k, v := range opts.CustomClaims {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = f.keyID

	return token.SignedString(f.privateKey)
}

// CreateExpiredJWT generates a JWT that expired in the past.
func (f *JWTFixtures) CreateExpiredJWT(issuer, subject, audience string) (string, error) {
	return f.CreateJWT(JWTOptions{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		ExpiresIn: -1 * time.Hour, // Expired 1 hour ago
		IssuedAt:  time.Now().Add(-2 * time.Hour),
	})
}

// CreateKubernetesServiceAccountJWT generates a JWT that mimics a Kubernetes service account token.
// If issuer is empty, it defaults to "https://kubernetes.default.svc.cluster.local".
func (f *JWTFixtures) CreateKubernetesServiceAccountJWT(issuer, namespace, serviceAccount string) (string, error) {
	if issuer == "" {
		issuer = "https://kubernetes.default.svc.cluster.local"
	}
	return f.CreateJWT(JWTOptions{
		Issuer:    issuer,
		Subject:   fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount),
		Audience:  "vault",
		ExpiresIn: 1 * time.Hour,
		CustomClaims: map[string]interface{}{
			"kubernetes.io/serviceaccount/namespace":            namespace,
			"kubernetes.io/serviceaccount/service-account.name": serviceAccount,
			"kubernetes.io/serviceaccount/service-account.uid":  "test-uid-12345",
		},
	})
}

// CreateOIDCJWT generates a JWT that mimics an OIDC token from an identity provider.
func (f *JWTFixtures) CreateOIDCJWT(issuer, subject, email string, audiences []string) (string, error) {
	return f.CreateJWT(JWTOptions{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audiences,
		ExpiresIn: 1 * time.Hour,
		CustomClaims: map[string]interface{}{
			"email":          email,
			"email_verified": true,
			"name":           "Test User",
		},
	})
}

// CreateAWSWebIdentityJWT generates a JWT that mimics an AWS IRSA web identity token.
func (f *JWTFixtures) CreateAWSWebIdentityJWT(
	issuer string,
	namespace, serviceAccount string,
	audiences []string,
) (string, error) {
	return f.CreateJWT(JWTOptions{
		Issuer:    issuer,
		Subject:   fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount),
		Audience:  audiences,
		ExpiresIn: 1 * time.Hour,
		CustomClaims: map[string]interface{}{
			"kubernetes.io": map[string]interface{}{
				"namespace": namespace,
				"pod": map[string]interface{}{
					"name": "test-pod",
					"uid":  "pod-uid-12345",
				},
				"serviceaccount": map[string]interface{}{
					"name": serviceAccount,
					"uid":  "sa-uid-12345",
				},
			},
		},
	})
}

// CreateGCPWorkloadIdentityJWT generates a JWT that mimics a GCP Workload Identity token.
func (f *JWTFixtures) CreateGCPWorkloadIdentityJWT(
	issuer string,
	email string,
	audiences []string,
) (string, error) {
	return f.CreateJWT(JWTOptions{
		Issuer:    issuer,
		Subject:   email,
		Audience:  audiences,
		ExpiresIn: 1 * time.Hour,
		CustomClaims: map[string]interface{}{
			"email": email,
			"azp":   email,
		},
	})
}

// GetPublicKeyPEM returns the public key in PEM format.
// This is useful for configuring Vault's JWT auth method.
func (f *JWTFixtures) GetPublicKeyPEM() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(f.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// GetJWKS returns the public key in JWKS (JSON Web Key Set) format.
// This is useful for OIDC discovery configuration.
func (f *JWTFixtures) GetJWKS() (string, error) {
	n := base64.RawURLEncoding.EncodeToString(f.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}) // 65537 in big-endian

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": f.keyID,
				"n":   n,
				"e":   e,
			},
		},
	}

	jwksJSON, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWKS: %w", err)
	}

	return string(jwksJSON), nil
}

// CreateUnsignedTestJWT creates a test JWT without cryptographic signing.
// This is useful for basic parsing tests where signature validation is not needed.
// The token is NOT suitable for actual authentication.
func CreateUnsignedTestJWT(claims map[string]interface{}) string {
	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return headerB64 + "." + claimsB64 + "."
}

// CreateTestJWTWithClaims is a convenience function for creating JWTs with specific claims.
// This uses the unsigned format suitable for parsing tests.
func CreateTestJWTWithClaims(issuer, subject, audience string, exp time.Time) string {
	claims := map[string]interface{}{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
	}
	return CreateUnsignedTestJWT(claims)
}

// ParseJWTPayload extracts and decodes the payload from a JWT without verification.
// Useful for inspecting JWT contents in tests.
func ParseJWTPayload(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode payload (part 1)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try with standard base64
		payload, err = base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT claims: %w", err)
	}

	return claims, nil
}

// VerifyJWTClaims checks that a JWT contains expected claim values.
// Returns an error if any expected claim is missing or has wrong value.
func VerifyJWTClaims(tokenString string, expected map[string]interface{}) error {
	claims, err := ParseJWTPayload(tokenString)
	if err != nil {
		return err
	}

	for key, expectedValue := range expected {
		actualValue, ok := claims[key]
		if !ok {
			return fmt.Errorf("missing claim %q", key)
		}

		// Handle different types
		switch ev := expectedValue.(type) {
		case string:
			if av, ok := actualValue.(string); !ok || av != ev {
				return fmt.Errorf("claim %q: expected %q, got %v", key, ev, actualValue)
			}
		case []string:
			// Audience can be string or []string
			switch av := actualValue.(type) {
			case string:
				if len(ev) != 1 || ev[0] != av {
					return fmt.Errorf("claim %q: expected %v, got %q", key, ev, av)
				}
			case []interface{}:
				if len(av) != len(ev) {
					return fmt.Errorf("claim %q: expected %d values, got %d", key, len(ev), len(av))
				}
				for i, v := range av {
					if s, ok := v.(string); !ok || s != ev[i] {
						return fmt.Errorf("claim %q[%d]: expected %q, got %v", key, i, ev[i], v)
					}
				}
			default:
				return fmt.Errorf("claim %q: unexpected type %T", key, actualValue)
			}
		default:
			// For other types, use simple equality
			if actualValue != expectedValue {
				return fmt.Errorf("claim %q: expected %v, got %v", key, expectedValue, actualValue)
			}
		}
	}

	return nil
}
