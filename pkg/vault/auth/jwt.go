/*
Package auth provides cloud-specific authentication helpers for Vault.

This file provides JWT token utilities for JWT and OIDC authentication,
including integration with Kubernetes TokenRequest API for short-lived tokens.
*/
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// JWTTokenOptions contains options for JWT token acquisition
type JWTTokenOptions struct {
	// Audiences is the list of audiences for the token
	// Maps to the 'aud' claim in the JWT
	Audiences []string

	// Duration is the requested token lifetime
	Duration time.Duration

	// ServiceAccountName is the name of the service account
	// If empty, uses the operator's service account
	ServiceAccountName string

	// ServiceAccountNamespace is the namespace of the service account
	// If empty, uses the operator's namespace
	ServiceAccountNamespace string
}

// DefaultJWTAudiences are the default audiences for JWT auth
var DefaultJWTAudiences = []string{"vault"}

// DefaultTokenDuration is the default token duration
const DefaultTokenDuration = 1 * time.Hour

// GetJWTFromTokenRequest creates a JWT token using Kubernetes TokenRequest API.
// This provides short-lived tokens suitable for JWT/OIDC authentication.
func GetJWTFromTokenRequest(
	ctx context.Context,
	client kubernetes.Interface,
	opts JWTTokenOptions,
) (string, time.Time, error) {
	// Set defaults
	if len(opts.Audiences) == 0 {
		opts.Audiences = DefaultJWTAudiences
	}
	if opts.Duration == 0 {
		opts.Duration = DefaultTokenDuration
	}
	if opts.ServiceAccountName == "" {
		opts.ServiceAccountName = getOperatorServiceAccount()
	}
	if opts.ServiceAccountNamespace == "" {
		opts.ServiceAccountNamespace = getOperatorNamespace()
	}

	// Calculate expiration seconds
	expirationSeconds := int64(opts.Duration.Seconds())

	// Create TokenRequest
	tokenRequest := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         opts.Audiences,
			ExpirationSeconds: &expirationSeconds,
		},
	}

	// Request the token
	result, err := client.CoreV1().ServiceAccounts(opts.ServiceAccountNamespace).
		CreateToken(ctx, opts.ServiceAccountName, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create token request: %w", err)
	}

	expirationTime := result.Status.ExpirationTimestamp.Time
	return result.Status.Token, expirationTime, nil
}

// GetJWTFromFile reads a JWT token from a file path.
// This is used when a pre-existing JWT is available (e.g., from a mounted secret).
func GetJWTFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read JWT from file %s: %w", path, err)
	}
	return string(data), nil
}

// GetJWTFromMountedServiceAccount reads the JWT from the default
// mounted service account token path.
func GetJWTFromMountedServiceAccount() (string, error) {
	return GetJWTFromFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
}

// getOperatorServiceAccount returns the operator's service account name
func getOperatorServiceAccount() string {
	if sa := os.Getenv("OPERATOR_SERVICE_ACCOUNT"); sa != "" {
		return sa
	}
	return "vault-access-operator-controller-manager"
}

// getOperatorNamespace returns the operator's namespace
func getOperatorNamespace() string {
	if ns := os.Getenv("OPERATOR_NAMESPACE"); ns != "" {
		return ns
	}

	// Try to read from the mounted namespace file
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		return string(data)
	}

	return "vault-access-operator-system"
}

// OIDCTokenOptions contains options for OIDC token acquisition
type OIDCTokenOptions struct {
	// ProviderURL is the OIDC provider URL (issuer)
	// This is used to determine the correct audience for the token
	ProviderURL string

	// Audiences is the list of audiences for the token
	// If empty, uses the ProviderURL as the audience
	Audiences []string

	// Duration is the requested token lifetime
	Duration time.Duration

	// ServiceAccountName is the name of the service account
	ServiceAccountName string

	// ServiceAccountNamespace is the namespace of the service account
	ServiceAccountNamespace string
}

// GetOIDCToken creates a JWT token suitable for OIDC authentication.
// For EKS OIDC, the audience should typically be "sts.amazonaws.com".
func GetOIDCToken(
	ctx context.Context,
	client kubernetes.Interface,
	opts OIDCTokenOptions,
) (string, time.Time, error) {
	// Determine audiences
	audiences := opts.Audiences
	if len(audiences) == 0 && opts.ProviderURL != "" {
		// Use provider URL as default audience for OIDC
		audiences = []string{opts.ProviderURL}
	}
	if len(audiences) == 0 {
		audiences = []string{"vault"}
	}

	jwtOpts := JWTTokenOptions{
		Audiences:               audiences,
		Duration:                opts.Duration,
		ServiceAccountName:      opts.ServiceAccountName,
		ServiceAccountNamespace: opts.ServiceAccountNamespace,
	}

	return GetJWTFromTokenRequest(ctx, client, jwtOpts)
}

// ValidateJWTClaims performs basic validation of JWT claims.
// This is a pre-flight check before sending to Vault.
// Note: Full cryptographic validation is done by Vault.
func ValidateJWTClaims(token string, expectedIssuer string, expectedAudience string) error {
	// Parse JWT without verification (just to check claims format)
	// The actual verification is done by Vault
	claims, err := parseJWTClaims(token)
	if err != nil {
		return fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Check issuer if specified
	if expectedIssuer != "" {
		if iss, ok := claims["iss"].(string); ok {
			if iss != expectedIssuer {
				return fmt.Errorf("JWT issuer mismatch: got %q, expected %q", iss, expectedIssuer)
			}
		}
	}

	// Check audience if specified
	if expectedAudience != "" {
		audMatch := false
		switch aud := claims["aud"].(type) {
		case string:
			audMatch = aud == expectedAudience
		case []interface{}:
			for _, a := range aud {
				if s, ok := a.(string); ok && s == expectedAudience {
					audMatch = true
					break
				}
			}
		}
		if !audMatch {
			return fmt.Errorf("JWT audience mismatch: expected %q", expectedAudience)
		}
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return fmt.Errorf("JWT has expired")
		}
	}

	return nil
}

// parseJWTClaims extracts claims from a JWT without verification
func parseJWTClaims(token string) (map[string]interface{}, error) {
	// JWT format: header.payload.signature
	parts := splitJWT(token)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload (base64url encoded)
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON
	var claims map[string]interface{}
	if err := jsonUnmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return claims, nil
}

// splitJWT splits a JWT into its parts
func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

// base64URLDecode decodes base64url encoded data
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	// Replace URL-safe characters
	s = replaceBase64URLChars(s)

	// Use standard library
	return base64StdDecode(s)
}

// replaceBase64URLChars replaces base64url characters with standard base64
func replaceBase64URLChars(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '-':
			result[i] = '+'
		case '_':
			result[i] = '/'
		default:
			result[i] = s[i]
		}
	}
	return string(result)
}

func base64StdDecode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
