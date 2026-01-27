/*
Package auth provides cloud-specific authentication helpers for Vault.

This file contains unit tests for JWT token utilities.
*/
package auth

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// createTestJWT creates a JWT for testing with the given claims
func createTestJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	// Encode as base64url
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create a fake signature (not cryptographically valid, but fine for parsing tests)
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return headerB64 + "." + claimsB64 + "." + signature
}

func TestSplitJWT(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected int
	}{
		{
			name:     "valid JWT with 3 parts",
			token:    "header.payload.signature",
			expected: 3,
		},
		{
			name:     "JWT with 2 parts",
			token:    "header.payload",
			expected: 2,
		},
		{
			name:     "JWT with 1 part",
			token:    "header",
			expected: 1,
		},
		{
			name:     "empty string",
			token:    "",
			expected: 1,
		},
		{
			name:     "JWT with 4 parts",
			token:    "a.b.c.d",
			expected: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := splitJWT(tt.token)
			if len(parts) != tt.expected {
				t.Errorf("splitJWT() returned %d parts, expected %d", len(parts), tt.expected)
			}
		})
	}
}

func TestReplaceBase64URLChars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "replace dash with plus",
			input:    "abc-def",
			expected: "abc+def",
		},
		{
			name:     "replace underscore with slash",
			input:    "abc_def",
			expected: "abc/def",
		},
		{
			name:     "replace both",
			input:    "a-b_c-d_e",
			expected: "a+b/c+d/e",
		},
		{
			name:     "no replacements needed",
			input:    "abcdef",
			expected: "abcdef",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := replaceBase64URLChars(tt.input)
			if result != tt.expected {
				t.Errorf("replaceBase64URLChars(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBase64URLDecode(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:     "standard base64url",
			input:    "SGVsbG8gV29ybGQ",
			expected: "Hello World",
		},
		{
			name:     "with padding needed (2)",
			input:    "YWI",
			expected: "ab",
		},
		{
			name:     "with padding needed (3)",
			input:    "YWJj",
			expected: "abc",
		},
		{
			name:     "with URL-safe characters",
			input:    "PDw_Pz4-",
			expected: "<<??>>",
		},
		{
			name:        "invalid base64",
			input:       "!!!invalid!!!",
			expectError: true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := base64URLDecode(tt.input)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(result) != tt.expected {
				t.Errorf("base64URLDecode(%q) = %q, expected %q", tt.input, string(result), tt.expected)
			}
		})
	}
}

func TestParseJWTClaims(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		checkClaims func(t *testing.T, claims map[string]interface{})
		expectError bool
	}{
		{
			name: "valid JWT with standard claims",
			token: createTestJWT(&testing.T{}, map[string]interface{}{
				"iss": "https://kubernetes.default.svc.cluster.local",
				"sub": "system:serviceaccount:default:my-sa",
				"aud": "vault",
				"exp": float64(time.Now().Add(time.Hour).Unix()),
				"iat": float64(time.Now().Unix()),
			}),
			checkClaims: func(t *testing.T, claims map[string]interface{}) {
				if claims["iss"] != "https://kubernetes.default.svc.cluster.local" {
					t.Errorf("unexpected issuer: %v", claims["iss"])
				}
				if claims["aud"] != "vault" {
					t.Errorf("unexpected audience: %v", claims["aud"])
				}
			},
		},
		{
			name: "JWT with array audience",
			token: createTestJWT(&testing.T{}, map[string]interface{}{
				"aud": []string{"vault", "sts.amazonaws.com"},
			}),
			checkClaims: func(t *testing.T, claims map[string]interface{}) {
				aud, ok := claims["aud"].([]interface{})
				if !ok {
					t.Errorf("expected array audience, got %T", claims["aud"])
					return
				}
				if len(aud) != 2 {
					t.Errorf("expected 2 audiences, got %d", len(aud))
				}
			},
		},
		{
			name:        "invalid JWT format - single part",
			token:       "not-a-valid-jwt",
			expectError: true,
		},
		{
			name:        "invalid JWT format - two parts",
			token:       "header.payload",
			expectError: true,
		},
		{
			name:        "invalid base64 in payload",
			token:       "eyJhbGciOiJSUzI1NiJ9.!!!invalid!!!.signature",
			expectError: true,
		},
		{
			name:        "invalid JSON in payload",
			token:       "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := parseJWTClaims(tt.token)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkClaims != nil {
				tt.checkClaims(t, claims)
			}
		})
	}
}

func TestValidateJWTClaims(t *testing.T) {
	now := time.Now()
	validExpiry := float64(now.Add(time.Hour).Unix())
	expiredExpiry := float64(now.Add(-time.Hour).Unix())

	tests := []struct {
		name             string
		claims           map[string]interface{}
		expectedIssuer   string
		expectedAudience string
		expectError      bool
		errorContains    string
	}{
		{
			name: "valid token - no validation",
			claims: map[string]interface{}{
				"iss": "https://issuer.example.com",
				"aud": "vault",
				"exp": validExpiry,
			},
			expectedIssuer:   "",
			expectedAudience: "",
			expectError:      false,
		},
		{
			name: "valid token - matching issuer",
			claims: map[string]interface{}{
				"iss": "https://issuer.example.com",
				"aud": "vault",
				"exp": validExpiry,
			},
			expectedIssuer:   "https://issuer.example.com",
			expectedAudience: "",
			expectError:      false,
		},
		{
			name: "valid token - matching string audience",
			claims: map[string]interface{}{
				"iss": "https://issuer.example.com",
				"aud": "vault",
				"exp": validExpiry,
			},
			expectedIssuer:   "",
			expectedAudience: "vault",
			expectError:      false,
		},
		{
			name: "valid token - matching array audience",
			claims: map[string]interface{}{
				"iss": "https://issuer.example.com",
				"aud": []interface{}{"vault", "api"},
				"exp": validExpiry,
			},
			expectedIssuer:   "",
			expectedAudience: "vault",
			expectError:      false,
		},
		{
			name: "invalid - wrong issuer",
			claims: map[string]interface{}{
				"iss": "https://wrong-issuer.example.com",
				"aud": "vault",
				"exp": validExpiry,
			},
			expectedIssuer: "https://issuer.example.com",
			expectError:    true,
			errorContains:  "issuer mismatch",
		},
		{
			name: "invalid - wrong string audience",
			claims: map[string]interface{}{
				"iss": "https://issuer.example.com",
				"aud": "wrong-audience",
				"exp": validExpiry,
			},
			expectedAudience: "vault",
			expectError:      true,
			errorContains:    "audience mismatch",
		},
		{
			name: "invalid - wrong array audience",
			claims: map[string]interface{}{
				"iss": "https://issuer.example.com",
				"aud": []interface{}{"other", "api"},
				"exp": validExpiry,
			},
			expectedAudience: "vault",
			expectError:      true,
			errorContains:    "audience mismatch",
		},
		{
			name: "invalid - expired token",
			claims: map[string]interface{}{
				"iss": "https://issuer.example.com",
				"aud": "vault",
				"exp": expiredExpiry,
			},
			expectError:   true,
			errorContains: "expired",
		},
		{
			name: "valid - missing issuer claim (not required)",
			claims: map[string]interface{}{
				"aud": "vault",
				"exp": validExpiry,
			},
			expectedIssuer: "https://issuer.example.com",
			expectError:    false, // Missing claim is not checked against expected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := createTestJWT(t, tt.claims)
			err := ValidateJWTClaims(token, tt.expectedIssuer, tt.expectedAudience)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorContains != "" && !containsString(err.Error(), tt.errorContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errorContains)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateJWTClaims_InvalidToken(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		errorContains string
	}{
		{
			name:          "invalid format",
			token:         "not-a-jwt",
			errorContains: "invalid JWT format",
		},
		{
			name:          "invalid base64",
			token:         "header.!!!invalid!!!.sig",
			errorContains: "failed to decode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJWTClaims(tt.token, "", "")
			if err == nil {
				t.Error("expected error but got none")
				return
			}
			if !containsString(err.Error(), tt.errorContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errorContains)
			}
		})
	}
}

func TestGetJWTFromFile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
	}{
		{
			name:    "valid token file",
			content: "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdCJ9.signature",
		},
		{
			name:    "token with whitespace",
			content: "  token-with-whitespace  ",
		},
		{
			name:    "empty file",
			content: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			tokenPath := filepath.Join(tmpDir, "token")
			if err := os.WriteFile(tokenPath, []byte(tt.content), 0600); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			token, err := GetJWTFromFile(tokenPath)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token != tt.content {
				t.Errorf("got token %q, expected %q", token, tt.content)
			}
		})
	}
}

func TestGetJWTFromFile_NotFound(t *testing.T) {
	_, err := GetJWTFromFile("/nonexistent/path/to/token")
	if err == nil {
		t.Error("expected error for nonexistent file, got none")
	}
}

func TestGetOperatorServiceAccount(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "from environment variable",
			envValue: "custom-service-account",
			expected: "custom-service-account",
		},
		{
			name:     "default when env not set",
			envValue: "",
			expected: "vault-access-operator-controller-manager",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore original env
			orig := os.Getenv("OPERATOR_SERVICE_ACCOUNT")
			defer func() {
				if orig != "" {
					os.Setenv("OPERATOR_SERVICE_ACCOUNT", orig)
				} else {
					os.Unsetenv("OPERATOR_SERVICE_ACCOUNT")
				}
			}()

			if tt.envValue != "" {
				os.Setenv("OPERATOR_SERVICE_ACCOUNT", tt.envValue)
			} else {
				os.Unsetenv("OPERATOR_SERVICE_ACCOUNT")
			}

			result := getOperatorServiceAccount()
			if result != tt.expected {
				t.Errorf("getOperatorServiceAccount() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestGetOperatorNamespace(t *testing.T) {
	tests := []struct {
		name          string
		envValue      string
		fileContent   string
		createFile    bool
		expected      string
		useDefaultDir bool
	}{
		{
			name:     "from environment variable",
			envValue: "custom-namespace",
			expected: "custom-namespace",
		},
		{
			name:       "default when env not set and file not found",
			envValue:   "",
			createFile: false,
			expected:   "vault-access-operator-system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore original env
			orig := os.Getenv("OPERATOR_NAMESPACE")
			defer func() {
				if orig != "" {
					os.Setenv("OPERATOR_NAMESPACE", orig)
				} else {
					os.Unsetenv("OPERATOR_NAMESPACE")
				}
			}()

			if tt.envValue != "" {
				os.Setenv("OPERATOR_NAMESPACE", tt.envValue)
			} else {
				os.Unsetenv("OPERATOR_NAMESPACE")
			}

			result := getOperatorNamespace()
			if result != tt.expected {
				t.Errorf("getOperatorNamespace() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// containsString checks if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
