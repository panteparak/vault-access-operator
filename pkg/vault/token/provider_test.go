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
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const tokenSubresource = "token"

// createTestJWT creates a JWT token with the given claims for testing.
// The token is not cryptographically valid but has the correct structure
// for parsing by parseJWT.
func createTestJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))
	return header + "." + payload + "." + sig
}

// ---------------------------------------------------------------------------
// MountedTokenProvider tests
// ---------------------------------------------------------------------------

func TestMountedTokenProvider_GetToken_Success(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	exp := now.Add(1 * time.Hour)

	jwt := createTestJWT(t, map[string]interface{}{
		"exp": exp.Unix(),
		"iat": now.Unix(),
		"aud": []string{"vault"},
	})

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(jwt), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	provider := NewMountedTokenProvider(tokenFile, logr.Discard())
	info, err := provider.GetToken(context.Background(), GetTokenOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Token != jwt {
		t.Errorf("token mismatch: got %q, want %q", info.Token, jwt)
	}
	if !info.ExpirationTime.Equal(exp) {
		t.Errorf("expiration mismatch: got %v, want %v", info.ExpirationTime, exp)
	}
	if !info.IssuedAt.Equal(now) {
		t.Errorf("issuedAt mismatch: got %v, want %v", info.IssuedAt, now)
	}
	if len(info.Audiences) != 1 || info.Audiences[0] != "vault" {
		t.Errorf("audiences mismatch: got %v, want [vault]", info.Audiences)
	}
}

func TestMountedTokenProvider_GetToken_FileNotFound(t *testing.T) {
	provider := NewMountedTokenProvider("/nonexistent/path/token", logr.Discard())
	_, err := provider.GetToken(context.Background(), GetTokenOptions{})
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

func TestMountedTokenProvider_GetToken_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	provider := NewMountedTokenProvider(tokenFile, logr.Discard())
	_, err := provider.GetToken(context.Background(), GetTokenOptions{})
	if err == nil {
		t.Fatal("expected error for empty file, got nil")
	}
}

func TestMountedTokenProvider_GetToken_InvalidJWT(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	// Write something that is not a valid JWT (only one part, not three)
	if err := os.WriteFile(tokenFile, []byte("not-a-jwt"), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	provider := NewMountedTokenProvider(tokenFile, logr.Discard())
	_, err := provider.GetToken(context.Background(), GetTokenOptions{})
	if err == nil {
		t.Fatal("expected error for invalid JWT, got nil")
	}
}

func TestMountedTokenProvider_ParseJWT_KnownClaims(t *testing.T) {
	// Use fixed timestamps for deterministic assertions
	iat := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	exp := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)

	jwt := createTestJWT(t, map[string]interface{}{
		"exp": exp.Unix(),
		"iat": iat.Unix(),
		"aud": []string{"vault", "kubernetes"},
		"sub": "system:serviceaccount:default:my-sa",
	})

	provider := NewMountedTokenProvider("", logr.Discard())
	info, err := provider.parseJWT(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Token != jwt {
		t.Errorf("token mismatch")
	}
	if !info.ExpirationTime.Equal(exp) {
		t.Errorf("exp mismatch: got %v, want %v", info.ExpirationTime, exp)
	}
	if !info.IssuedAt.Equal(iat) {
		t.Errorf("iat mismatch: got %v, want %v", info.IssuedAt, iat)
	}
	if len(info.Audiences) != 2 {
		t.Fatalf("expected 2 audiences, got %d", len(info.Audiences))
	}
	if info.Audiences[0] != "vault" || info.Audiences[1] != "kubernetes" {
		t.Errorf("audiences mismatch: got %v", info.Audiences)
	}
}

// ---------------------------------------------------------------------------
// TokenRequestProvider tests
// ---------------------------------------------------------------------------

func TestTokenRequestProvider_GetToken_Success(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	exp := now.Add(1 * time.Hour)

	clientset := fake.NewClientset()
	clientset.PrependReactor("create", "serviceaccounts",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction, ok := action.(k8stesting.CreateActionImpl)
			if !ok || createAction.GetSubresource() != tokenSubresource {
				return false, nil, nil
			}

			return true, &authenticationv1.TokenRequest{
				Status: authenticationv1.TokenRequestStatus{
					Token:               "fake-vault-token",
					ExpirationTimestamp: metav1.NewTime(exp),
				},
				ObjectMeta: metav1.ObjectMeta{
					CreationTimestamp: metav1.NewTime(now),
				},
			}, nil
		})

	provider := NewTokenRequestProvider(clientset, logr.Discard())
	info, err := provider.GetToken(context.Background(), GetTokenOptions{
		ServiceAccount: ServiceAccountRef{
			Namespace: "default",
			Name:      "my-sa",
		},
		Duration:  1 * time.Hour,
		Audiences: []string{"vault"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Token != "fake-vault-token" {
		t.Errorf("token mismatch: got %q", info.Token)
	}
	if !info.ExpirationTime.Equal(exp) {
		t.Errorf("expiration mismatch: got %v, want %v", info.ExpirationTime, exp)
	}
	if len(info.Audiences) != 1 || info.Audiences[0] != "vault" {
		t.Errorf("audiences mismatch: got %v", info.Audiences)
	}
}

func TestTokenRequestProvider_GetToken_APIError(t *testing.T) {
	clientset := fake.NewClientset()
	clientset.PrependReactor("create", "serviceaccounts",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction, ok := action.(k8stesting.CreateActionImpl)
			if !ok || createAction.GetSubresource() != tokenSubresource {
				return false, nil, nil
			}
			return true, nil, fmt.Errorf("simulated API error")
		})

	provider := NewTokenRequestProvider(clientset, logr.Discard())
	_, err := provider.GetToken(context.Background(), GetTokenOptions{
		ServiceAccount: ServiceAccountRef{
			Namespace: "default",
			Name:      "my-sa",
		},
	})
	if err == nil {
		t.Fatal("expected error from API, got nil")
	}
}

func TestTokenRequestProvider_GetToken_DefaultDuration(t *testing.T) {
	var capturedRequest *authenticationv1.TokenRequest

	clientset := fake.NewClientset()
	clientset.PrependReactor("create", "serviceaccounts",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction, ok := action.(k8stesting.CreateActionImpl)
			if !ok || createAction.GetSubresource() != tokenSubresource {
				return false, nil, nil
			}

			capturedRequest = createAction.GetObject().(*authenticationv1.TokenRequest)

			now := time.Now()
			return true, &authenticationv1.TokenRequest{
				Status: authenticationv1.TokenRequestStatus{
					Token:               "default-duration-token",
					ExpirationTimestamp: metav1.NewTime(now.Add(DefaultTokenDuration)),
				},
				ObjectMeta: metav1.ObjectMeta{
					CreationTimestamp: metav1.NewTime(now),
				},
			}, nil
		})

	provider := NewTokenRequestProvider(clientset, logr.Discard())
	_, err := provider.GetToken(context.Background(), GetTokenOptions{
		ServiceAccount: ServiceAccountRef{
			Namespace: "default",
			Name:      "my-sa",
		},
		// Duration is 0, should use DefaultTokenDuration
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedRequest == nil {
		t.Fatal("expected token request to be captured")
	}

	expectedSeconds := int64(DefaultTokenDuration.Seconds())
	if capturedRequest.Spec.ExpirationSeconds == nil {
		t.Fatal("expected ExpirationSeconds to be set")
	}
	if *capturedRequest.Spec.ExpirationSeconds != expectedSeconds {
		t.Errorf("expected default duration %d seconds, got %d",
			expectedSeconds, *capturedRequest.Spec.ExpirationSeconds)
	}
}

func TestTokenRequestProvider_GetToken_WithAudiences(t *testing.T) {
	var capturedRequest *authenticationv1.TokenRequest

	clientset := fake.NewClientset()
	clientset.PrependReactor("create", "serviceaccounts",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction, ok := action.(k8stesting.CreateActionImpl)
			if !ok || createAction.GetSubresource() != tokenSubresource {
				return false, nil, nil
			}

			capturedRequest = createAction.GetObject().(*authenticationv1.TokenRequest)

			now := time.Now()
			return true, &authenticationv1.TokenRequest{
				Status: authenticationv1.TokenRequestStatus{
					Token:               "audience-token",
					ExpirationTimestamp: metav1.NewTime(now.Add(1 * time.Hour)),
				},
				ObjectMeta: metav1.ObjectMeta{
					CreationTimestamp: metav1.NewTime(now),
				},
			}, nil
		})

	audiences := []string{"vault", "custom-audience"}
	provider := NewTokenRequestProvider(clientset, logr.Discard())
	info, err := provider.GetToken(context.Background(), GetTokenOptions{
		ServiceAccount: ServiceAccountRef{
			Namespace: "default",
			Name:      "my-sa",
		},
		Duration:  30 * time.Minute,
		Audiences: audiences,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedRequest == nil {
		t.Fatal("expected token request to be captured")
	}

	if len(capturedRequest.Spec.Audiences) != 2 {
		t.Fatalf("expected 2 audiences in request, got %d", len(capturedRequest.Spec.Audiences))
	}
	if capturedRequest.Spec.Audiences[0] != "vault" || capturedRequest.Spec.Audiences[1] != "custom-audience" {
		t.Errorf("audiences mismatch in request: got %v", capturedRequest.Spec.Audiences)
	}

	// Verify audiences are also in the returned info
	if len(info.Audiences) != 2 || info.Audiences[0] != "vault" || info.Audiences[1] != "custom-audience" {
		t.Errorf("audiences mismatch in result: got %v", info.Audiences)
	}
}

func TestTokenRequestProvider_GetToken_MissingNamespace(t *testing.T) {
	clientset := fake.NewClientset()
	provider := NewTokenRequestProvider(clientset, logr.Discard())

	_, err := provider.GetToken(context.Background(), GetTokenOptions{
		ServiceAccount: ServiceAccountRef{
			Namespace: "",
			Name:      "my-sa",
		},
	})
	if err == nil {
		t.Fatal("expected error for missing namespace, got nil")
	}
}
