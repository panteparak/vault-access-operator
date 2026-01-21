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
	"testing"
	"time"
)

func TestLifecycleConfig_WithDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    LifecycleConfig
		expected LifecycleConfig
	}{
		{
			name:  "empty config gets all defaults",
			input: LifecycleConfig{},
			expected: LifecycleConfig{
				TokenDuration:    DefaultTokenDuration,
				RenewalThreshold: DefaultRenewalThreshold,
				MaxRetries:       DefaultMaxRetries,
				RetryInterval:    DefaultRetryInterval,
				Audiences:        []string{DefaultAudience},
				VaultAuthPath:    "kubernetes",
			},
		},
		{
			name: "custom values are preserved",
			input: LifecycleConfig{
				VaultAddress:     "https://vault.example.com:8200",
				VaultRole:        "my-role",
				VaultAuthPath:    "custom-auth",
				TokenDuration:    30 * time.Minute,
				RenewalThreshold: 0.8,
				MaxRetries:       5,
				RetryInterval:    20 * time.Second,
				Audiences:        []string{"custom-audience"},
				ServiceAccount: ServiceAccountRef{
					Namespace: "my-ns",
					Name:      "my-sa",
				},
			},
			expected: LifecycleConfig{
				VaultAddress:     "https://vault.example.com:8200",
				VaultRole:        "my-role",
				VaultAuthPath:    "custom-auth",
				TokenDuration:    30 * time.Minute,
				RenewalThreshold: 0.8,
				MaxRetries:       5,
				RetryInterval:    20 * time.Second,
				Audiences:        []string{"custom-audience"},
				ServiceAccount: ServiceAccountRef{
					Namespace: "my-ns",
					Name:      "my-sa",
				},
			},
		},
		{
			name: "partial config fills missing defaults",
			input: LifecycleConfig{
				VaultAddress:  "https://vault.example.com:8200",
				VaultRole:     "my-role",
				TokenDuration: 2 * time.Hour,
			},
			expected: LifecycleConfig{
				VaultAddress:     "https://vault.example.com:8200",
				VaultRole:        "my-role",
				VaultAuthPath:    "kubernetes",
				TokenDuration:    2 * time.Hour,
				RenewalThreshold: DefaultRenewalThreshold,
				MaxRetries:       DefaultMaxRetries,
				RetryInterval:    DefaultRetryInterval,
				Audiences:        []string{DefaultAudience},
			},
		},
		{
			name: "TLS config is preserved",
			input: LifecycleConfig{
				TLSConfig: &TLSConfig{
					CACert:     "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					SkipVerify: false,
				},
			},
			expected: LifecycleConfig{
				TokenDuration:    DefaultTokenDuration,
				RenewalThreshold: DefaultRenewalThreshold,
				MaxRetries:       DefaultMaxRetries,
				RetryInterval:    DefaultRetryInterval,
				Audiences:        []string{DefaultAudience},
				VaultAuthPath:    "kubernetes",
				TLSConfig: &TLSConfig{
					CACert:     "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					SkipVerify: false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.WithDefaults()

			// Verify it's a copy, not the original
			if &tt.input == result {
				t.Error("WithDefaults should return a copy, not the original")
			}

			// Check scalar fields
			if result.VaultAddress != tt.expected.VaultAddress {
				t.Errorf("VaultAddress = %q, want %q", result.VaultAddress, tt.expected.VaultAddress)
			}
			if result.VaultRole != tt.expected.VaultRole {
				t.Errorf("VaultRole = %q, want %q", result.VaultRole, tt.expected.VaultRole)
			}
			if result.VaultAuthPath != tt.expected.VaultAuthPath {
				t.Errorf("VaultAuthPath = %q, want %q", result.VaultAuthPath, tt.expected.VaultAuthPath)
			}
			if result.TokenDuration != tt.expected.TokenDuration {
				t.Errorf("TokenDuration = %v, want %v", result.TokenDuration, tt.expected.TokenDuration)
			}
			if result.RenewalThreshold != tt.expected.RenewalThreshold {
				t.Errorf("RenewalThreshold = %v, want %v", result.RenewalThreshold, tt.expected.RenewalThreshold)
			}
			if result.MaxRetries != tt.expected.MaxRetries {
				t.Errorf("MaxRetries = %d, want %d", result.MaxRetries, tt.expected.MaxRetries)
			}
			if result.RetryInterval != tt.expected.RetryInterval {
				t.Errorf("RetryInterval = %v, want %v", result.RetryInterval, tt.expected.RetryInterval)
			}
			if result.ServiceAccount.Namespace != tt.expected.ServiceAccount.Namespace {
				t.Errorf("ServiceAccount.Namespace = %q, want %q",
					result.ServiceAccount.Namespace, tt.expected.ServiceAccount.Namespace)
			}
			if result.ServiceAccount.Name != tt.expected.ServiceAccount.Name {
				t.Errorf("ServiceAccount.Name = %q, want %q", result.ServiceAccount.Name, tt.expected.ServiceAccount.Name)
			}

			// Check audiences
			if len(result.Audiences) != len(tt.expected.Audiences) {
				t.Errorf("Audiences length = %d, want %d", len(result.Audiences), len(tt.expected.Audiences))
			} else {
				for i, aud := range result.Audiences {
					if aud != tt.expected.Audiences[i] {
						t.Errorf("Audiences[%d] = %q, want %q", i, aud, tt.expected.Audiences[i])
					}
				}
			}

			// Check TLS config
			if tt.expected.TLSConfig == nil {
				if result.TLSConfig != nil {
					t.Errorf("TLSConfig = %v, want nil", result.TLSConfig)
				}
			} else {
				if result.TLSConfig == nil {
					t.Error("TLSConfig = nil, want non-nil")
				} else {
					if result.TLSConfig.CACert != tt.expected.TLSConfig.CACert {
						t.Errorf("TLSConfig.CACert = %q, want %q", result.TLSConfig.CACert, tt.expected.TLSConfig.CACert)
					}
					if result.TLSConfig.SkipVerify != tt.expected.TLSConfig.SkipVerify {
						t.Errorf("TLSConfig.SkipVerify = %v, want %v", result.TLSConfig.SkipVerify, tt.expected.TLSConfig.SkipVerify)
					}
				}
			}
		})
	}
}

func TestReviewerConfig_WithDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    ReviewerConfig
		expected ReviewerConfig
	}{
		{
			name:  "empty config gets all defaults",
			input: ReviewerConfig{},
			expected: ReviewerConfig{
				Duration:        DefaultReviewerDuration,
				RefreshInterval: DefaultReviewerRefreshInterval,
				VaultAuthPath:   "kubernetes",
			},
		},
		{
			name: "custom values are preserved",
			input: ReviewerConfig{
				ServiceAccount: ServiceAccountRef{
					Namespace: "vault-system",
					Name:      "token-reviewer",
				},
				Duration:        48 * time.Hour,
				RefreshInterval: 24 * time.Hour,
				VaultAuthPath:   "custom-k8s",
			},
			expected: ReviewerConfig{
				ServiceAccount: ServiceAccountRef{
					Namespace: "vault-system",
					Name:      "token-reviewer",
				},
				Duration:        48 * time.Hour,
				RefreshInterval: 24 * time.Hour,
				VaultAuthPath:   "custom-k8s",
			},
		},
		{
			name: "partial config fills missing defaults",
			input: ReviewerConfig{
				ServiceAccount: ServiceAccountRef{
					Namespace: "default",
					Name:      "reviewer",
				},
				Duration: 12 * time.Hour,
			},
			expected: ReviewerConfig{
				ServiceAccount: ServiceAccountRef{
					Namespace: "default",
					Name:      "reviewer",
				},
				Duration:        12 * time.Hour,
				RefreshInterval: DefaultReviewerRefreshInterval,
				VaultAuthPath:   "kubernetes",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.WithDefaults()

			// Verify it's a copy, not the original
			if &tt.input == result {
				t.Error("WithDefaults should return a copy, not the original")
			}

			if result.Duration != tt.expected.Duration {
				t.Errorf("Duration = %v, want %v", result.Duration, tt.expected.Duration)
			}
			if result.RefreshInterval != tt.expected.RefreshInterval {
				t.Errorf("RefreshInterval = %v, want %v", result.RefreshInterval, tt.expected.RefreshInterval)
			}
			if result.VaultAuthPath != tt.expected.VaultAuthPath {
				t.Errorf("VaultAuthPath = %q, want %q", result.VaultAuthPath, tt.expected.VaultAuthPath)
			}
			if result.ServiceAccount.Namespace != tt.expected.ServiceAccount.Namespace {
				t.Errorf("ServiceAccount.Namespace = %q, want %q",
					result.ServiceAccount.Namespace, tt.expected.ServiceAccount.Namespace)
			}
			if result.ServiceAccount.Name != tt.expected.ServiceAccount.Name {
				t.Errorf("ServiceAccount.Name = %q, want %q", result.ServiceAccount.Name, tt.expected.ServiceAccount.Name)
			}
		})
	}
}

func TestDefaultConstants(t *testing.T) {
	// Verify that default constants have reasonable values
	if DefaultTokenDuration != 1*time.Hour {
		t.Errorf("DefaultTokenDuration = %v, want 1h", DefaultTokenDuration)
	}
	if DefaultRenewalThreshold < 0 || DefaultRenewalThreshold > 1 {
		t.Errorf("DefaultRenewalThreshold = %v, want value between 0 and 1", DefaultRenewalThreshold)
	}
	if DefaultMaxRetries < 1 {
		t.Errorf("DefaultMaxRetries = %d, want at least 1", DefaultMaxRetries)
	}
	if DefaultRetryInterval < time.Second {
		t.Errorf("DefaultRetryInterval = %v, want at least 1s", DefaultRetryInterval)
	}
	if DefaultReviewerDuration < time.Hour {
		t.Errorf("DefaultReviewerDuration = %v, want at least 1h", DefaultReviewerDuration)
	}
	if DefaultReviewerRefreshInterval >= DefaultReviewerDuration {
		t.Errorf("DefaultReviewerRefreshInterval (%v) should be less than DefaultReviewerDuration (%v)",
			DefaultReviewerRefreshInterval, DefaultReviewerDuration)
	}
	if DefaultAudience != "vault" {
		t.Errorf("DefaultAudience = %q, want 'vault'", DefaultAudience)
	}
}

func TestTokenInfo_Fields(t *testing.T) {
	now := time.Now()
	expiration := now.Add(1 * time.Hour)

	info := TokenInfo{
		Token:          "test-jwt-token",
		ExpirationTime: expiration,
		IssuedAt:       now,
		Audiences:      []string{"vault", "custom"},
	}

	if info.Token != "test-jwt-token" {
		t.Errorf("Token = %q, want 'test-jwt-token'", info.Token)
	}
	if !info.ExpirationTime.Equal(expiration) {
		t.Errorf("ExpirationTime = %v, want %v", info.ExpirationTime, expiration)
	}
	if !info.IssuedAt.Equal(now) {
		t.Errorf("IssuedAt = %v, want %v", info.IssuedAt, now)
	}
	if len(info.Audiences) != 2 {
		t.Errorf("Audiences length = %d, want 2", len(info.Audiences))
	}
}

func TestAuthResult_Fields(t *testing.T) {
	expiration := time.Now().Add(1 * time.Hour)

	result := AuthResult{
		ClientToken:    "s.xxx",
		TokenTTL:       1 * time.Hour,
		Renewable:      true,
		ExpirationTime: expiration,
		Policies:       []string{"default", "my-policy"},
	}

	if result.ClientToken != "s.xxx" {
		t.Errorf("ClientToken = %q, want 's.xxx'", result.ClientToken)
	}
	if result.TokenTTL != 1*time.Hour {
		t.Errorf("TokenTTL = %v, want 1h", result.TokenTTL)
	}
	if !result.Renewable {
		t.Error("Renewable = false, want true")
	}
	if !result.ExpirationTime.Equal(expiration) {
		t.Errorf("ExpirationTime = %v, want %v", result.ExpirationTime, expiration)
	}
	if len(result.Policies) != 2 {
		t.Errorf("Policies length = %d, want 2", len(result.Policies))
	}
}

func TestTokenStatus_Fields(t *testing.T) {
	now := time.Now()
	status := TokenStatus{
		ConnectionName: "test-connection",
		Authenticated:  true,
		ExpirationTime: now.Add(1 * time.Hour),
		LastRenewal:    now,
		RenewalCount:   5,
		NextRenewal:    now.Add(45 * time.Minute),
		Error:          "",
	}

	if status.ConnectionName != "test-connection" {
		t.Errorf("ConnectionName = %q, want 'test-connection'", status.ConnectionName)
	}
	if !status.Authenticated {
		t.Error("Authenticated = false, want true")
	}
	if status.RenewalCount != 5 {
		t.Errorf("RenewalCount = %d, want 5", status.RenewalCount)
	}
	if status.Error != "" {
		t.Errorf("Error = %q, want empty", status.Error)
	}
}

func TestTokenReviewerStatus_Fields(t *testing.T) {
	now := time.Now()
	status := TokenReviewerStatus{
		ConnectionName: "test-connection",
		Enabled:        true,
		LastRefresh:    now,
		NextRefresh:    now.Add(12 * time.Hour),
		ExpirationTime: now.Add(24 * time.Hour),
		Error:          "",
	}

	if status.ConnectionName != "test-connection" {
		t.Errorf("ConnectionName = %q, want 'test-connection'", status.ConnectionName)
	}
	if !status.Enabled {
		t.Error("Enabled = false, want true")
	}
	if status.Error != "" {
		t.Errorf("Error = %q, want empty", status.Error)
	}
}

func TestServiceAccountRef_Fields(t *testing.T) {
	ref := ServiceAccountRef{
		Namespace: "kube-system",
		Name:      "default",
	}

	if ref.Namespace != "kube-system" {
		t.Errorf("Namespace = %q, want 'kube-system'", ref.Namespace)
	}
	if ref.Name != "default" {
		t.Errorf("Name = %q, want 'default'", ref.Name)
	}
}

func TestGetTokenOptions_Fields(t *testing.T) {
	opts := GetTokenOptions{
		ServiceAccount: ServiceAccountRef{
			Namespace: "default",
			Name:      "my-sa",
		},
		Duration:  1 * time.Hour,
		Audiences: []string{"vault"},
	}

	if opts.ServiceAccount.Name != "my-sa" {
		t.Errorf("ServiceAccount.Name = %q, want 'my-sa'", opts.ServiceAccount.Name)
	}
	if opts.Duration != 1*time.Hour {
		t.Errorf("Duration = %v, want 1h", opts.Duration)
	}
	if len(opts.Audiences) != 1 || opts.Audiences[0] != "vault" {
		t.Errorf("Audiences = %v, want [vault]", opts.Audiences)
	}
}
