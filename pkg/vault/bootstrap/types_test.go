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

package bootstrap

import (
	"testing"
	"time"

	"github.com/panteparak/vault-access-operator/pkg/vault/token"
)

func TestConfig_WithDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    Config
		expected Config
	}{
		{
			name:  "empty config gets all defaults",
			input: Config{},
			expected: Config{
				AuthMethodName:              DefaultAuthMethodName,
				TokenReviewerDuration:       DefaultTokenReviewerDuration,
				TokenReviewerServiceAccount: &token.ServiceAccountRef{},
			},
		},
		{
			name: "custom values are preserved",
			input: Config{
				BootstrapToken: "s.bootstrap-token",
				AuthMethodName: "custom-k8s",
				OperatorRole:   "vault-operator",
				OperatorPolicy: "operator-policy",
				OperatorServiceAccount: token.ServiceAccountRef{
					Namespace: "vault-system",
					Name:      "vault-operator",
				},
				AutoRevoke:            true,
				TokenReviewerDuration: 48 * time.Hour,
				TokenReviewerServiceAccount: &token.ServiceAccountRef{
					Namespace: "vault-system",
					Name:      "token-reviewer",
				},
				VaultAddress: "https://vault.example.com:8200",
				TLSConfig: &token.TLSConfig{
					CACert:     "test-ca",
					SkipVerify: false,
				},
			},
			expected: Config{
				BootstrapToken: "s.bootstrap-token",
				AuthMethodName: "custom-k8s",
				OperatorRole:   "vault-operator",
				OperatorPolicy: "operator-policy",
				OperatorServiceAccount: token.ServiceAccountRef{
					Namespace: "vault-system",
					Name:      "vault-operator",
				},
				AutoRevoke:            true,
				TokenReviewerDuration: 48 * time.Hour,
				TokenReviewerServiceAccount: &token.ServiceAccountRef{
					Namespace: "vault-system",
					Name:      "token-reviewer",
				},
				VaultAddress: "https://vault.example.com:8200",
				TLSConfig: &token.TLSConfig{
					CACert:     "test-ca",
					SkipVerify: false,
				},
			},
		},
		{
			name: "partial config fills missing defaults",
			input: Config{
				BootstrapToken: "s.xxx",
				OperatorRole:   "my-role",
				OperatorServiceAccount: token.ServiceAccountRef{
					Namespace: "default",
					Name:      "operator",
				},
			},
			expected: Config{
				BootstrapToken: "s.xxx",
				AuthMethodName: DefaultAuthMethodName,
				OperatorRole:   "my-role",
				OperatorServiceAccount: token.ServiceAccountRef{
					Namespace: "default",
					Name:      "operator",
				},
				TokenReviewerDuration: DefaultTokenReviewerDuration,
				TokenReviewerServiceAccount: &token.ServiceAccountRef{
					Namespace: "default",
					Name:      "operator",
				},
			},
		},
		{
			name: "TokenReviewerServiceAccount defaults to OperatorServiceAccount",
			input: Config{
				OperatorServiceAccount: token.ServiceAccountRef{
					Namespace: "vault-ns",
					Name:      "operator-sa",
				},
			},
			expected: Config{
				AuthMethodName: DefaultAuthMethodName,
				OperatorServiceAccount: token.ServiceAccountRef{
					Namespace: "vault-ns",
					Name:      "operator-sa",
				},
				TokenReviewerDuration: DefaultTokenReviewerDuration,
				TokenReviewerServiceAccount: &token.ServiceAccountRef{
					Namespace: "vault-ns",
					Name:      "operator-sa",
				},
			},
		},
		{
			name: "KubernetesConfig is preserved",
			input: Config{
				KubernetesConfig: &KubernetesClusterConfig{
					Host:   "https://kubernetes.default.svc",
					CACert: "k8s-ca-cert",
				},
			},
			expected: Config{
				AuthMethodName:        DefaultAuthMethodName,
				TokenReviewerDuration: DefaultTokenReviewerDuration,
				KubernetesConfig: &KubernetesClusterConfig{
					Host:   "https://kubernetes.default.svc",
					CACert: "k8s-ca-cert",
				},
				TokenReviewerServiceAccount: &token.ServiceAccountRef{},
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
			if result.BootstrapToken != tt.expected.BootstrapToken {
				t.Errorf("BootstrapToken = %q, want %q", result.BootstrapToken, tt.expected.BootstrapToken)
			}
			if result.AuthMethodName != tt.expected.AuthMethodName {
				t.Errorf("AuthMethodName = %q, want %q", result.AuthMethodName, tt.expected.AuthMethodName)
			}
			if result.OperatorRole != tt.expected.OperatorRole {
				t.Errorf("OperatorRole = %q, want %q", result.OperatorRole, tt.expected.OperatorRole)
			}
			if result.OperatorPolicy != tt.expected.OperatorPolicy {
				t.Errorf("OperatorPolicy = %q, want %q", result.OperatorPolicy, tt.expected.OperatorPolicy)
			}
			if result.AutoRevoke != tt.expected.AutoRevoke {
				t.Errorf("AutoRevoke = %v, want %v", result.AutoRevoke, tt.expected.AutoRevoke)
			}
			if result.TokenReviewerDuration != tt.expected.TokenReviewerDuration {
				t.Errorf("TokenReviewerDuration = %v, want %v", result.TokenReviewerDuration, tt.expected.TokenReviewerDuration)
			}
			if result.VaultAddress != tt.expected.VaultAddress {
				t.Errorf("VaultAddress = %q, want %q", result.VaultAddress, tt.expected.VaultAddress)
			}

			// Check OperatorServiceAccount
			if result.OperatorServiceAccount.Namespace != tt.expected.OperatorServiceAccount.Namespace {
				t.Errorf("OperatorServiceAccount.Namespace = %q, want %q",
					result.OperatorServiceAccount.Namespace, tt.expected.OperatorServiceAccount.Namespace)
			}
			if result.OperatorServiceAccount.Name != tt.expected.OperatorServiceAccount.Name {
				t.Errorf("OperatorServiceAccount.Name = %q, want %q",
					result.OperatorServiceAccount.Name, tt.expected.OperatorServiceAccount.Name)
			}

			// Check TokenReviewerServiceAccount
			if tt.expected.TokenReviewerServiceAccount == nil {
				if result.TokenReviewerServiceAccount != nil {
					t.Errorf("TokenReviewerServiceAccount = %v, want nil", result.TokenReviewerServiceAccount)
				}
			} else {
				if result.TokenReviewerServiceAccount == nil {
					t.Error("TokenReviewerServiceAccount = nil, want non-nil")
				} else {
					if result.TokenReviewerServiceAccount.Namespace != tt.expected.TokenReviewerServiceAccount.Namespace {
						t.Errorf("TokenReviewerServiceAccount.Namespace = %q, want %q",
							result.TokenReviewerServiceAccount.Namespace, tt.expected.TokenReviewerServiceAccount.Namespace)
					}
					if result.TokenReviewerServiceAccount.Name != tt.expected.TokenReviewerServiceAccount.Name {
						t.Errorf("TokenReviewerServiceAccount.Name = %q, want %q",
							result.TokenReviewerServiceAccount.Name, tt.expected.TokenReviewerServiceAccount.Name)
					}
				}
			}

			// Check KubernetesConfig
			if tt.expected.KubernetesConfig == nil {
				if result.KubernetesConfig != nil {
					t.Errorf("KubernetesConfig = %v, want nil", result.KubernetesConfig)
				}
			} else {
				if result.KubernetesConfig == nil {
					t.Error("KubernetesConfig = nil, want non-nil")
				} else {
					if result.KubernetesConfig.Host != tt.expected.KubernetesConfig.Host {
						t.Errorf("KubernetesConfig.Host = %q, want %q",
							result.KubernetesConfig.Host, tt.expected.KubernetesConfig.Host)
					}
					if result.KubernetesConfig.CACert != tt.expected.KubernetesConfig.CACert {
						t.Errorf("KubernetesConfig.CACert = %q, want %q",
							result.KubernetesConfig.CACert, tt.expected.KubernetesConfig.CACert)
					}
				}
			}

			// Check TLSConfig
			if tt.expected.TLSConfig == nil {
				if result.TLSConfig != nil {
					t.Errorf("TLSConfig = %v, want nil", result.TLSConfig)
				}
			} else {
				if result.TLSConfig == nil {
					t.Error("TLSConfig = nil, want non-nil")
				} else {
					if result.TLSConfig.CACert != tt.expected.TLSConfig.CACert {
						t.Errorf("TLSConfig.CACert = %q, want %q",
							result.TLSConfig.CACert, tt.expected.TLSConfig.CACert)
					}
					if result.TLSConfig.SkipVerify != tt.expected.TLSConfig.SkipVerify {
						t.Errorf("TLSConfig.SkipVerify = %v, want %v",
							result.TLSConfig.SkipVerify, tt.expected.TLSConfig.SkipVerify)
					}
				}
			}
		})
	}
}

func TestDefaultConstants(t *testing.T) {
	// Verify that default constants have reasonable values
	if DefaultAuthMethodName != "kubernetes" {
		t.Errorf("DefaultAuthMethodName = %q, want 'kubernetes'", DefaultAuthMethodName)
	}
	if DefaultTokenReviewerDuration < time.Hour {
		t.Errorf("DefaultTokenReviewerDuration = %v, want at least 1h", DefaultTokenReviewerDuration)
	}
}

func TestResult_Fields(t *testing.T) {
	now := time.Now()
	result := Result{
		AuthPath:                "auth/kubernetes",
		AuthMethodCreated:       true,
		RoleCreated:             true,
		BootstrapRevoked:        true,
		K8sAuthTestPassed:       true,
		TokenReviewerExpiration: now.Add(24 * time.Hour),
	}

	if result.AuthPath != "auth/kubernetes" {
		t.Errorf("AuthPath = %q, want 'auth/kubernetes'", result.AuthPath)
	}
	if !result.AuthMethodCreated {
		t.Error("AuthMethodCreated = false, want true")
	}
	if !result.RoleCreated {
		t.Error("RoleCreated = false, want true")
	}
	if !result.BootstrapRevoked {
		t.Error("BootstrapRevoked = false, want true")
	}
	if !result.K8sAuthTestPassed {
		t.Error("K8sAuthTestPassed = false, want true")
	}
	if result.TokenReviewerExpiration.Before(now) {
		t.Errorf("TokenReviewerExpiration = %v, want after %v", result.TokenReviewerExpiration, now)
	}
}

func TestKubernetesClusterConfig_Fields(t *testing.T) {
	config := KubernetesClusterConfig{
		Host:   "https://kubernetes.default.svc:443",
		CACert: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}

	if config.Host != "https://kubernetes.default.svc:443" {
		t.Errorf("Host = %q, want 'https://kubernetes.default.svc:443'", config.Host)
	}
	if config.CACert == "" {
		t.Error("CACert = empty, want non-empty")
	}
}
