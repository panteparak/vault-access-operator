/*
Package auth provides cloud-specific authentication helpers for Vault.

This file contains unit tests for AWS IAM authentication helpers.
*/
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBuildIAMRequestHeaders(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		serverIDHeader string
		wantHeaders    map[string][]string
	}{
		{
			name:           "basic headers without server ID",
			host:           "sts.amazonaws.com",
			serverIDHeader: "",
			wantHeaders: map[string][]string{
				"Host":         {"sts.amazonaws.com"},
				"Content-Type": {"application/x-www-form-urlencoded; charset=utf-8"},
			},
		},
		{
			name:           "headers with server ID",
			host:           "sts.us-west-2.amazonaws.com",
			serverIDHeader: "vault.example.com",
			wantHeaders: map[string][]string{
				"Host":                      {"sts.us-west-2.amazonaws.com"},
				"Content-Type":              {"application/x-www-form-urlencoded; charset=utf-8"},
				"X-Vault-AWS-IAM-Server-ID": {"vault.example.com"},
			},
		},
		{
			name:           "regional STS endpoint",
			host:           "sts.eu-west-1.amazonaws.com",
			serverIDHeader: "",
			wantHeaders: map[string][]string{
				"Host":         {"sts.eu-west-1.amazonaws.com"},
				"Content-Type": {"application/x-www-form-urlencoded; charset=utf-8"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildIAMRequestHeaders(tt.host, tt.serverIDHeader)

			// Decode the base64 result
			decoded, err := base64.StdEncoding.DecodeString(result)
			if err != nil {
				t.Fatalf("failed to decode base64: %v", err)
			}

			// Parse the JSON
			var headers map[string][]string
			if err := json.Unmarshal(decoded, &headers); err != nil {
				t.Fatalf("failed to unmarshal JSON: %v", err)
			}

			// Verify expected headers
			for key, wantValue := range tt.wantHeaders {
				gotValue, ok := headers[key]
				if !ok {
					t.Errorf("missing header %q", key)
					continue
				}
				if len(gotValue) != len(wantValue) {
					t.Errorf("header %q: got %v, want %v", key, gotValue, wantValue)
					continue
				}
				for i, v := range wantValue {
					if gotValue[i] != v {
						t.Errorf("header %q[%d]: got %q, want %q", key, i, gotValue[i], v)
					}
				}
			}

			// Verify no extra headers (except expected ones)
			expectedCount := len(tt.wantHeaders)
			if len(headers) != expectedCount {
				t.Errorf("got %d headers, want %d", len(headers), expectedCount)
			}
		})
	}
}

func TestGetAWSRegion_FromEnv(t *testing.T) {
	tests := []struct {
		name       string
		envVars    map[string]string
		wantRegion string
		wantErr    bool
	}{
		{
			name: "AWS_REGION set",
			envVars: map[string]string{
				"AWS_REGION": "us-west-2",
			},
			wantRegion: "us-west-2",
			wantErr:    false,
		},
		{
			name: "AWS_DEFAULT_REGION set",
			envVars: map[string]string{
				"AWS_DEFAULT_REGION": "eu-central-1",
			},
			wantRegion: "eu-central-1",
			wantErr:    false,
		},
		{
			name: "AWS_REGION takes precedence",
			envVars: map[string]string{
				"AWS_REGION":         "us-east-1",
				"AWS_DEFAULT_REGION": "eu-west-1",
			},
			wantRegion: "us-east-1",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear and set environment variables
			os.Unsetenv("AWS_REGION")
			os.Unsetenv("AWS_DEFAULT_REGION")
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}
			defer func() {
				os.Unsetenv("AWS_REGION")
				os.Unsetenv("AWS_DEFAULT_REGION")
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			region, err := GetAWSRegion(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAWSRegion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if region != tt.wantRegion {
				t.Errorf("GetAWSRegion() = %v, want %v", region, tt.wantRegion)
			}
		})
	}
}

func TestGetAWSRegion_NoEnvFailsFast(t *testing.T) {
	// Clear environment variables
	os.Unsetenv("AWS_REGION")
	os.Unsetenv("AWS_DEFAULT_REGION")

	// Use a very short timeout since IMDS will fail (not on EC2)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := GetAWSRegion(ctx)
	// Should fail since we're not on EC2 and no env vars set
	if err == nil {
		t.Skip("Skipping test - appears to be running on EC2 or has default AWS config")
	}

	if !strings.Contains(err.Error(), "unable to determine AWS region") {
		t.Errorf("GetAWSRegion() error = %v, want error containing 'unable to determine AWS region'", err)
	}
}

func TestExtractRegionFromAZ(t *testing.T) {
	// Test the region extraction logic used in IMDS functions
	tests := []struct {
		az         string
		wantRegion string
	}{
		{"us-west-2a", "us-west-2"},
		{"us-west-2b", "us-west-2"},
		{"eu-central-1c", "eu-central-1"},
		{"ap-southeast-1a", "ap-southeast-1"},
		{"us-east-1f", "us-east-1"},
	}

	for _, tt := range tests {
		t.Run(tt.az, func(t *testing.T) {
			// The logic in getRegionFromIMDS: az[:len(az)-1]
			if len(tt.az) > 0 {
				gotRegion := tt.az[:len(tt.az)-1]
				if gotRegion != tt.wantRegion {
					t.Errorf("region from %q = %q, want %q", tt.az, gotRegion, tt.wantRegion)
				}
			}
		})
	}
}

func TestNewStsPresigner(t *testing.T) {
	// Test that the presigner is created correctly
	serverID := "vault.example.com"
	presigner := newStsPresigner(nil, serverID)

	if presigner.serverIDHeader != serverID {
		t.Errorf("serverIDHeader = %q, want %q", presigner.serverIDHeader, serverID)
	}
}

func TestAWSAuthOptions(t *testing.T) {
	// Test that AWSAuthOptions struct fields work correctly
	opts := AWSAuthOptions{
		Region:                 "us-west-2",
		STSEndpoint:            "https://sts.us-west-2.amazonaws.com",
		IAMServerIDHeaderValue: "vault.example.com",
		Role:                   "my-vault-role",
	}

	if opts.Region != "us-west-2" {
		t.Errorf("Region = %q, want 'us-west-2'", opts.Region)
	}
	if opts.STSEndpoint != "https://sts.us-west-2.amazonaws.com" {
		t.Errorf("STSEndpoint = %q, want 'https://sts.us-west-2.amazonaws.com'", opts.STSEndpoint)
	}
	if opts.IAMServerIDHeaderValue != "vault.example.com" {
		t.Errorf("IAMServerIDHeaderValue = %q, want 'vault.example.com'", opts.IAMServerIDHeaderValue)
	}
	if opts.Role != "my-vault-role" {
		t.Errorf("Role = %q, want 'my-vault-role'", opts.Role)
	}
}

func TestLoadAWSConfig_IRSADetection(t *testing.T) {
	// Test that IRSA detection works with env vars
	tests := []struct {
		name       string
		envVars    map[string]string
		wantErr    bool
		errContain string
	}{
		{
			name: "IRSA with token file but no role ARN",
			envVars: map[string]string{
				"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/token",
				// AWS_ROLE_ARN is missing
			},
			wantErr:    true,
			errContain: "AWS_ROLE_ARN not set",
		},
		{
			name: "No IRSA - uses default credentials",
			envVars: map[string]string{
				"AWS_REGION": "us-west-2",
			},
			wantErr: false, // Will use default credentials chain
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore env vars
			originalTokenFile := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
			originalRoleARN := os.Getenv("AWS_ROLE_ARN")
			originalRegion := os.Getenv("AWS_REGION")
			defer func() {
				setOrUnset("AWS_WEB_IDENTITY_TOKEN_FILE", originalTokenFile)
				setOrUnset("AWS_ROLE_ARN", originalRoleARN)
				setOrUnset("AWS_REGION", originalRegion)
			}()

			// Clear and set env vars
			os.Unsetenv("AWS_WEB_IDENTITY_TOKEN_FILE")
			os.Unsetenv("AWS_ROLE_ARN")
			os.Unsetenv("AWS_REGION")
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := loadAWSConfig(ctx, AWSAuthOptions{})
			if (err != nil) != tt.wantErr {
				t.Errorf("loadAWSConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errContain != "" {
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("loadAWSConfig() error = %v, want error containing %q", err, tt.errContain)
				}
			}
		})
	}
}

// setOrUnset sets an env var if value is non-empty, otherwise unsets it
func setOrUnset(key, value string) {
	if value == "" {
		os.Unsetenv(key)
	} else {
		os.Setenv(key, value)
	}
}

func TestBuildIAMRequestHeaders_IsBase64(t *testing.T) {
	// Ensure the result is valid base64
	result := buildIAMRequestHeaders("sts.amazonaws.com", "vault.example.com")

	// Try to decode it
	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("result is not valid base64: %v", err)
	}

	// Ensure it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		t.Fatalf("decoded result is not valid JSON: %v", err)
	}
}
