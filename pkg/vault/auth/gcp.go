/*
Package auth provides cloud-specific authentication helpers for Vault.

This file implements GCP IAM authentication for Vault, supporting:
- Workload Identity for GKE
- Service account key authentication
- Application Default Credentials (ADC)
*/
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

// GCPAuthOptions contains options for GCP IAM authentication
type GCPAuthOptions struct {
	// AuthType is "iam" or "gce"
	AuthType string

	// ServiceAccountEmail is the GCP service account email
	// If empty, attempts to auto-detect from metadata server
	ServiceAccountEmail string

	// Role is the Vault role to authenticate as
	Role string

	// CredentialsJSON is optional GCP credentials JSON
	// If empty, uses Application Default Credentials or Workload Identity
	CredentialsJSON []byte
}

// GenerateGCPIAMJWT generates a signed JWT for Vault's GCP IAM auth method.
// The JWT is signed by GCP's IAM service to prove identity.
func GenerateGCPIAMJWT(ctx context.Context, opts GCPAuthOptions) (string, error) {
	// Get service account email
	saEmail := opts.ServiceAccountEmail
	if saEmail == "" {
		var err error
		saEmail, err = GetGCPServiceAccountEmail(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to determine service account email: %w", err)
		}
	}

	// Create IAM credentials client
	var clientOpts []option.ClientOption
	if len(opts.CredentialsJSON) > 0 {
		// Parse credentials JSON to create a credentials object
		creds, err := google.CredentialsFromJSON(ctx, opts.CredentialsJSON,
			iamcredentials.CloudPlatformScope)
		if err != nil {
			return "", fmt.Errorf("failed to parse credentials JSON: %w", err)
		}
		clientOpts = append(clientOpts, option.WithCredentials(creds))
	}

	iamService, err := iamcredentials.NewService(ctx, clientOpts...)
	if err != nil {
		return "", fmt.Errorf("failed to create IAM credentials service: %w", err)
	}

	// Build the JWT claims for Vault
	now := time.Now()
	claims := map[string]interface{}{
		"aud": fmt.Sprintf("vault/%s", opts.Role),
		"sub": saEmail,
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT claims: %w", err)
	}

	// Sign the JWT using GCP IAM
	name := fmt.Sprintf("projects/-/serviceAccounts/%s", saEmail)
	signReq := &iamcredentials.SignJwtRequest{
		Payload: string(claimsJSON),
	}

	signResp, err := iamService.Projects.ServiceAccounts.SignJwt(name, signReq).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return signResp.SignedJwt, nil
}

// GenerateGCPGCELoginData generates login data for Vault's GCP GCE auth method.
// This uses the instance identity token from the metadata server.
func GenerateGCPGCELoginData(ctx context.Context, opts GCPAuthOptions) (map[string]interface{}, error) {
	// Get instance identity token from metadata server
	identityToken, err := getGCEIdentityToken(ctx, opts.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to get GCE identity token: %w", err)
	}

	return map[string]interface{}{
		"role": opts.Role,
		"jwt":  identityToken,
	}, nil
}

// GetGCPServiceAccountEmail retrieves the service account email.
// It first checks for Workload Identity, then metadata server.
func GetGCPServiceAccountEmail(ctx context.Context) (string, error) {
	// Try to get from environment (useful for testing)
	if email := os.Getenv("GOOGLE_SERVICE_ACCOUNT_EMAIL"); email != "" {
		return email, nil
	}

	// Try to get from Application Default Credentials
	creds, err := google.FindDefaultCredentials(ctx)
	if err == nil && creds.JSON != nil {
		var credData struct {
			ClientEmail string `json:"client_email"`
		}
		if json.Unmarshal(creds.JSON, &credData) == nil && credData.ClientEmail != "" {
			return credData.ClientEmail, nil
		}
	}

	// Try metadata server
	return getServiceAccountFromMetadata(ctx)
}

// getServiceAccountFromMetadata retrieves the service account email from GCE metadata
func getServiceAccountFromMetadata(ctx context.Context) (string, error) {
	metadataURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata request returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	email := strings.TrimSpace(string(body))
	if email == "" {
		return "", fmt.Errorf("empty service account email from metadata")
	}

	return email, nil
}

// getGCEIdentityToken retrieves an identity token from the GCE metadata server
func getGCEIdentityToken(ctx context.Context, audience string) (string, error) {
	baseURL := "http://metadata.google.internal/computeMetadata/v1"
	metadataURL := fmt.Sprintf(
		"%s/instance/service-accounts/default/identity?audience=vault/%s&format=full",
		baseURL, audience,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("identity token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("identity token request returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("empty identity token from metadata")
	}

	return token, nil
}

// GetGCPProjectID retrieves the current GCP project ID
func GetGCPProjectID(ctx context.Context) (string, error) {
	// Try environment variable first
	if projectID := os.Getenv("GOOGLE_CLOUD_PROJECT"); projectID != "" {
		return projectID, nil
	}
	if projectID := os.Getenv("GCP_PROJECT"); projectID != "" {
		return projectID, nil
	}
	if projectID := os.Getenv("GCLOUD_PROJECT"); projectID != "" {
		return projectID, nil
	}

	// Try Application Default Credentials
	creds, err := google.FindDefaultCredentials(ctx)
	if err == nil && creds.ProjectID != "" {
		return creds.ProjectID, nil
	}

	// Try metadata server
	return getProjectIDFromMetadata(ctx)
}

// getProjectIDFromMetadata retrieves the project ID from GCE metadata
func getProjectIDFromMetadata(ctx context.Context) (string, error) {
	metadataURL := "http://metadata.google.internal/computeMetadata/v1/project/project-id"

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("project ID metadata request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("project ID metadata request returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	projectID := strings.TrimSpace(string(body))
	if projectID == "" {
		return "", fmt.Errorf("empty project ID from metadata")
	}

	return projectID, nil
}
