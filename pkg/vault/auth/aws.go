/*
Package auth provides cloud-specific authentication helpers for Vault.

This file implements AWS IAM authentication for Vault, supporting both:
- IAM Roles for Service Accounts (IRSA) on EKS
- EC2 instance profiles and IAM roles
*/
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSAuthOptions contains options for AWS IAM authentication
type AWSAuthOptions struct {
	// Region is the AWS region (auto-detected if empty)
	Region string

	// STSEndpoint overrides the default STS endpoint
	STSEndpoint string

	// IAMServerIDHeaderValue sets the X-Vault-AWS-IAM-Server-ID header
	// This must match the value configured in Vault's AWS auth backend
	IAMServerIDHeaderValue string

	// Role is the Vault role to authenticate as
	Role string
}

// GenerateAWSIAMLoginData generates the login data for Vault's AWS IAM auth method.
// This creates a signed STS GetCallerIdentity request that Vault uses to verify
// the AWS identity.
func GenerateAWSIAMLoginData(ctx context.Context, opts AWSAuthOptions) (map[string]interface{}, error) {
	// Load AWS configuration
	awsCfg, err := loadAWSConfig(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create STS client
	stsClient := sts.NewFromConfig(awsCfg, func(o *sts.Options) {
		if opts.STSEndpoint != "" {
			o.BaseEndpoint = aws.String(opts.STSEndpoint)
		}
	})

	// Create a presigned GetCallerIdentity request
	presignClient := sts.NewPresignClient(stsClient)

	// Build the GetCallerIdentity request
	presignedReq, err := presignClient.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{},
		func(po *sts.PresignOptions) {
			// Set expiration to 15 minutes (Vault default)
			po.Presigner = newStsPresigner(po.Presigner, opts.IAMServerIDHeaderValue)
		})
	if err != nil {
		return nil, fmt.Errorf("failed to presign GetCallerIdentity: %w", err)
	}

	// Parse the presigned URL to extract components
	parsedURL, err := url.Parse(presignedReq.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse presigned URL: %w", err)
	}

	// Build login data for Vault
	loginData := map[string]interface{}{
		"iam_http_request_method": presignedReq.Method,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(presignedReq.URL)),
		"iam_request_body":        base64.StdEncoding.EncodeToString([]byte("Action=GetCallerIdentity&Version=2011-06-15")),
		"iam_request_headers":     buildIAMRequestHeaders(parsedURL.Host, opts.IAMServerIDHeaderValue),
	}

	return loginData, nil
}

// loadAWSConfig loads AWS configuration with support for IRSA
func loadAWSConfig(ctx context.Context, opts AWSAuthOptions) (aws.Config, error) {
	var configOpts []func(*config.LoadOptions) error

	// Set region if specified
	if opts.Region != "" {
		configOpts = append(configOpts, config.WithRegion(opts.Region))
	}

	// Check for IRSA (IAM Roles for Service Accounts)
	// IRSA injects AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN
	if tokenFile := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); tokenFile != "" {
		roleARN := os.Getenv("AWS_ROLE_ARN")
		if roleARN == "" {
			return aws.Config{}, fmt.Errorf("AWS_ROLE_ARN not set but AWS_WEB_IDENTITY_TOKEN_FILE is present")
		}

		// Load base config first
		baseCfg, err := config.LoadDefaultConfig(ctx, configOpts...)
		if err != nil {
			return aws.Config{}, fmt.Errorf("failed to load base AWS config: %w", err)
		}

		// Create STS client for web identity
		stsClient := sts.NewFromConfig(baseCfg)

		// Use web identity token provider
		webIdentityProvider := stscreds.NewWebIdentityRoleProvider(
			stsClient,
			roleARN,
			stscreds.IdentityTokenFile(tokenFile),
			func(o *stscreds.WebIdentityRoleOptions) {
				if sessionName := os.Getenv("AWS_ROLE_SESSION_NAME"); sessionName != "" {
					o.RoleSessionName = sessionName
				}
			},
		)

		configOpts = append(configOpts, config.WithCredentialsProvider(webIdentityProvider))
	}

	return config.LoadDefaultConfig(ctx, configOpts...)
}

// buildIAMRequestHeaders builds the headers JSON for Vault AWS auth
func buildIAMRequestHeaders(host, serverIDHeader string) string {
	headers := map[string][]string{
		"Host":         {host},
		"Content-Type": {"application/x-www-form-urlencoded; charset=utf-8"},
	}

	if serverIDHeader != "" {
		headers["X-Vault-AWS-IAM-Server-ID"] = []string{serverIDHeader}
	}

	headersJSON, _ := json.Marshal(headers)
	return base64.StdEncoding.EncodeToString(headersJSON)
}

// stsPresigner wraps the default presigner to add custom headers
type stsPresigner struct {
	inner          sts.HTTPPresignerV4
	serverIDHeader string
}

func newStsPresigner(inner sts.HTTPPresignerV4, serverIDHeader string) *stsPresigner {
	return &stsPresigner{
		inner:          inner,
		serverIDHeader: serverIDHeader,
	}
}

func (p *stsPresigner) PresignHTTP(
	ctx context.Context, credentials aws.Credentials, r *http.Request,
	payloadHash string, service string, region string, signingTime time.Time,
	optFns ...func(*v4.SignerOptions),
) (signedURL string, signedHeader http.Header, err error) {
	// Add custom header before signing
	if p.serverIDHeader != "" {
		r.Header.Set("X-Vault-AWS-IAM-Server-ID", p.serverIDHeader)
	}
	return p.inner.PresignHTTP(ctx, credentials, r, payloadHash, service, region, signingTime, optFns...)
}

// GetAWSRegion attempts to detect the AWS region from environment or IMDS
func GetAWSRegion(ctx context.Context) (string, error) {
	// Check environment variables first
	if region := os.Getenv("AWS_REGION"); region != "" {
		return region, nil
	}
	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		return region, nil
	}

	// Try EC2 instance metadata service (IMDS)
	region, err := getRegionFromIMDS(ctx)
	if err == nil {
		return region, nil
	}

	return "", fmt.Errorf("unable to determine AWS region: %w", err)
}

// getRegionFromIMDS retrieves the region from EC2 Instance Metadata Service
func getRegionFromIMDS(ctx context.Context) (string, error) {
	// Try IMDSv2 first (with token)
	tokenURL := "http://169.254.169.254/latest/api/token"
	tokenReq, err := http.NewRequestWithContext(ctx, "PUT", tokenURL, nil)
	if err != nil {
		return "", err
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	client := &http.Client{Timeout: 2 * time.Second}
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		// Fall back to IMDSv1
		return getRegionFromIMDSv1(ctx)
	}
	defer tokenResp.Body.Close()

	tokenBytes, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(tokenBytes))

	// Use token to get region
	azURL := "http://169.254.169.254/latest/meta-data/placement/availability-zone"
	azReq, err := http.NewRequestWithContext(ctx, "GET", azURL, nil)
	if err != nil {
		return "", err
	}
	azReq.Header.Set("X-aws-ec2-metadata-token", token)

	azResp, err := client.Do(azReq)
	if err != nil {
		return "", err
	}
	defer azResp.Body.Close()

	azBytes, err := io.ReadAll(azResp.Body)
	if err != nil {
		return "", err
	}

	az := strings.TrimSpace(string(azBytes))
	if len(az) > 0 {
		// AZ is region + letter (e.g., us-west-2a -> us-west-2)
		return az[:len(az)-1], nil
	}

	return "", fmt.Errorf("empty availability zone from IMDS")
}

// getRegionFromIMDSv1 retrieves region using IMDSv1 (no token)
func getRegionFromIMDSv1(ctx context.Context) (string, error) {
	azURL := "http://169.254.169.254/latest/meta-data/placement/availability-zone"
	req, err := http.NewRequestWithContext(ctx, "GET", azURL, nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	azBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	az := strings.TrimSpace(string(azBytes))
	if len(az) > 0 {
		return az[:len(az)-1], nil
	}

	return "", fmt.Errorf("empty availability zone from IMDSv1")
}
