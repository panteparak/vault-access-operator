/*
Package auth provides cloud-specific authentication helpers for Vault.

This package contains implementations for various Vault auth methods, each
optimized for specific cloud environments and authentication patterns.

# Supported Authentication Methods

  - kubernetes.go: Kubernetes service account token utilities
  - jwt.go: JWT/OIDC token utilities and TokenRequest API integration
  - aws.go: AWS IAM authentication (IRSA, EC2 instance profiles)
  - gcp.go: GCP IAM authentication (Workload Identity, GCE)

# Common Pattern

Each cloud provider module follows a consistent pattern:

 1. Options struct - Configuration for the auth method
 2. Generate* function - Creates login data or signed JWT for Vault
 3. Helper functions - Credential/metadata discovery

# Kubernetes Authentication

The simplest auth method for in-cluster workloads:

	token, err := auth.GetMountedServiceAccountToken()
	if err != nil {
	    log.Fatal(err)
	}
	// Use token with Vault's Kubernetes auth method

# JWT/OIDC Authentication

For external identity providers or TokenRequest API:

	token, expiry, err := auth.GetJWTFromTokenRequest(ctx, k8sClient, auth.JWTTokenOptions{
	    Audiences: []string{"vault"},
	    Duration:  30 * time.Minute,
	})

# AWS IAM Authentication

For EKS with IRSA or EC2 instance profiles:

	loginData, err := auth.GenerateAWSIAMLoginData(ctx, auth.AWSAuthOptions{
	    Role:   "my-vault-role",
	    Region: "us-west-2",
	})
	// Use loginData with Vault's AWS auth method

# GCP IAM Authentication

For GKE with Workload Identity:

	jwt, err := auth.GenerateGCPIAMJWT(ctx, auth.GCPAuthOptions{
	    Role:                "my-vault-role",
	    ServiceAccountEmail: "sa@project.iam.gserviceaccount.com",
	})
	// Use jwt with Vault's GCP auth method
*/
package auth
