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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultConnectionSpec defines the desired state of VaultConnection.
type VaultConnectionSpec struct {
	// Address is the Vault server address (e.g., https://vault.example.com:8200)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^https?://`
	Address string `json:"address"`

	// TLS configuration for the Vault connection
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`

	// Auth configuration for authenticating to Vault
	// +kubebuilder:validation:Required
	Auth AuthConfig `json:"auth"`

	// Defaults for various Vault paths
	// +optional
	Defaults *ConnectionDefaults `json:"defaults,omitempty"`

	// HealthCheckInterval defines how often to check Vault connectivity
	// +kubebuilder:default="30s"
	// +optional
	HealthCheckInterval string `json:"healthCheckInterval,omitempty"`
}

// TLSConfig defines TLS settings for Vault connection
type TLSConfig struct {
	// SkipVerify disables TLS certificate verification
	// +optional
	SkipVerify bool `json:"skipVerify,omitempty"`

	// CASecretRef references a secret containing the CA certificate
	// +optional
	CASecretRef *SecretKeySelector `json:"caSecretRef,omitempty"`
}

// AuthConfig defines authentication settings for Vault.
// Supports multiple auth methods: bootstrap, Kubernetes, Token, AppRole, JWT, OIDC, AWS, and GCP.
// Only one auth method should be configured at a time (enforced by webhook).
type AuthConfig struct {
	// Bootstrap enables one-time setup of Kubernetes auth.
	// After bootstrap succeeds, the operator uses Kubernetes auth exclusively.
	// +optional
	Bootstrap *BootstrapAuth `json:"bootstrap,omitempty"`

	// Kubernetes auth method configuration
	// +optional
	Kubernetes *KubernetesAuth `json:"kubernetes,omitempty"`

	// Token auth method configuration
	// +optional
	Token *TokenAuth `json:"token,omitempty"`

	// AppRole auth method configuration
	// +optional
	AppRole *AppRoleAuth `json:"appRole,omitempty"`

	// JWT auth method configuration for external identity providers
	// +optional
	JWT *JWTAuth `json:"jwt,omitempty"`

	// OIDC auth method configuration for OpenID Connect providers (e.g., EKS OIDC)
	// +optional
	OIDC *OIDCAuth `json:"oidc,omitempty"`

	// AWS auth method configuration for AWS IAM authentication (EKS/IRSA)
	// +optional
	AWS *AWSAuth `json:"aws,omitempty"`

	// GCP auth method configuration for GCP IAM authentication (GKE Workload Identity)
	// +optional
	GCP *GCPAuth `json:"gcp,omitempty"`
}

// BootstrapAuth configures one-time bootstrap authentication.
// Use this when Vault's Kubernetes auth method needs to be set up initially.
type BootstrapAuth struct {
	// SecretRef references a secret containing the bootstrap Vault token.
	// This token should have permissions to enable and configure auth methods.
	// +kubebuilder:validation:Required
	SecretRef SecretKeySelector `json:"secretRef"`

	// AutoRevoke revokes the bootstrap token after successful setup.
	// +kubebuilder:default=true
	// +optional
	AutoRevoke *bool `json:"autoRevoke,omitempty"`
}

// KubernetesAuth defines Kubernetes auth method settings.
// Only the Role field is required - everything else uses smart defaults.
type KubernetesAuth struct {
	// Role is the Vault role to authenticate as.
	// This is the Vault role (not K8s role) created in Vault's Kubernetes auth config.
	// +kubebuilder:validation:Required
	Role string `json:"role"`

	// AuthPath is the Vault auth mount path (default: "kubernetes").
	// Use a custom path if the Kubernetes auth method is mounted elsewhere.
	// +kubebuilder:default="kubernetes"
	// +optional
	AuthPath string `json:"authPath,omitempty"`

	// TokenDuration is the requested service account token lifetime.
	// Uses Kubernetes TokenRequest API for short-lived tokens.
	// +kubebuilder:default="1h"
	// +optional
	TokenDuration metav1.Duration `json:"tokenDuration,omitempty"`

	// TokenReviewerRotation enables automatic token_reviewer_jwt rotation.
	// IMPORTANT: When disabled, you must manually manage token_reviewer_jwt
	// or all Kubernetes auth will fail when the JWT expires.
	// +kubebuilder:default=true
	// +optional
	TokenReviewerRotation *bool `json:"tokenReviewerRotation,omitempty"`
}

// TokenAuth defines token auth method settings
type TokenAuth struct {
	// SecretRef references a secret containing the Vault token
	// +kubebuilder:validation:Required
	SecretRef SecretKeySelector `json:"secretRef"`
}

// AppRoleAuth defines AppRole auth method settings
type AppRoleAuth struct {
	// RoleID is the AppRole role ID
	// +kubebuilder:validation:Required
	RoleID string `json:"roleId"`

	// SecretIDRef references a secret containing the AppRole secret ID
	// +kubebuilder:validation:Required
	SecretIDRef SecretKeySelector `json:"secretIdRef"`

	// MountPath is the mount path of the AppRole auth method
	// +kubebuilder:default="approle"
	// +optional
	MountPath string `json:"mountPath,omitempty"`
}

// JWTAuth configures JWT authentication with external identity providers.
// Use this for generic JWT-based authentication from any identity provider.
type JWTAuth struct {
	// Role is the Vault role configured for JWT auth
	// +kubebuilder:validation:Required
	Role string `json:"role"`

	// AuthPath is the mount path for JWT auth (default: "jwt")
	// +kubebuilder:default="jwt"
	// +optional
	AuthPath string `json:"authPath,omitempty"`

	// JWTSecretRef references a secret containing the JWT token.
	// If not provided, uses the mounted service account token via TokenRequest API.
	// +optional
	JWTSecretRef *SecretKeySelector `json:"jwtSecretRef,omitempty"`

	// Audiences is the list of audiences to include in the token request.
	// Maps to the 'aud' claim in the generated JWT.
	// If not specified, defaults to ["vault"].
	// +optional
	Audiences []string `json:"audiences,omitempty"`

	// TokenDuration is the requested service account token lifetime.
	// Controls the 'exp' claim in the generated JWT.
	// +kubebuilder:default="1h"
	// +optional
	TokenDuration metav1.Duration `json:"tokenDuration,omitempty"`

	// ExpectedIssuer is the expected 'iss' claim value.
	// Used for documentation and validation at the operator level.
	// Vault validates this against bound_issuer in the auth config.
	// +optional
	ExpectedIssuer string `json:"expectedIssuer,omitempty"`

	// ExpectedAudience is the expected 'aud' claim value for validation.
	// Used for documentation and pre-flight checks.
	// Vault validates this against bound_audiences in the auth config.
	// +optional
	ExpectedAudience string `json:"expectedAudience,omitempty"`

	// UserClaim specifies which claim to use for the Vault entity alias.
	// Common values: "sub", "email", "name". Vault default is "sub".
	// This must match the user_claim in the Vault role configuration.
	// +optional
	UserClaim string `json:"userClaim,omitempty"`

	// GroupsClaim specifies which claim contains group membership.
	// Common values: "groups", "roles", "cognito:groups".
	// This must match the groups_claim in the Vault role configuration.
	// +optional
	GroupsClaim string `json:"groupsClaim,omitempty"`

	// ClaimsToPass is a list of JWT claims to include in the auth response metadata.
	// Useful for passing identity information to policies via identity templating.
	// +optional
	ClaimsToPass []string `json:"claimsToPass,omitempty"`
}

// OIDCAuth configures OIDC authentication with OpenID Connect providers.
// Use this for workload identity federation (e.g., EKS OIDC, Azure AD, GKE).
type OIDCAuth struct {
	// Role is the Vault role configured for OIDC auth
	// +kubebuilder:validation:Required
	Role string `json:"role"`

	// AuthPath is the mount path for OIDC auth (default: "oidc")
	// +kubebuilder:default="oidc"
	// +optional
	AuthPath string `json:"authPath,omitempty"`

	// ProviderURL is the OIDC provider URL for discovery.
	// Format examples:
	//   - EKS: https://oidc.eks.<region>.amazonaws.com/id/<cluster-id>
	//   - GKE: https://container.googleapis.com/v1/projects/<project>/locations/<zone>/clusters/<name>
	//   - Azure AD: https://login.microsoftonline.com/<tenant>/v2.0
	// +optional
	ProviderURL string `json:"providerURL,omitempty"`

	// UseServiceAccountToken uses the K8s SA token for OIDC auth.
	// The SA token contains the OIDC issuer claim for verification.
	// +kubebuilder:default=true
	// +optional
	UseServiceAccountToken *bool `json:"useServiceAccountToken,omitempty"`

	// Audiences is the list of audiences to include in the token request.
	// For OIDC, this should match the client_id configured in Vault's OIDC auth.
	// Default: uses the ProviderURL as the audience if not specified.
	// +optional
	Audiences []string `json:"audiences,omitempty"`

	// TokenDuration is the requested service account token lifetime.
	// +kubebuilder:default="1h"
	// +optional
	TokenDuration metav1.Duration `json:"tokenDuration,omitempty"`

	// JWTSecretRef references a secret containing a pre-obtained JWT.
	// Use this instead of SA token when you have an external OIDC token.
	// +optional
	JWTSecretRef *SecretKeySelector `json:"jwtSecretRef,omitempty"`

	// UserClaim specifies which claim to use for the Vault entity alias.
	// Common values: "sub", "email", "preferred_username".
	// +optional
	UserClaim string `json:"userClaim,omitempty"`

	// GroupsClaim specifies which claim contains group membership.
	// +optional
	GroupsClaim string `json:"groupsClaim,omitempty"`

	// Scopes specifies the OIDC scopes to request (for browser-based OIDC flow).
	// Not used when using SA token, but useful for documentation.
	// +optional
	Scopes []string `json:"scopes,omitempty"`
}

// AWSAuth configures AWS IAM authentication for EKS workloads.
// Supports both IAM roles (IRSA) and EC2 instance profiles.
type AWSAuth struct {
	// Role is the Vault role configured for AWS auth
	// +kubebuilder:validation:Required
	Role string `json:"role"`

	// AuthPath is the mount path for AWS auth (default: "aws")
	// +kubebuilder:default="aws"
	// +optional
	AuthPath string `json:"authPath,omitempty"`

	// AuthType is the AWS auth method type: "iam" or "ec2"
	// +kubebuilder:validation:Enum=iam;ec2
	// +kubebuilder:default="iam"
	// +optional
	AuthType string `json:"authType,omitempty"`

	// Region is the AWS region (auto-detected if not specified)
	// +optional
	Region string `json:"region,omitempty"`

	// STSEndpoint overrides the default STS endpoint
	// +optional
	STSEndpoint string `json:"stsEndpoint,omitempty"`

	// IAMServerIDHeaderValue sets the X-Vault-AWS-IAM-Server-ID header
	// for additional security. Must match the server_id_header_value
	// configured in Vault's AWS auth backend.
	// +optional
	IAMServerIDHeaderValue string `json:"iamServerIdHeaderValue,omitempty"`
}

// GCPAuth configures GCP IAM authentication for GKE workloads.
// Supports both IAM and GCE auth types.
type GCPAuth struct {
	// Role is the Vault role configured for GCP auth
	// +kubebuilder:validation:Required
	Role string `json:"role"`

	// AuthPath is the mount path for GCP auth (default: "gcp")
	// +kubebuilder:default="gcp"
	// +optional
	AuthPath string `json:"authPath,omitempty"`

	// AuthType is the GCP auth method type: "iam" or "gce"
	// +kubebuilder:validation:Enum=iam;gce
	// +kubebuilder:default="iam"
	// +optional
	AuthType string `json:"authType,omitempty"`

	// ServiceAccountEmail is the GCP service account email.
	// If not specified, uses the default service account from metadata server.
	// +optional
	ServiceAccountEmail string `json:"serviceAccountEmail,omitempty"`

	// CredentialsSecretRef references a secret containing GCP credentials JSON.
	// If not specified, uses Workload Identity or Application Default Credentials.
	// +optional
	CredentialsSecretRef *SecretKeySelector `json:"credentialsSecretRef,omitempty"`
}

// ConnectionDefaults defines default paths for Vault operations
type ConnectionDefaults struct {
	// SecretEnginePath is the default path for secret engines
	// +optional
	SecretEnginePath string `json:"secretEnginePath,omitempty"`

	// TransitPath is the default path for the transit engine
	// +optional
	TransitPath string `json:"transitPath,omitempty"`

	// AuthPath is the default path for auth methods
	// +kubebuilder:default="auth/kubernetes"
	// +optional
	AuthPath string `json:"authPath,omitempty"`
}

// VaultConnectionStatus defines the observed state of VaultConnection.
type VaultConnectionStatus struct {
	// Phase represents the current phase of the connection
	// +optional
	Phase Phase `json:"phase,omitempty"`

	// VaultVersion is the version of the connected Vault server
	// +optional
	VaultVersion string `json:"vaultVersion,omitempty"`

	// LastHeartbeat is the time of the last successful health check
	// +optional
	LastHeartbeat *metav1.Time `json:"lastHeartbeat,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`

	// Message provides additional information about the current state
	// +optional
	Message string `json:"message,omitempty"`

	// AuthStatus contains authentication-related status information
	// +optional
	AuthStatus *AuthStatus `json:"authStatus,omitempty"`
}

// AuthStatus contains authentication-related status information.
type AuthStatus struct {
	// BootstrapComplete indicates if bootstrap has been completed
	// +optional
	BootstrapComplete bool `json:"bootstrapComplete,omitempty"`

	// BootstrapCompletedAt is when bootstrap was completed
	// +optional
	BootstrapCompletedAt *metav1.Time `json:"bootstrapCompletedAt,omitempty"`

	// AuthMethod is the currently active authentication method
	// +optional
	AuthMethod string `json:"authMethod,omitempty"`

	// TokenExpiration is when the current Vault token expires
	// +optional
	TokenExpiration *metav1.Time `json:"tokenExpiration,omitempty"`

	// TokenLastRenewed is when the token was last renewed
	// +optional
	TokenLastRenewed *metav1.Time `json:"tokenLastRenewed,omitempty"`

	// TokenRenewalCount is how many times the token has been renewed
	// +optional
	TokenRenewalCount int `json:"tokenRenewalCount,omitempty"`

	// TokenReviewerExpiration is when the token_reviewer_jwt expires
	// +optional
	TokenReviewerExpiration *metav1.Time `json:"tokenReviewerExpiration,omitempty"`

	// TokenReviewerLastRefresh is when token_reviewer_jwt was last refreshed
	// +optional
	TokenReviewerLastRefresh *metav1.Time `json:"tokenReviewerLastRefresh,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.spec.address`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.status.vaultVersion`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VaultConnection is the Schema for the vaultconnections API.
type VaultConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultConnectionSpec   `json:"spec,omitempty"`
	Status VaultConnectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultConnectionList contains a list of VaultConnection.
type VaultConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultConnection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultConnection{}, &VaultConnectionList{})
}
