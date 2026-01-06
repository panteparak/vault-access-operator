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

// AuthConfig defines authentication settings for Vault
type AuthConfig struct {
	// Kubernetes auth method configuration
	// +optional
	Kubernetes *KubernetesAuth `json:"kubernetes,omitempty"`

	// Token auth method configuration
	// +optional
	Token *TokenAuth `json:"token,omitempty"`

	// AppRole auth method configuration
	// +optional
	AppRole *AppRoleAuth `json:"appRole,omitempty"`
}

// KubernetesAuth defines Kubernetes auth method settings
type KubernetesAuth struct {
	// Role is the Vault role to authenticate as
	// +kubebuilder:validation:Required
	Role string `json:"role"`

	// MountPath is the mount path of the Kubernetes auth method
	// +kubebuilder:default="kubernetes"
	// +optional
	MountPath string `json:"mountPath,omitempty"`

	// ServiceAccountTokenPath is the path to the service account token
	// +kubebuilder:default="/var/run/secrets/kubernetes.io/serviceaccount/token"
	// +optional
	ServiceAccountTokenPath string `json:"serviceAccountTokenPath,omitempty"`
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
