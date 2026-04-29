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

package authprovider

import "os"

// Default Vault auth mount paths. These mirror the fall-through defaults
// used by the pre-refactor authenticate() method so provider behavior is
// bit-for-bit compatible.
const (
	defaultKubernetesPath = "kubernetes"
	defaultAppRolePath    = "approle"
	defaultJWTPath        = "jwt"
	defaultOIDCPath       = "oidc"
	defaultAWSPath        = "aws"
	defaultGCPPath        = "gcp"
	defaultJWTAudience    = "vault"
)

// operatorServiceAccountName returns the operator's service account name,
// honoring OPERATOR_SERVICE_ACCOUNT override.
func operatorServiceAccountName() string {
	if sa := os.Getenv("OPERATOR_SERVICE_ACCOUNT"); sa != "" {
		return sa
	}
	return "vault-access-operator-controller-manager"
}

// operatorNamespace returns the operator's namespace, honoring
// OPERATOR_NAMESPACE override and falling back to the in-cluster
// serviceaccount namespace file.
func operatorNamespace() string {
	if ns := os.Getenv("OPERATOR_NAMESPACE"); ns != "" {
		return ns
	}
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		return string(data)
	}
	return "vault-access-operator-system"
}
