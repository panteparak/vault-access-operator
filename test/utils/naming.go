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

package utils

import (
	"os"

	"github.com/panteparak/vault-access-operator/shared/naming"
)

// ExpectedVaultName is the single place e2e tests derive an operator-written
// Vault resource name (ADR 0010): vao.{identity}.{namespace}.{name}. Pass
// namespace "" for cluster-scoped CRs (rendered as the placeholder).
func ExpectedVaultName(identity, namespace, name string) string {
	return naming.VaultName(identity, namespace, name)
}

// DefaultIdentity is the identity segment for CRs synced through a
// connection with no login auth mount (the suite's default static-token
// connection): E2E_CLUSTER_NAME when the cluster-name variant stack is up
// (make e2e-local-up-with-cluster-name), else the "_" placeholder.
func DefaultIdentity() string {
	return naming.Identity(os.Getenv("E2E_CLUSTER_NAME"), "")
}
