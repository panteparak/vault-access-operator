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

package e2e

import (
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

var _ = Describe("AppRole Authentication Tests", Label("auth"), func() {
	// TC-AU-APPROLE: AppRole Authentication
	Context("TC-AU-APPROLE: AppRole Auth with role_id and secret_id", Ordered, func() {
		const (
			approlePolicyName = "tc-au-approle-policy"
			approleRoleName   = "tc-au-approle-role"
		)

		var (
			roleID string
		)

		BeforeAll(func() {
			By("enabling AppRole auth method in Vault")
			_, err := utils.RunVaultCommand("auth", "enable", "approle")
			if err != nil && !strings.Contains(err.Error(), "already in use") {
				Fail(fmt.Sprintf("Failed to enable AppRole auth: %v", err))
			}

			By("creating test policy for AppRole tests")
			policyHCL := `
path "secret/data/approle-test/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/health" {
  capabilities = ["read"]
}
`
			err = utils.CreateUnmanagedVaultPolicy(approlePolicyName, policyHCL)
			Expect(err).NotTo(HaveOccurred())

			By("creating AppRole role in Vault")
			_, err = utils.RunVaultCommand("write", fmt.Sprintf("auth/approle/role/%s", approleRoleName),
				fmt.Sprintf("policies=%s,default", approlePolicyName),
				"token_ttl=1h",
			)
			Expect(err).NotTo(HaveOccurred())

			By("reading role_id for the AppRole role")
			output, err := utils.GetAppRoleRoleID("auth/approle", approleRoleName)
			Expect(err).NotTo(HaveOccurred())

			var roleIDResp struct {
				Data struct {
					RoleID string `json:"role_id"`
				} `json:"data"`
			}
			err = json.Unmarshal([]byte(output), &roleIDResp)
			Expect(err).NotTo(HaveOccurred())
			roleID = roleIDResp.Data.RoleID
			Expect(roleID).NotTo(BeEmpty())
		})

		AfterAll(func() {
			By("cleaning up TC-AU-APPROLE test resources")
			_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/approle/role/%s", approleRoleName))
			_, _ = utils.RunVaultCommand("policy", "delete", approlePolicyName)
		})

		It("TC-AU-APPROLE-01: should authenticate with valid role_id and secret_id", func() {
			By("generating a secret_id")
			output, err := utils.GenerateAppRoleSecretID("auth/approle", approleRoleName)
			Expect(err).NotTo(HaveOccurred())

			var secretIDResp struct {
				Data struct {
					SecretID string `json:"secret_id"`
				} `json:"data"`
			}
			err = json.Unmarshal([]byte(output), &secretIDResp)
			Expect(err).NotTo(HaveOccurred())
			secretID := secretIDResp.Data.SecretID
			Expect(secretID).NotTo(BeEmpty())

			By("logging in with role_id and secret_id")
			loginOutput, err := utils.VaultLoginWithAppRole("auth/approle", roleID, secretID)
			Expect(err).NotTo(HaveOccurred())

			var loginResp struct {
				Auth struct {
					ClientToken string   `json:"client_token"`
					Policies    []string `json:"policies"`
				} `json:"auth"`
			}
			err = json.Unmarshal([]byte(loginOutput), &loginResp)
			Expect(err).NotTo(HaveOccurred())
			Expect(loginResp.Auth.ClientToken).NotTo(BeEmpty())
			Expect(loginResp.Auth.Policies).To(ContainElement(approlePolicyName))
		})

		It("TC-AU-APPROLE-02: should reject authentication with invalid secret_id", func() {
			By("attempting login with valid role_id and garbage secret_id")
			_, err := utils.VaultLoginWithAppRole("auth/approle", roleID, "invalid-secret-id-12345")
			Expect(err).To(HaveOccurred())
		})

		It("TC-AU-APPROLE-03: should reject authentication with invalid role_id", func() {
			By("generating a valid secret_id")
			output, err := utils.GenerateAppRoleSecretID("auth/approle", approleRoleName)
			Expect(err).NotTo(HaveOccurred())

			var secretIDResp struct {
				Data struct {
					SecretID string `json:"secret_id"`
				} `json:"data"`
			}
			err = json.Unmarshal([]byte(output), &secretIDResp)
			Expect(err).NotTo(HaveOccurred())

			By("attempting login with garbage role_id and valid secret_id")
			_, err = utils.VaultLoginWithAppRole("auth/approle", "invalid-role-id-12345", secretIDResp.Data.SecretID)
			Expect(err).To(HaveOccurred())
		})

		It("TC-AU-APPROLE-04: should enforce single-use secret_id when configured", func() {
			singleUseRole := "tc-au-approle-single-use"

			By("creating AppRole role with secret_id_num_uses=1")
			_, err := utils.RunVaultCommand("write", fmt.Sprintf("auth/approle/role/%s", singleUseRole),
				fmt.Sprintf("policies=%s", approlePolicyName),
				"secret_id_num_uses=1",
				"token_ttl=1h",
			)
			Expect(err).NotTo(HaveOccurred())

			By("reading role_id for single-use role")
			output, err := utils.GetAppRoleRoleID("auth/approle", singleUseRole)
			Expect(err).NotTo(HaveOccurred())

			var roleIDResp struct {
				Data struct {
					RoleID string `json:"role_id"`
				} `json:"data"`
			}
			err = json.Unmarshal([]byte(output), &roleIDResp)
			Expect(err).NotTo(HaveOccurred())
			singleUseRoleID := roleIDResp.Data.RoleID

			By("generating a single-use secret_id")
			output, err = utils.GenerateAppRoleSecretID("auth/approle", singleUseRole)
			Expect(err).NotTo(HaveOccurred())

			var secretIDResp struct {
				Data struct {
					SecretID string `json:"secret_id"`
				} `json:"data"`
			}
			err = json.Unmarshal([]byte(output), &secretIDResp)
			Expect(err).NotTo(HaveOccurred())
			secretID := secretIDResp.Data.SecretID

			By("first login should succeed")
			_, err = utils.VaultLoginWithAppRole("auth/approle", singleUseRoleID, secretID)
			Expect(err).NotTo(HaveOccurred())

			By("second login with same secret_id should fail (single-use)")
			_, err = utils.VaultLoginWithAppRole("auth/approle", singleUseRoleID, secretID)
			Expect(err).To(HaveOccurred())

			By("cleaning up single-use role")
			_, _ = utils.RunVaultCommand("delete", fmt.Sprintf("auth/approle/role/%s", singleUseRole))
		})

		It("TC-AU-APPROLE-05: VaultConnection with AppRole auth", func() {
			Skip("VaultConnection AppRole auth not yet implemented - this test documents the expected API")

			// When AppRole auth is added to the VaultConnection spec, this test should be enabled.
			//
			// Expected VaultConnection YAML:
			// apiVersion: vault.platform.io/v1alpha1
			// kind: VaultConnection
			// metadata:
			//   name: approle-connection
			// spec:
			//   address: http://vault.vault.svc.cluster.local:8200
			//   auth:
			//     appRole:
			//       roleId: <role-id>
			//       secretRef:
			//         name: approle-secret
			//         namespace: default
			//         key: secret-id
		})
	})
})
