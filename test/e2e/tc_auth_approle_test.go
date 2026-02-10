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
	"context"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

var _ = Describe("AppRole Authentication Tests", Label("auth"), func() {
	// TC-AU-APPROLE: AppRole Authentication
	Context("TC-AU-APPROLE: AppRole Auth with "+
		"role_id and secret_id", Ordered, func() {
		const (
			approlePolicyName = "tc-au-approle-policy"
			approleRoleName   = "tc-au-approle-role"
		)

		var roleID string
		ctx := context.Background()

		BeforeAll(func() {
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			By("enabling AppRole auth method in Vault")
			err = vaultClient.EnableAuth(
				ctx, "approle", "approle",
			)
			if err != nil &&
				!strings.Contains(
					err.Error(), "already in use",
				) {
				Fail(fmt.Sprintf(
					"Failed to enable AppRole: %v", err,
				))
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
			err = vaultClient.WritePolicy(
				ctx, approlePolicyName, policyHCL,
			)
			Expect(err).NotTo(HaveOccurred())

			By("creating AppRole role in Vault")
			err = vaultClient.WriteAuthRole(
				ctx, "approle", approleRoleName,
				map[string]interface{}{
					"policies": fmt.Sprintf(
						"%s,default",
						approlePolicyName,
					),
					"token_ttl": "5m",
				},
			)
			Expect(err).NotTo(HaveOccurred())

			By("reading role_id for the AppRole role")
			roleID, err = vaultClient.GetAppRoleRoleID(
				ctx, "approle", approleRoleName,
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(roleID).NotTo(BeEmpty())
		})

		AfterAll(func() {
			By("cleaning up TC-AU-APPROLE resources")
			vaultClient, err := utils.GetTestVaultClient()
			if err != nil {
				return
			}
			_ = vaultClient.DeleteAuthRole(
				ctx, "approle", approleRoleName,
			)
			_ = vaultClient.DeletePolicy(
				ctx, approlePolicyName,
			)
		})

		It("TC-AU-APPROLE-01: should authenticate "+
			"with valid role_id and secret_id", func() {
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			By("generating a secret_id")
			secretID, err :=
				vaultClient.GenerateAppRoleSecretID(
					ctx, "approle", approleRoleName,
				)
			Expect(err).NotTo(HaveOccurred())
			Expect(secretID).NotTo(BeEmpty())

			By("logging in with role_id and secret_id")
			secret, err := vaultClient.Write(
				ctx,
				"auth/approle/login",
				map[string]interface{}{
					"role_id":   roleID,
					"secret_id": secretID,
				},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret).NotTo(BeNil())
			Expect(secret.Auth).NotTo(BeNil())
			Expect(secret.Auth.ClientToken).NotTo(
				BeEmpty(),
			)
			Expect(secret.Auth.Policies).To(
				ContainElement(approlePolicyName),
			)
		})

		It("TC-AU-APPROLE-02: should reject "+
			"authentication with invalid secret_id",
			func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("attempting login with invalid " +
					"secret_id")
				_, err = vaultClient.LoginAppRole(
					ctx, "approle",
					roleID, "invalid-secret-id-12345",
				)
				Expect(err).To(HaveOccurred())
			})

		It("TC-AU-APPROLE-03: should reject "+
			"authentication with invalid role_id",
			func() {
				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("generating a valid secret_id")
				secretID, err :=
					vaultClient.GenerateAppRoleSecretID(
						ctx, "approle",
						approleRoleName,
					)
				Expect(err).NotTo(HaveOccurred())

				By("attempting login with invalid " +
					"role_id")
				_, err = vaultClient.LoginAppRole(
					ctx, "approle",
					"invalid-role-id-12345", secretID,
				)
				Expect(err).To(HaveOccurred())
			})

		It("TC-AU-APPROLE-04: should enforce "+
			"single-use secret_id when configured",
			func() {
				singleUseRole :=
					"tc-au-approle-single-use"

				vaultClient, err :=
					utils.GetTestVaultClient()
				Expect(err).NotTo(HaveOccurred())

				By("creating role with " +
					"secret_id_num_uses=1")
				err = vaultClient.WriteAuthRole(
					ctx, "approle", singleUseRole,
					map[string]interface{}{
						"policies":           approlePolicyName,
						"secret_id_num_uses": 1,
						"token_ttl":          "1h",
					},
				)
				Expect(err).NotTo(HaveOccurred())

				By("reading role_id for single-use role")
				singleUseRoleID, err :=
					vaultClient.GetAppRoleRoleID(
						ctx, "approle", singleUseRole,
					)
				Expect(err).NotTo(HaveOccurred())

				By("generating a single-use secret_id")
				secretID, err :=
					vaultClient.GenerateAppRoleSecretID(
						ctx, "approle", singleUseRole,
					)
				Expect(err).NotTo(HaveOccurred())

				By("first login should succeed")
				_, err = vaultClient.LoginAppRole(
					ctx, "approle",
					singleUseRoleID, secretID,
				)
				Expect(err).NotTo(HaveOccurred())

				By("second login should fail " +
					"(single-use)")
				_, err = vaultClient.LoginAppRole(
					ctx, "approle",
					singleUseRoleID, secretID,
				)
				Expect(err).To(HaveOccurred())

				By("cleaning up single-use role")
				_ = vaultClient.DeleteAuthRole(
					ctx, "approle", singleUseRole,
				)
			})

		It("TC-AU-APPROLE-05: VaultConnection "+
			"with AppRole auth", func() {
			Skip("VaultConnection AppRole auth " +
				"not yet implemented")
		})
	})
})
