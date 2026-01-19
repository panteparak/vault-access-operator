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
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

var _ = Describe("VaultRole Tests", Ordered, func() {
	// Test configuration
	const (
		roleName       = "tc-vr-role"
		rolePolicyName = "tc-vr-policy"
		roleSAName     = "tc-vr-sa"
	)

	BeforeAll(func() {
		By("creating test service account for role tests")
		cmd := exec.Command("kubectl", "create", "serviceaccount", roleSAName, "-n", testNamespace)
		_, _ = utils.Run(cmd)

		By("creating test policy for role binding")
		policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  rules:
    - path: "secret/data/%s/*"
      capabilities: ["read", "list"]
`, rolePolicyName, testNamespace, sharedVaultConnectionName, testNamespace)

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = stringReader(policyYAML)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "vaultpolicy", rolePolicyName,
				"-n", testNamespace, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterAll(func() {
		By("cleaning up VaultRole test resources")
		cmd := exec.Command("kubectl", "delete", "vaultrole", roleName, "-n", testNamespace,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "vaultpolicy", rolePolicyName, "-n", testNamespace,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "serviceaccount", roleSAName, "-n", testNamespace,
			"--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	Context("TC-VR: VaultRole Lifecycle", func() {
		It("TC-VR01: Create namespaced VaultRole", func() {
			By("creating VaultRole resource")
			roleYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  serviceAccounts:
    - %s
  policies:
    - kind: VaultPolicy
      name: %s
      namespace: %s
  tokenTTL: "30m"
`, roleName, testNamespace, sharedVaultConnectionName, roleSAName, rolePolicyName, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultRole")

			By("waiting for VaultRole to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultrole", roleName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultRole not active, got: %s", output)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying VaultRole has namespaced vaultRoleName")
			cmd = exec.Command("kubectl", "get", "vaultrole", roleName,
				"-n", testNamespace, "-o", "jsonpath={.status.vaultRoleName}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			expectedRoleName := fmt.Sprintf("%s-%s", testNamespace, roleName)
			Expect(output).To(Equal(expectedRoleName))

			By("verifying VaultRole has bound service accounts")
			cmd = exec.Command("kubectl", "get", "vaultrole", roleName,
				"-n", testNamespace, "-o", "jsonpath={.status.boundServiceAccounts}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring(roleSAName))
		})

		It("TC-VR02: Verify role configuration in Vault", func() {
			expectedRoleName := fmt.Sprintf("%s-%s", testNamespace, roleName)
			expectedPolicyName := fmt.Sprintf("%s-%s", testNamespace, rolePolicyName)

			By("reading role configuration from Vault")
			var roleJSON string
			Eventually(func(g Gomega) {
				var err error
				roleJSON, err = utils.ReadVaultRole("auth/kubernetes", expectedRoleName)
				g.Expect(err).NotTo(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("parsing role JSON and verifying configuration")
			var roleResponse struct {
				Data struct {
					BoundServiceAccountNames      []string `json:"bound_service_account_names"`
					BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
					TokenPolicies                 []string `json:"token_policies"`
					TokenTTL                      int      `json:"token_ttl"`
				} `json:"data"`
			}
			err := json.Unmarshal([]byte(roleJSON), &roleResponse)
			Expect(err).NotTo(HaveOccurred(), "Failed to parse role JSON: %s", roleJSON)

			By("verifying bound service accounts (namespace-scoped)")
			Expect(roleResponse.Data.BoundServiceAccountNames).To(ContainElement(roleSAName),
				"Role should have test SA as bound service account")
			Expect(roleResponse.Data.BoundServiceAccountNamespaces).To(ConsistOf(testNamespace),
				"Role should only be bound to its own namespace")

			By("verifying policies are attached with namespace prefix")
			Expect(roleResponse.Data.TokenPolicies).To(ContainElement(expectedPolicyName),
				"Role should have namespaced policy attached")

			By("verifying token TTL configuration")
			// tokenTTL is "30m" = 1800 seconds
			Expect(roleResponse.Data.TokenTTL).To(Equal(1800),
				"Role should have token_ttl of 30m (1800 seconds)")
		})

		It("TC-VR03-DEL: Remove role from Vault when VaultRole is deleted", func() {
			tempRoleName := "tc-vr03-temp"
			tempPolicyName := "tc-vr03-policy"
			tempSAName := "tc-vr03-sa"
			expectedRoleVaultName := fmt.Sprintf("%s-%s", testNamespace, tempRoleName)
			expectedPolicyVaultName := fmt.Sprintf("%s-%s", testNamespace, tempPolicyName)

			By("creating a temporary service account")
			cmd := exec.Command("kubectl", "create", "serviceaccount", tempSAName, "-n", testNamespace)
			_, _ = utils.Run(cmd)

			By("creating a temporary policy for the role")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  rules:
    - path: "secret/data/temp-role/*"
      capabilities: ["read"]
`, tempPolicyName, testNamespace, sharedVaultConnectionName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for temp policy to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", tempPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("creating a temporary VaultRole")
			roleYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  serviceAccounts:
    - %s
  policies:
    - kind: VaultPolicy
      name: %s
      namespace: %s
  tokenTTL: "10m"
`, tempRoleName, testNamespace, sharedVaultConnectionName, tempSAName, tempPolicyName, testNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultRole to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultrole", tempRoleName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying role exists in Vault")
			Eventually(func(g Gomega) {
				exists, err := utils.VaultRoleExists("auth/kubernetes", expectedRoleVaultName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeTrue(), "Role should exist in Vault")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("deleting the VaultRole")
			cmd = exec.Command("kubectl", "delete", "vaultrole", tempRoleName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultRole resource is deleted from Kubernetes")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultrole", tempRoleName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying role is removed from Vault")
			Eventually(func(g Gomega) {
				exists, err := utils.VaultRoleExists("auth/kubernetes", expectedRoleVaultName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeFalse(), "Role should be removed from Vault")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up temp policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", tempPolicyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "serviceaccount", tempSAName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			_ = utils.DeleteVaultPolicy(expectedPolicyVaultName)
		})
	})
})
