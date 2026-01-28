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
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// AuthTestSuite defines a reusable test suite that runs against any AuthProvider.
// This allows the same tests to verify behavior across different auth methods.
var _ = Describe("TC-AU-SHARED: Authentication Method Compatibility", func() {
	// Test with each available auth provider
	authProviders := []struct {
		name     string
		provider func() AuthProvider
	}{
		{"kubernetes", func() AuthProvider { return NewKubernetesAuthProvider() }},
		{"jwt", func() AuthProvider { return NewJWTAuthProvider() }},
	}

	for _, ap := range authProviders {
		Context(fmt.Sprintf("with %s auth", ap.name), Ordered, func() {
			var (
				provider       AuthProvider
				testSAName     string
				testRoleName   string
				testPolicyName string
				skipReason     string
			)

			BeforeAll(func() {
				provider = ap.provider()
				testSAName = fmt.Sprintf("tc-shared-%s-sa", ap.name)
				testRoleName = fmt.Sprintf("tc-shared-%s-role", ap.name)
				testPolicyName = fmt.Sprintf("tc-shared-%s-policy", ap.name)

				By(fmt.Sprintf("setting up %s auth provider", ap.name))
				var err error
				skipReason, err = provider.Setup()
				if err != nil {
					Fail(fmt.Sprintf("Failed to setup %s auth: %v", ap.name, err))
				}
				if skipReason != "" {
					Skip(fmt.Sprintf("%s auth not available: %s", ap.name, skipReason))
				}

				By("creating test service account")
				cmd := exec.Command("kubectl", "create", "serviceaccount", testSAName,
					"-n", testNamespace)
				_, _ = utils.Run(cmd) // Ignore if exists

				By("creating test policy in Vault")
				policyHCL := `
path "secret/data/shared-test/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/health" {
  capabilities = ["read"]
}
`
				cmd = exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "-i", "--",
					"vault", "policy", "write", testPolicyName, "-")
				cmd.Stdin = stringReader(policyHCL)
				_, err = utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())

				By("creating Vault role for test service account")
				err = provider.CreateRole(testRoleName, testNamespace, testSAName,
					[]string{testPolicyName, "default"})
				Expect(err).NotTo(HaveOccurred())
			})

			AfterAll(func() {
				if skipReason != "" {
					return // Nothing to clean up
				}

				By("cleaning up shared test resources")

				// Delete Vault role
				if provider != nil {
					_ = provider.DeleteRole(testRoleName)
				}

				// Delete Vault policy
				_, _ = utils.RunVaultCommand("policy", "delete", testPolicyName)

				// Delete service account
				cmd := exec.Command("kubectl", "delete", "serviceaccount", testSAName,
					"-n", testNamespace, "--ignore-not-found")
				_, _ = utils.Run(cmd)

				// Cleanup provider
				if provider != nil {
					_ = provider.Cleanup()
				}
			})

			It("should authenticate successfully with valid credentials", func() {
				By("getting service account token")
				token, err := provider.GetToken(testNamespace, testSAName)
				Expect(err).NotTo(HaveOccurred())
				Expect(token).NotTo(BeEmpty())

				By("logging into Vault")
				vaultToken, err := provider.Login(testRoleName, token)
				Expect(err).NotTo(HaveOccurred())
				Expect(vaultToken).NotTo(BeEmpty())
			})

			It("should reject authentication with invalid role", func() {
				By("getting service account token")
				token, err := provider.GetToken(testNamespace, testSAName)
				Expect(err).NotTo(HaveOccurred())

				By("attempting login with non-existent role")
				_, err = provider.Login("non-existent-role", token)
				Expect(err).To(HaveOccurred())
			})

			It("should work with VaultPolicy CRD", func() {
				policyName := fmt.Sprintf("tc-shared-%s-crd-policy", ap.name)
				// VaultPolicy uses namespace-prefixed vault name
				expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, policyName)

				By("creating VaultPolicy using the shared VaultConnection")
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
      capabilities: ["read"]
`, policyName, testNamespace, sharedVaultConnectionName, ap.name)

				cmd := exec.Command("kubectl", "apply", "-f", "-")
				cmd.Stdin = stringReader(policyYAML)
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())

				By("waiting for VaultPolicy to become Active")
				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "vaultpolicy", policyName,
						"-n", testNamespace, "-o", "jsonpath={.status.phase}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output).To(Equal("Active"))
				}, 30*time.Second, 2*time.Second).Should(Succeed())

				By("verifying policy exists in Vault")
				output, err := utils.RunVaultCommand("policy", "read", expectedVaultName)
				Expect(err).NotTo(HaveOccurred())
				Expect(output).To(ContainSubstring(fmt.Sprintf("secret/data/%s/*", ap.name)))

				By("cleaning up VaultPolicy")
				cmd = exec.Command("kubectl", "delete", "vaultpolicy", policyName,
					"-n", testNamespace, "--timeout=30s")
				_, _ = utils.Run(cmd)

				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "vaultpolicy", policyName,
						"-n", testNamespace)
					_, err := utils.Run(cmd)
					g.Expect(err).To(HaveOccurred())
				}, 30*time.Second, 2*time.Second).Should(Succeed())
			})

			It("should work with VaultRole CRD", func() {
				roleName := fmt.Sprintf("tc-shared-%s-crd-role", ap.name)
				roleSAName := fmt.Sprintf("tc-shared-%s-crd-sa", ap.name)
				rolePolicyName := fmt.Sprintf("tc-shared-%s-crd-role-policy", ap.name)
				// VaultRole uses namespace-prefixed vault name
				expectedVaultRoleName := fmt.Sprintf("%s-%s", testNamespace, roleName)

				By("creating service account for VaultRole test")
				cmd := exec.Command("kubectl", "create", "serviceaccount", roleSAName,
					"-n", testNamespace)
				_, _ = utils.Run(cmd)

				By("creating a VaultPolicy for the role to reference")
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
      capabilities: ["read"]
`, rolePolicyName, testNamespace, sharedVaultConnectionName, ap.name)

				cmd = exec.Command("kubectl", "apply", "-f", "-")
				cmd.Stdin = stringReader(policyYAML)
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())

				By("waiting for VaultPolicy to become Active")
				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "vaultpolicy", rolePolicyName,
						"-n", testNamespace, "-o", "jsonpath={.status.phase}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output).To(Equal("Active"))
				}, 30*time.Second, 2*time.Second).Should(Succeed())

				By("creating VaultRole using the shared VaultConnection")
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
  tokenTTL: "1h"
`, roleName, testNamespace, sharedVaultConnectionName, roleSAName, rolePolicyName, testNamespace)

				cmd = exec.Command("kubectl", "apply", "-f", "-")
				cmd.Stdin = stringReader(roleYAML)
				_, err = utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())

				By("waiting for VaultRole to become Active")
				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "vaultrole", roleName,
						"-n", testNamespace, "-o", "jsonpath={.status.phase}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output).To(Equal("Active"))
				}, 2*time.Minute, 5*time.Second).Should(Succeed())

				By("verifying role exists in Vault")
				output, err := utils.RunVaultCommand("read", "-format=json",
					fmt.Sprintf("auth/kubernetes/role/%s", expectedVaultRoleName))
				Expect(err).NotTo(HaveOccurred())
				Expect(output).To(ContainSubstring(roleSAName))

				By("cleaning up VaultRole, VaultPolicy, and service account")
				cmd = exec.Command("kubectl", "delete", "vaultrole", roleName,
					"-n", testNamespace, "--timeout=30s")
				_, _ = utils.Run(cmd)

				cmd = exec.Command("kubectl", "delete", "vaultpolicy", rolePolicyName,
					"-n", testNamespace, "--timeout=30s")
				_, _ = utils.Run(cmd)

				cmd = exec.Command("kubectl", "delete", "serviceaccount", roleSAName,
					"-n", testNamespace, "--ignore-not-found")
				_, _ = utils.Run(cmd)

				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "vaultrole", roleName,
						"-n", testNamespace)
					_, err := utils.Run(cmd)
					g.Expect(err).To(HaveOccurred())
				}, 30*time.Second, 2*time.Second).Should(Succeed())
			})
		})
	}
})
