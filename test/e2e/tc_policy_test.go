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
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

var _ = Describe("VaultPolicy Tests", Ordered, func() {
	// Test configuration
	const (
		policyName = "tc-vp-policy"
	)

	AfterAll(func() {
		By("cleaning up VaultPolicy test resources")
		cmd := exec.Command("kubectl", "delete", "vaultpolicy", policyName, "-n", testNamespace,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
	})

	Context("TC-VP: VaultPolicy Lifecycle", func() {
		It("TC-VP01: Create namespaced VaultPolicy and sync to Vault", func() {
			By("creating VaultPolicy resource")
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
      capabilities: ["create", "read", "update", "delete", "list"]
      description: "Full access to namespace secrets"
`, policyName, testNamespace, sharedVaultConnectionName, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

			By("waiting for VaultPolicy to become Active")
			// Using client-go helper for faster status checks (~10ms vs ~500ms with kubectl)
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(context.Background(), policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"), "VaultPolicy not active, got: %s", status)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying VaultPolicy has namespaced vaultName")
			// Using client-go helper for faster resource access
			policy, err := utils.GetVaultPolicy(context.Background(), policyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, policyName)
			Expect(policy.Status.VaultName).To(Equal(expectedVaultName),
				"Namespaced policy should have namespace-prefixed vaultName")

			By("verifying policy exists in Vault with namespaced name")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
					"vault", "policy", "read", expectedVaultName)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(testNamespace))
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-VP02: Substitute {{namespace}} variable in policy paths", func() {
			nsSubstPolicyName := "tc-vp02-ns-subst"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, nsSubstPolicyName)

			By("creating VaultPolicy with {{namespace}} variable")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  enforceNamespaceBoundary: true
  rules:
    - path: "secret/data/{{namespace}}/app/*"
      capabilities: ["read", "list"]
      description: "Namespace-scoped secret access"
`, nsSubstPolicyName, testNamespace, sharedVaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", nsSubstPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("reading policy content from Vault and verifying namespace substitution")
			Eventually(func(g Gomega) {
				policyContent, err := utils.ReadVaultPolicy(expectedVaultName)
				g.Expect(err).NotTo(HaveOccurred())
				// The {{namespace}} variable should be replaced with actual namespace
				g.Expect(policyContent).To(ContainSubstring(testNamespace),
					"Policy should contain the substituted namespace")
				g.Expect(policyContent).NotTo(ContainSubstring("{{namespace}}"),
					"Policy should NOT contain unsubstituted {{namespace}} variable")
				// Verify the full path with namespace substituted
				expectedPath := fmt.Sprintf("secret/data/%s/app/*", testNamespace)
				g.Expect(policyContent).To(ContainSubstring(expectedPath),
					"Policy should contain the namespace-substituted path")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up namespace substitution test policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", nsSubstPolicyName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("TC-VP03: Update VaultPolicy when spec changes", func() {
			By("updating VaultPolicy with additional rule")
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
      capabilities: ["create", "read", "update", "delete", "list"]
      description: "Full access to namespace secrets"
    - path: "secret/metadata/%s/*"
      capabilities: ["read", "list"]
      description: "Read metadata"
`, policyName, testNamespace, sharedVaultConnectionName, testNamespace, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying rulesCount updated to 2")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", policyName,
					"-n", testNamespace, "-o", "jsonpath={.status.rulesCount}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("2"))
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-VP04-DEL: Handle VaultPolicy deletion with finalizer", func() {
			tempPolicyName := "tc-vp04-temp"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, tempPolicyName)

			By("creating temporary VaultPolicy")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  rules:
    - path: "secret/data/temp/*"
      capabilities: ["read"]
`, tempPolicyName, testNamespace, sharedVaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for temporary policy to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", tempPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying policy exists in Vault before deletion")
			cmd = exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
				"vault", "policy", "read", expectedVaultName)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("deleting the temporary VaultPolicy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", tempPolicyName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultPolicy resource is deleted")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", tempPolicyName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred()) // Should fail because resource is deleted
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying policy is deleted from Vault")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
					"vault", "policy", "read", expectedVaultName)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred()) // Should fail because policy is deleted
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-VP05-RET: Respect deletionPolicy=Retain", func() {
			retainPolicyName := "tc-vp05-retain"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, retainPolicyName)

			By("creating VaultPolicy with deletionPolicy=Retain")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  deletionPolicy: Retain
  rules:
    - path: "secret/data/retain/*"
      capabilities: ["read"]
`, retainPolicyName, testNamespace, sharedVaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", retainPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("deleting the VaultPolicy with Retain policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", retainPolicyName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for K8s resource to be deleted")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", retainPolicyName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying policy is STILL in Vault after K8s deletion")
			cmd = exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
				"vault", "policy", "read", expectedVaultName)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Policy should still exist in Vault")
			Expect(output).To(ContainSubstring("retain"))

			By("cleaning up retained policy from Vault")
			cmd = exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
				"vault", "policy", "delete", expectedVaultName)
			_, _ = utils.Run(cmd)
		})
	})
})
