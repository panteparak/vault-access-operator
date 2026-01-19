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

var _ = Describe("Conflict Policy Tests", Ordered, func() {
	Context("TC-CF: Policy Conflict Resolution", func() {
		It("TC-CF01-ADOPT: Adopt existing unmanaged policy", func() {
			adoptPolicyName := "tc-cf01-adopt"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, adoptPolicyName)
			unmanagedHCL := `path "secret/data/unmanaged/*" { capabilities = ["read"] }`

			By("creating policy directly in Vault (unmanaged)")
			err := utils.CreateUnmanagedVaultPolicy(expectedVaultName, unmanagedHCL)
			Expect(err).NotTo(HaveOccurred(), "Failed to create unmanaged policy in Vault")

			By("verifying policy exists in Vault before creating K8s resource")
			exists, err := utils.VaultPolicyExists(expectedVaultName)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeTrue(), "Unmanaged policy should exist in Vault")

			By("creating VaultPolicy with conflictPolicy=Adopt")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  conflictPolicy: Adopt
  rules:
    - path: "secret/data/adopted/*"
      capabilities: ["read", "list"]
      description: "Adopted policy path"
`, adoptPolicyName, testNamespace, sharedVaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active (adoption successful)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", adoptPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultPolicy should be Active after adoption")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying policy content was updated by operator")
			Eventually(func(g Gomega) {
				policyContent, err := utils.ReadVaultPolicy(expectedVaultName)
				g.Expect(err).NotTo(HaveOccurred())
				// Should now contain the new path from K8s spec, not the old unmanaged content
				g.Expect(policyContent).To(ContainSubstring("adopted"),
					"Policy should contain new adopted path")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up adopt test policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", adoptPolicyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
		})

		It("TC-CF02-FAIL: Fail when policy exists and conflictPolicy=Fail", func() {
			failPolicyName := "tc-cf02-fail"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, failPolicyName)
			unmanagedHCL := `path "secret/data/preexisting/*" { capabilities = ["read"] }`

			By("creating policy directly in Vault (unmanaged)")
			err := utils.CreateUnmanagedVaultPolicy(expectedVaultName, unmanagedHCL)
			Expect(err).NotTo(HaveOccurred(), "Failed to create unmanaged policy in Vault")

			By("creating VaultPolicy with conflictPolicy=Fail")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  conflictPolicy: Fail
  rules:
    - path: "secret/data/wontwork/*"
      capabilities: ["read"]
`, failPolicyName, testNamespace, sharedVaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultPolicy enters Conflict or Error phase")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", failPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Conflict"), Equal("Error")),
					"VaultPolicy should be in Conflict or Error phase")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying original policy content is preserved in Vault")
			policyContent, err := utils.ReadVaultPolicy(expectedVaultName)
			Expect(err).NotTo(HaveOccurred())
			Expect(policyContent).To(ContainSubstring("preexisting"),
				"Original policy content should be preserved")
			Expect(policyContent).NotTo(ContainSubstring("wontwork"),
				"New policy content should NOT be written")

			By("cleaning up fail test policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", failPolicyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
			_ = utils.DeleteVaultPolicy(expectedVaultName)
		})

		It("TC-CF03-NORM: Create policy normally when no conflict exists", func() {
			newPolicyName := "tc-cf03-new"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, newPolicyName)

			By("ensuring policy does NOT exist in Vault")
			_ = utils.DeleteVaultPolicy(expectedVaultName)

			By("creating VaultPolicy with conflictPolicy=Fail (default behavior)")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  conflictPolicy: Fail
  rules:
    - path: "secret/data/newpath/*"
      capabilities: ["read"]
`, newPolicyName, testNamespace, sharedVaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", newPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying policy was created in Vault")
			Eventually(func(g Gomega) {
				policyContent, err := utils.ReadVaultPolicy(expectedVaultName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(policyContent).To(ContainSubstring("newpath"))
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up new policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", newPolicyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
		})
	})
})
