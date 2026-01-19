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

var _ = Describe("VaultClusterPolicy Tests", Ordered, func() {
	// Test configuration - uses shared VaultConnection from suite
	const (
		clusterPolicyName = "tc-cp-cluster-policy"
	)

	AfterAll(func() {
		By("cleaning up VaultClusterPolicy test resources")
		cmd := exec.Command("kubectl", "delete", "vaultclusterpolicy", clusterPolicyName,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
	})

	Context("TC-CP: VaultClusterPolicy Lifecycle", func() {
		It("TC-CP01: Create and sync cluster policy to Vault", func() {
			By("creating VaultClusterPolicy resource")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: %s
spec:
  connectionRef: %s
  rules:
    - path: "secret/data/shared/*"
      capabilities: ["read", "list"]
      description: "Read shared secrets"
    - path: "secret/metadata/shared/*"
      capabilities: ["read", "list"]
`, clusterPolicyName, sharedVaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultClusterPolicy")

			By("waiting for VaultClusterPolicy to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultclusterpolicy", clusterPolicyName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultClusterPolicy not active, got: %s", output)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying VaultClusterPolicy has correct vaultName in status")
			cmd = exec.Command("kubectl", "get", "vaultclusterpolicy", clusterPolicyName,
				"-o", "jsonpath={.status.vaultName}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal(clusterPolicyName),
				"Cluster policy vaultName should match resource name")

			By("verifying rulesCount in status")
			cmd = exec.Command("kubectl", "get", "vaultclusterpolicy", clusterPolicyName,
				"-o", "jsonpath={.status.rulesCount}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("2"), "Should have 2 rules")

			By("verifying policy exists in Vault")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
					"vault", "policy", "read", clusterPolicyName)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("secret/data/shared/*"))
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-CP02: Verify policy HCL content in Vault", func() {
			By("reading policy content from Vault")
			var policyContent string
			Eventually(func(g Gomega) {
				var err error
				policyContent, err = utils.ReadVaultPolicy(clusterPolicyName)
				g.Expect(err).NotTo(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying all paths are present in policy HCL")
			Expect(policyContent).To(ContainSubstring(`path "secret/data/shared/*"`),
				"Policy should contain secret/data/shared/* path")
			Expect(policyContent).To(ContainSubstring(`path "secret/metadata/shared/*"`),
				"Policy should contain secret/metadata/shared/* path")

			By("verifying capabilities are correctly written")
			Expect(policyContent).To(ContainSubstring("read"),
				"Policy should include read capability")
			Expect(policyContent).To(ContainSubstring("list"),
				"Policy should include list capability")
		})
	})
})
