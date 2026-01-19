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

var _ = Describe("VaultConnection Tests", Ordered, func() {
	// Test configuration
	const (
		vaultConnectionName  = "tc-vc-vault"
		vaultTokenSecretName = "vault-token"
	)

	BeforeAll(func() {
		By("creating test namespace for connection tests")
		cmd := exec.Command("kubectl", "create", "ns", testNamespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		By("creating Vault token secret")
		cmd = exec.Command("kubectl", "create", "secret", "generic", vaultTokenSecretName,
			"-n", testNamespace,
			"--from-literal=token=root")
		_, _ = utils.Run(cmd) // Ignore if exists
	})

	AfterAll(func() {
		By("cleaning up VaultConnection test resources")
		cmd := exec.Command("kubectl", "delete", "vaultconnection", vaultConnectionName,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
	})

	Context("TC-VC: VaultConnection Lifecycle", func() {
		It("TC-VC01: Create VaultConnection with token auth", func() {
			By("creating VaultConnection resource using token authentication")
			connectionYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: %s
spec:
  address: http://vault.%s.svc.cluster.local:8200
  auth:
    token:
      secretRef:
        name: %s
        namespace: %s
        key: token
  healthCheckInterval: "10s"
`, vaultConnectionName, vaultNamespace, vaultTokenSecretName, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(connectionYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultConnection")

			By("waiting for VaultConnection to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", vaultConnectionName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultConnection not active, got: %s", output)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying VaultConnection has finalizer")
			cmd = exec.Command("kubectl", "get", "vaultconnection", vaultConnectionName,
				"-o", "jsonpath={.metadata.finalizers}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("vault.platform.io/finalizer"),
				"VaultConnection should have finalizer for cleanup")
		})

		It("TC-VC02: Verify VaultConnection health check and version", func() {
			By("verifying VaultConnection has vault version in status")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", vaultConnectionName,
					"-o", "jsonpath={.status.vaultVersion}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("1."), "Expected Vault version 1.x in status")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying health check interval is respected")
			cmd := exec.Command("kubectl", "get", "vaultconnection", vaultConnectionName,
				"-o", "jsonpath={.spec.healthCheckInterval}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("10s"), "Health check interval should be 10s")
		})
	})
})
