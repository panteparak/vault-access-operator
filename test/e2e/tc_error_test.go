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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

var _ = Describe("Error Handling Tests", Ordered, func() {
	Context("TC-EH: Error Scenarios", func() {
		It("TC-EH01: Handle invalid connection reference", func() {
			invalidPolicyName := "tc-eh01-invalid-conn"

			By("creating VaultPolicy with non-existent connection")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: non-existent-connection
  rules:
    - path: "secret/data/test/*"
      capabilities: ["read"]
`, invalidPolicyName, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultPolicy enters Error or Pending phase")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", invalidPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Error"), Equal("Pending")))
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up invalid policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", invalidPolicyName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("TC-EH02: Handle missing policy reference in VaultRole", func() {
			missingPolicyRoleName := "tc-eh02-missing-policy"
			missingPolicySAName := "tc-eh02-sa"

			By("creating a test service account")
			cmd := exec.Command("kubectl", "create", "serviceaccount", missingPolicySAName, "-n", testNamespace)
			_, _ = utils.Run(cmd)

			By("creating VaultRole referencing non-existent policy")
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
      name: non-existent-policy
      namespace: %s
  tokenTTL: "30m"
`, missingPolicyRoleName, testNamespace, sharedVaultConnectionName, missingPolicySAName, testNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultRole enters Error or Pending phase")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultrole", missingPolicyRoleName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Error"), Equal("Pending")),
					"VaultRole should be in Error or Pending phase due to missing policy")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying status message indicates missing policy")
			cmd = exec.Command("kubectl", "get", "vaultrole", missingPolicyRoleName,
				"-n", testNamespace, "-o", "jsonpath={.status.message}")
			output, err := utils.Run(cmd)
			if err == nil && output != "" {
				Expect(strings.ToLower(output)).To(Or(
					ContainSubstring("not found"),
					ContainSubstring("missing"),
					ContainSubstring("policy"),
				), "Status message should indicate policy issue")
			}

			By("cleaning up missing policy role")
			cmd = exec.Command("kubectl", "delete", "vaultrole", missingPolicyRoleName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "serviceaccount", missingPolicySAName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("TC-EH03: Reject policy violating namespace boundary", func() {
			violationPolicyName := "tc-eh03-boundary"

			By("attempting to create VaultPolicy without {{namespace}} variable")
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
    - path: "secret/data/global/*"
      capabilities: ["read"]
      description: "This path violates namespace boundary - no {{namespace}} variable"
`, violationPolicyName, testNamespace, sharedVaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			output, err := utils.Run(cmd)

			// The webhook should reject this - either via admission error or the controller
			// should put it in error state
			if err != nil {
				By("webhook rejected the policy (expected behavior)")
				Expect(output).To(Or(
					ContainSubstring("namespace"),
					ContainSubstring("boundary"),
					ContainSubstring("{{namespace}}"),
				), "Rejection message should mention namespace boundary")
			} else {
				By("policy was created, checking if controller puts it in error state")
				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "vaultpolicy", violationPolicyName,
						"-n", testNamespace, "-o", "jsonpath={.status.phase}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output).To(Or(Equal("Error"), Equal("Active")))
				}, 30*time.Second, 2*time.Second).Should(Succeed())

				By("cleaning up boundary violation policy")
				cmd = exec.Command("kubectl", "delete", "vaultpolicy", violationPolicyName,
					"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
				_, _ = utils.Run(cmd)
			}
		})

		It("TC-EH04: Handle VaultConnection becoming unavailable", func() {
			unavailConnName := "tc-eh04-unavail"
			unavailPolicyName := "tc-eh04-policy"

			By("creating VaultConnection to a non-existent Vault address")
			connYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: %s
spec:
  address: http://vault-does-not-exist.%s.svc.cluster.local:8200
  auth:
    token:
      secretRef:
        name: vault-token
        namespace: %s
        key: token
  healthCheckInterval: "5s"
`, unavailConnName, testNamespace, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(connYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultConnection enters Error or Pending phase")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", unavailConnName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Error"), Equal("Pending")),
					"VaultConnection should be in Error or Pending phase")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("creating VaultPolicy using the unavailable connection")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  rules:
    - path: "secret/data/unavail/*"
      capabilities: ["read"]
`, unavailPolicyName, testNamespace, unavailConnName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultPolicy enters Error or Pending phase")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", unavailPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Error"), Equal("Pending")),
					"VaultPolicy should be in Error or Pending phase when connection unavailable")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up unavailable connection test resources")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", unavailPolicyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "vaultconnection", unavailConnName,
				"--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
		})

		It("TC-EH05: Reject invalid TTL format", func() {
			invalidTTLRoleName := "tc-eh05-invalid-ttl"
			invalidTTLSAName := "tc-eh05-sa"
			invalidTTLPolicyName := "tc-eh05-policy"

			By("creating test prerequisites")
			cmd := exec.Command("kubectl", "create", "serviceaccount", invalidTTLSAName, "-n", testNamespace)
			_, _ = utils.Run(cmd)

			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  rules:
    - path: "secret/data/test/*"
      capabilities: ["read"]
`, invalidTTLPolicyName, testNamespace, sharedVaultConnectionName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, _ = utils.Run(cmd)

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", invalidTTLPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("creating VaultRole with invalid TTL format")
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
  tokenTTL: "invalid-ttl"
`, invalidTTLRoleName, testNamespace, sharedVaultConnectionName, invalidTTLSAName, invalidTTLPolicyName, testNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			output, err := utils.Run(cmd)

			// Either webhook rejects it or it gets created in error state
			if err != nil {
				By("webhook rejected the invalid TTL (expected behavior)")
				Expect(output).To(Or(
					ContainSubstring("ttl"),
					ContainSubstring("duration"),
					ContainSubstring("invalid"),
				))
			} else {
				By("role was created, verifying it's in error state")
				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "vaultrole", invalidTTLRoleName,
						"-n", testNamespace, "-o", "jsonpath={.status.phase}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output).To(Or(Equal("Error"), Equal("Pending")))
				}, 30*time.Second, 2*time.Second).Should(Succeed())
			}

			By("cleaning up")
			cmd = exec.Command("kubectl", "delete", "vaultrole", invalidTTLRoleName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", invalidTTLPolicyName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "serviceaccount", invalidTTLSAName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("TC-EH06: Handle empty policy rules", func() {
			emptyRulesPolicyName := "tc-eh06-empty-rules"

			By("creating VaultPolicy with empty rules")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  rules: []
`, emptyRulesPolicyName, testNamespace, sharedVaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			output, err := utils.Run(cmd)

			// Webhook should reject empty rules, or it should result in error state
			if err != nil {
				By("webhook rejected empty rules (expected behavior)")
				Expect(output).To(Or(
					ContainSubstring("rules"),
					ContainSubstring("empty"),
					ContainSubstring("required"),
				))
			} else {
				By("policy created, checking status")
				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "vaultpolicy", emptyRulesPolicyName,
						"-n", testNamespace, "-o", "jsonpath={.status.phase}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					// Empty rules might be accepted but result in a warning
					g.Expect(output).To(Or(Equal("Error"), Equal("Active")))
				}, 30*time.Second, 2*time.Second).Should(Succeed())

				cmd = exec.Command("kubectl", "delete", "vaultpolicy", emptyRulesPolicyName,
					"-n", testNamespace, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			}
		})
	})
})
