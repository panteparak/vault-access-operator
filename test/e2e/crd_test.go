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
	"io"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// vaultNamespace is where Vault dev server is deployed
const vaultNamespace = "vault"

// testNamespace is where namespaced resources are created
const testNamespace = "e2e-test"

var _ = Describe("CRD Functionality", Ordered, func() {
	// Store resource names for cleanup
	const (
		vaultConnectionName    = "e2e-vault"
		vaultTokenSecretName   = "vault-token"
		vaultPolicyName        = "e2e-policy"
		vaultClusterPolicyName = "e2e-cluster-policy"
		vaultRoleName          = "e2e-role"
		vaultClusterRoleName   = "e2e-cluster-role"
	)

	BeforeAll(func() {
		By("creating test namespace")
		cmd := exec.Command("kubectl", "create", "ns", testNamespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		// Check if Vault is already deployed (CI deploys it before tests)
		// If not deployed, deploy it (for local development)
		By("checking if Vault is deployed")
		cmd = exec.Command("kubectl", "get", "ns", vaultNamespace)
		_, err := utils.Run(cmd)
		if err != nil {
			By("deploying Vault dev server (not found, deploying for local development)")
			cmd = exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/vault.yaml")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to deploy Vault")
		}

		By("waiting for Vault to be ready")
		verifyVaultReady := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods", "-n", vaultNamespace,
				"-l", "app=vault", "-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"))
		}
		Eventually(verifyVaultReady, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("creating Vault token secret for VaultConnection")
		cmd = exec.Command("kubectl", "create", "secret", "generic", vaultTokenSecretName,
			"-n", testNamespace,
			"--from-literal=token=root")
		_, _ = utils.Run(cmd) // Ignore error if already exists
	})

	AfterAll(func() {
		By("cleaning up test resources")

		// Delete VaultClusterRole
		cmd := exec.Command("kubectl", "delete", "vaultclusterrole", vaultClusterRoleName,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)

		// Delete VaultRole
		cmd = exec.Command("kubectl", "delete", "vaultrole", vaultRoleName, "-n", testNamespace,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)

		// Delete VaultClusterPolicy
		cmd = exec.Command("kubectl", "delete", "vaultclusterpolicy", vaultClusterPolicyName,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)

		// Delete VaultPolicy
		cmd = exec.Command("kubectl", "delete", "vaultpolicy", vaultPolicyName, "-n", testNamespace,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)

		// Delete VaultConnection (this should clean up Vault resources via finalizers)
		cmd = exec.Command("kubectl", "delete", "vaultconnection", vaultConnectionName,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)

		// Wait for finalizers to complete
		time.Sleep(5 * time.Second)

		// Delete test namespace (but not vault namespace - CI manages that)
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(2 * time.Second)

	Context("VaultConnection", func() {
		It("should create a VaultConnection and establish connectivity", func() {
			By("creating VaultConnection resource")
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
			verifyConnectionActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", vaultConnectionName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultConnection not active, got: %s", output)
			}
			Eventually(verifyConnectionActive, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying VaultConnection has vault version")
			cmd = exec.Command("kubectl", "get", "vaultconnection", vaultConnectionName,
				"-o", "jsonpath={.status.vaultVersion}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("1."), "Expected Vault version in status")

			By("verifying VaultConnection has finalizer")
			cmd = exec.Command("kubectl", "get", "vaultconnection", vaultConnectionName,
				"-o", "jsonpath={.metadata.finalizers}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("vault.platform.io/finalizer"))
		})
	})

	Context("VaultClusterPolicy", func() {
		It("should create a VaultClusterPolicy and sync to Vault", func() {
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
`, vaultClusterPolicyName, vaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultClusterPolicy")

			By("waiting for VaultClusterPolicy to become Active")
			verifyPolicyActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultclusterpolicy", vaultClusterPolicyName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultClusterPolicy not active, got: %s", output)
			}
			Eventually(verifyPolicyActive).Should(Succeed())

			By("verifying VaultClusterPolicy has correct vaultName")
			cmd = exec.Command("kubectl", "get", "vaultclusterpolicy", vaultClusterPolicyName,
				"-o", "jsonpath={.status.vaultName}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal(vaultClusterPolicyName))

			By("verifying VaultClusterPolicy has correct rulesCount")
			cmd = exec.Command("kubectl", "get", "vaultclusterpolicy", vaultClusterPolicyName,
				"-o", "jsonpath={.status.rulesCount}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("2"))

			By("verifying policy exists in Vault")
			verifyPolicyInVault := func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
					"vault", "policy", "read", vaultClusterPolicyName)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("secret/data/shared/*"))
			}
			Eventually(verifyPolicyInVault).Should(Succeed())
		})
	})

	Context("VaultPolicy", func() {
		It("should create a namespaced VaultPolicy and sync to Vault", func() {
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
`, vaultPolicyName, testNamespace, vaultConnectionName, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

			By("waiting for VaultPolicy to become Active")
			verifyPolicyActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", vaultPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultPolicy not active, got: %s", output)
			}
			Eventually(verifyPolicyActive).Should(Succeed())

			By("verifying VaultPolicy has namespaced vaultName")
			cmd = exec.Command("kubectl", "get", "vaultpolicy", vaultPolicyName,
				"-n", testNamespace, "-o", "jsonpath={.status.vaultName}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, vaultPolicyName)
			Expect(output).To(Equal(expectedVaultName))

			By("verifying policy exists in Vault with namespaced name")
			verifyPolicyInVault := func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
					"vault", "policy", "read", expectedVaultName)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(testNamespace))
			}
			Eventually(verifyPolicyInVault).Should(Succeed())
		})

		It("should update VaultPolicy when spec changes", func() {
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
`, vaultPolicyName, testNamespace, vaultConnectionName, testNamespace, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying rulesCount updated to 2")
			verifyRulesCount := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", vaultPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.rulesCount}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("2"))
			}
			Eventually(verifyRulesCount).Should(Succeed())
		})
	})

	Context("VaultClusterRole", func() {
		It("should create a VaultClusterRole referencing policies", func() {
			By("creating a test service account")
			cmd := exec.Command("kubectl", "create", "serviceaccount", "e2e-test-sa", "-n", testNamespace)
			_, _ = utils.Run(cmd) // Ignore if exists

			By("creating VaultClusterRole resource")
			roleYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: %s
spec:
  connectionRef: %s
  authPath: "auth/kubernetes"
  serviceAccounts:
    - name: e2e-test-sa
      namespace: %s
  policies:
    - kind: VaultClusterPolicy
      name: %s
    - kind: VaultPolicy
      name: %s
      namespace: %s
  tokenTTL: "1h"
  tokenMaxTTL: "24h"
`, vaultClusterRoleName, vaultConnectionName, testNamespace, vaultClusterPolicyName, vaultPolicyName, testNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultClusterRole")

			By("waiting for VaultClusterRole to become Active")
			verifyRoleActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultclusterrole", vaultClusterRoleName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultClusterRole not active, got: %s", output)
			}
			Eventually(verifyRoleActive).Should(Succeed())

			By("verifying VaultClusterRole has correct vaultRoleName")
			cmd = exec.Command("kubectl", "get", "vaultclusterrole", vaultClusterRoleName,
				"-o", "jsonpath={.status.vaultRoleName}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal(vaultClusterRoleName))

			By("verifying VaultClusterRole has resolved policies")
			cmd = exec.Command("kubectl", "get", "vaultclusterrole", vaultClusterRoleName,
				"-o", "jsonpath={.status.resolvedPolicies}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring(vaultClusterPolicyName))
		})
	})

	Context("VaultRole", func() {
		It("should create a namespaced VaultRole", func() {
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
    - e2e-test-sa
  policies:
    - kind: VaultPolicy
      name: %s
      namespace: %s
  tokenTTL: "30m"
`, vaultRoleName, testNamespace, vaultConnectionName, vaultPolicyName, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultRole")

			By("waiting for VaultRole to become Active")
			verifyRoleActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultrole", vaultRoleName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultRole not active, got: %s", output)
			}
			Eventually(verifyRoleActive).Should(Succeed())

			By("verifying VaultRole has namespaced vaultRoleName")
			cmd = exec.Command("kubectl", "get", "vaultrole", vaultRoleName,
				"-n", testNamespace, "-o", "jsonpath={.status.vaultRoleName}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			expectedRoleName := fmt.Sprintf("%s-%s", testNamespace, vaultRoleName)
			Expect(output).To(Equal(expectedRoleName))

			By("verifying VaultRole has bound service accounts")
			cmd = exec.Command("kubectl", "get", "vaultrole", vaultRoleName,
				"-n", testNamespace, "-o", "jsonpath={.status.boundServiceAccounts}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("e2e-test-sa"))
		})
	})

	Context("Finalizer and Cleanup", func() {
		It("should handle VaultPolicy deletion with finalizer", func() {
			// Create a temporary policy to test deletion
			tempPolicyName := "e2e-temp-policy"
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
`, tempPolicyName, testNamespace, vaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for temporary policy to become Active")
			verifyPolicyActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", tempPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}
			Eventually(verifyPolicyActive).Should(Succeed())

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
			verifyPolicyDeleted := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", tempPolicyName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred()) // Should fail because resource is deleted
			}
			Eventually(verifyPolicyDeleted).Should(Succeed())

			By("verifying policy is deleted from Vault")
			verifyPolicyDeletedFromVault := func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
					"vault", "policy", "read", expectedVaultName)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred()) // Should fail because policy is deleted
			}
			Eventually(verifyPolicyDeletedFromVault).Should(Succeed())
		})

		It("should respect deletionPolicy=Retain", func() {
			retainPolicyName := "e2e-retain-policy"
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
`, retainPolicyName, testNamespace, vaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active")
			verifyPolicyActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", retainPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}
			Eventually(verifyPolicyActive).Should(Succeed())

			By("deleting the VaultPolicy with Retain policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", retainPolicyName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying policy is STILL in Vault after K8s deletion")
			// Wait a bit for deletion to complete
			time.Sleep(3 * time.Second)
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

	Context("Error Handling", func() {
		It("should handle invalid connection reference", func() {
			invalidPolicyName := "e2e-invalid-conn"

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

			By("verifying VaultPolicy enters Error phase")
			verifyPolicyError := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", invalidPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				// Could be Error or Pending depending on reconciliation
				g.Expect(output).To(Or(Equal("Error"), Equal("Pending")))
			}
			Eventually(verifyPolicyError, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up invalid policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", invalidPolicyName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})
	})
})

// stringReader creates an io.Reader from a string
func stringReader(s string) *stringReaderImpl {
	return &stringReaderImpl{data: []byte(s)}
}

type stringReaderImpl struct {
	data []byte
	pos  int
}

func (r *stringReaderImpl) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
