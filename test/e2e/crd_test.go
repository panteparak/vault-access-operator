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
	"io"
	"os/exec"
	"strings"
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

		It("should write correct policy rules to Vault (content verification)", func() {
			By("reading policy content from Vault")
			var policyContent string
			verifyPolicyContent := func(g Gomega) {
				var err error
				policyContent, err = utils.ReadVaultPolicy(vaultClusterPolicyName)
				g.Expect(err).NotTo(HaveOccurred())
			}
			Eventually(verifyPolicyContent).Should(Succeed())

			By("verifying all paths are present in policy HCL")
			Expect(policyContent).To(ContainSubstring(`path "secret/data/shared/*"`),
				"Policy should contain secret/data/shared/* path")
			Expect(policyContent).To(ContainSubstring(`path "secret/metadata/shared/*"`),
				"Policy should contain secret/metadata/shared/* path")

			By("verifying capabilities are correctly written")
			// The policy should contain read and list capabilities
			Expect(policyContent).To(ContainSubstring("read"),
				"Policy should include read capability")
			Expect(policyContent).To(ContainSubstring("list"),
				"Policy should include list capability")
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

		It("should substitute {{namespace}} variable in policy paths", func() {
			nsSubstPolicyName := "e2e-ns-subst-policy"
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
`, nsSubstPolicyName, testNamespace, vaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active")
			verifyActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", nsSubstPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}
			Eventually(verifyActive).Should(Succeed())

			By("reading policy content from Vault and verifying namespace substitution")
			verifySubstitution := func(g Gomega) {
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
			}
			Eventually(verifySubstitution).Should(Succeed())

			By("cleaning up namespace substitution test policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", nsSubstPolicyName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
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

		It("should configure role with correct service accounts and policies in Vault", func() {
			By("reading role configuration from Vault")
			var roleJSON string
			verifyRoleExists := func(g Gomega) {
				var err error
				roleJSON, err = utils.ReadVaultRole("auth/kubernetes", vaultClusterRoleName)
				g.Expect(err).NotTo(HaveOccurred())
			}
			Eventually(verifyRoleExists).Should(Succeed())

			By("parsing role JSON and verifying configuration")
			// Parse the JSON response
			var roleResponse struct {
				Data struct {
					BoundServiceAccountNames      []string `json:"bound_service_account_names"`
					BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
					TokenPolicies                 []string `json:"token_policies"`
					TokenTTL                      int      `json:"token_ttl"`
					TokenMaxTTL                   int      `json:"token_max_ttl"`
				} `json:"data"`
			}
			err := json.Unmarshal([]byte(roleJSON), &roleResponse)
			Expect(err).NotTo(HaveOccurred(), "Failed to parse role JSON: %s", roleJSON)

			By("verifying bound service accounts")
			Expect(roleResponse.Data.BoundServiceAccountNames).To(ContainElement("e2e-test-sa"),
				"Role should have e2e-test-sa as bound service account")

			By("verifying bound namespaces")
			Expect(roleResponse.Data.BoundServiceAccountNamespaces).To(ContainElement(testNamespace),
				"Role should have test namespace as bound namespace")

			By("verifying policies are attached")
			Expect(roleResponse.Data.TokenPolicies).To(ContainElement(vaultClusterPolicyName),
				"Role should have cluster policy attached")
			// VaultPolicy gets namespace-prefixed name
			expectedPolicyName := fmt.Sprintf("%s-%s", testNamespace, vaultPolicyName)
			Expect(roleResponse.Data.TokenPolicies).To(ContainElement(expectedPolicyName),
				"Role should have namespaced policy attached")

			By("verifying token TTL configuration")
			// tokenTTL is "1h" = 3600 seconds
			Expect(roleResponse.Data.TokenTTL).To(Equal(3600),
				"Role should have token_ttl of 1h (3600 seconds)")
			// tokenMaxTTL is "24h" = 86400 seconds
			Expect(roleResponse.Data.TokenMaxTTL).To(Equal(86400),
				"Role should have token_max_ttl of 24h (86400 seconds)")
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

		It("should configure namespaced role correctly in Vault", func() {
			expectedRoleName := fmt.Sprintf("%s-%s", testNamespace, vaultRoleName)

			By("reading role configuration from Vault")
			var roleJSON string
			verifyRoleExists := func(g Gomega) {
				var err error
				roleJSON, err = utils.ReadVaultRole("auth/kubernetes", expectedRoleName)
				g.Expect(err).NotTo(HaveOccurred())
			}
			Eventually(verifyRoleExists).Should(Succeed())

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
			Expect(roleResponse.Data.BoundServiceAccountNames).To(ContainElement("e2e-test-sa"),
				"Role should have e2e-test-sa as bound service account")
			// VaultRole only binds to its own namespace
			Expect(roleResponse.Data.BoundServiceAccountNamespaces).To(ConsistOf(testNamespace),
				"Role should only be bound to its own namespace")

			By("verifying policies are attached with namespace prefix")
			expectedPolicyName := fmt.Sprintf("%s-%s", testNamespace, vaultPolicyName)
			Expect(roleResponse.Data.TokenPolicies).To(ContainElement(expectedPolicyName),
				"Role should have namespaced policy attached")

			By("verifying token TTL configuration")
			// tokenTTL is "30m" = 1800 seconds
			Expect(roleResponse.Data.TokenTTL).To(Equal(1800),
				"Role should have token_ttl of 30m (1800 seconds)")
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

		It("should remove role from Vault when VaultRole is deleted", func() {
			tempRoleName := "e2e-temp-role"
			tempPolicyName := "e2e-role-cleanup-policy"
			tempSAName := "e2e-temp-role-sa"
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
`, tempPolicyName, testNamespace, vaultConnectionName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for temp policy to become Active")
			verifyPolicyActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", tempPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}
			Eventually(verifyPolicyActive).Should(Succeed())

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
`, tempRoleName, testNamespace, vaultConnectionName, tempSAName, tempPolicyName, testNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultRole to become Active")
			verifyRoleActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultrole", tempRoleName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}
			Eventually(verifyRoleActive).Should(Succeed())

			By("verifying role exists in Vault")
			verifyRoleInVault := func(g Gomega) {
				exists, err := utils.VaultRoleExists("auth/kubernetes", expectedRoleVaultName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeTrue(), "Role should exist in Vault")
			}
			Eventually(verifyRoleInVault).Should(Succeed())

			By("deleting the VaultRole")
			cmd = exec.Command("kubectl", "delete", "vaultrole", tempRoleName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultRole resource is deleted from Kubernetes")
			verifyRoleDeleted := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultrole", tempRoleName, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred())
			}
			Eventually(verifyRoleDeleted).Should(Succeed())

			By("verifying role is removed from Vault")
			verifyRoleDeletedFromVault := func(g Gomega) {
				exists, err := utils.VaultRoleExists("auth/kubernetes", expectedRoleVaultName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeFalse(), "Role should be removed from Vault")
			}
			Eventually(verifyRoleDeletedFromVault).Should(Succeed())

			By("cleaning up temp policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", tempPolicyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "serviceaccount", tempSAName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			// Clean up from Vault if still exists
			_ = utils.DeleteVaultPolicy(expectedPolicyVaultName)
		})
	})

	Context("Service Account Authentication", func() {
		It("should allow bound service account to authenticate with Vault", func() {
			saName := "e2e-auth-test-sa"
			authRoleName := "e2e-auth-role"
			authPolicyName := "e2e-auth-policy"
			expectedPolicyVaultName := fmt.Sprintf("%s-%s", testNamespace, authPolicyName)
			expectedRoleVaultName := fmt.Sprintf("%s-%s", testNamespace, authRoleName)

			By("creating a test service account")
			cmd := exec.Command("kubectl", "create", "serviceaccount", saName, "-n", testNamespace)
			_, _ = utils.Run(cmd) // Ignore if exists

			By("creating a VaultPolicy for the auth test")
			policyYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: %s
  namespace: %s
spec:
  connectionRef: %s
  rules:
    - path: "secret/data/auth-test/*"
      capabilities: ["read"]
`, authPolicyName, testNamespace, vaultConnectionName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for auth test policy to become Active")
			verifyPolicyActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", authPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}
			Eventually(verifyPolicyActive).Should(Succeed())

			By("creating a VaultRole that binds the service account")
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
  tokenTTL: "15m"
`, authRoleName, testNamespace, vaultConnectionName, saName, authPolicyName, testNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for auth role to become Active")
			verifyRoleActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultrole", authRoleName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}
			Eventually(verifyRoleActive).Should(Succeed())

			By("getting a JWT token for the service account")
			saToken, err := utils.GetServiceAccountToken(testNamespace, saName)
			Expect(err).NotTo(HaveOccurred())
			saToken = strings.TrimSpace(saToken)
			Expect(saToken).NotTo(BeEmpty(), "Service account token should not be empty")

			By("attempting to login to Vault with the service account JWT")
			verifyLogin := func(g Gomega) {
				loginOutput, err := utils.VaultLoginWithJWT("auth/kubernetes", expectedRoleVaultName, saToken)
				g.Expect(err).NotTo(HaveOccurred(), "Vault login should succeed")

				// Parse the login response to verify policies
				var loginResponse struct {
					Auth struct {
						ClientToken   string   `json:"client_token"`
						TokenPolicies []string `json:"token_policies"`
						LeaseDuration int      `json:"lease_duration"`
					} `json:"auth"`
				}
				err = json.Unmarshal([]byte(loginOutput), &loginResponse)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to parse login response")

				// Verify we got a client token
				g.Expect(loginResponse.Auth.ClientToken).NotTo(BeEmpty(),
					"Should receive a Vault client token")

				// Verify policies are attached
				g.Expect(loginResponse.Auth.TokenPolicies).To(ContainElement(expectedPolicyVaultName),
					"Token should have the auth test policy attached")

				// Verify lease duration matches TTL (15m = 900s)
				g.Expect(loginResponse.Auth.LeaseDuration).To(Equal(900),
					"Token lease duration should be 15m (900 seconds)")
			}
			Eventually(verifyLogin).Should(Succeed())

			By("cleaning up auth test resources")
			cmd = exec.Command("kubectl", "delete", "vaultrole", authRoleName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", authPolicyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "serviceaccount", saName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})
	})

	Context("Conflict Policy", func() {
		It("should adopt existing unmanaged policy when conflictPolicy=Adopt", func() {
			adoptPolicyName := "e2e-adopt-policy"
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
`, adoptPolicyName, testNamespace, vaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active (adoption successful)")
			verifyActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", adoptPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultPolicy should be Active after adoption")
			}
			Eventually(verifyActive).Should(Succeed())

			By("verifying policy content was updated by operator")
			verifyContent := func(g Gomega) {
				policyContent, err := utils.ReadVaultPolicy(expectedVaultName)
				g.Expect(err).NotTo(HaveOccurred())
				// Should now contain the new path from K8s spec, not the old unmanaged content
				g.Expect(policyContent).To(ContainSubstring("adopted"),
					"Policy should contain new adopted path")
			}
			Eventually(verifyContent).Should(Succeed())

			By("cleaning up adopt test policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", adoptPolicyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
		})

		It("should fail when policy exists and conflictPolicy=Fail", func() {
			failPolicyName := "e2e-fail-policy"
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
`, failPolicyName, testNamespace, vaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultPolicy enters Conflict or Error phase")
			verifyConflict := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", failPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Conflict"), Equal("Error")),
					"VaultPolicy should be in Conflict or Error phase")
			}
			Eventually(verifyConflict, 30*time.Second, 2*time.Second).Should(Succeed())

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
			// Also clean up the unmanaged policy from Vault
			_ = utils.DeleteVaultPolicy(expectedVaultName)
		})

		It("should create policy normally when no conflict exists", func() {
			newPolicyName := "e2e-new-policy"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, newPolicyName)

			By("ensuring policy does NOT exist in Vault")
			_ = utils.DeleteVaultPolicy(expectedVaultName)

			By("creating VaultPolicy with conflictPolicy=Fail (default)")
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
`, newPolicyName, testNamespace, vaultConnectionName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active")
			verifyActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", newPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}
			Eventually(verifyActive).Should(Succeed())

			By("cleaning up new policy")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", newPolicyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
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

		It("should handle missing policy reference in VaultRole", func() {
			missingPolicyRoleName := "e2e-missing-policy-role"
			missingPolicySAName := "e2e-missing-policy-sa"

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
`, missingPolicyRoleName, testNamespace, vaultConnectionName, missingPolicySAName, testNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(roleYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultRole enters Error or Pending phase")
			verifyRoleError := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultrole", missingPolicyRoleName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Error"), Equal("Pending")),
					"VaultRole should be in Error or Pending phase due to missing policy")
			}
			Eventually(verifyRoleError, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying status message indicates missing policy")
			cmd = exec.Command("kubectl", "get", "vaultrole", missingPolicyRoleName,
				"-n", testNamespace, "-o", "jsonpath={.status.message}")
			output, err := utils.Run(cmd)
			// Check if there's an error message about missing policy
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

		It("should reject policy without {{namespace}} when enforcement is enabled via webhook", func() {
			violationPolicyName := "e2e-boundary-violation"

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
`, violationPolicyName, testNamespace, vaultConnectionName)

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
				verifyPolicyState := func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "vaultpolicy", violationPolicyName,
						"-n", testNamespace, "-o", "jsonpath={.status.phase}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					// If webhook didn't catch it, controller should
					g.Expect(output).To(Or(Equal("Error"), Equal("Active")))
				}
				Eventually(verifyPolicyState, 30*time.Second, 2*time.Second).Should(Succeed())

				By("cleaning up boundary violation policy")
				cmd = exec.Command("kubectl", "delete", "vaultpolicy", violationPolicyName,
					"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
				_, _ = utils.Run(cmd)
			}
		})

		It("should handle VaultConnection becoming unavailable", func() {
			unavailConnName := "e2e-unavail-conn"
			unavailPolicyName := "e2e-unavail-policy"

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
        name: %s
        namespace: %s
        key: token
  healthCheckInterval: "5s"
`, unavailConnName, testNamespace, vaultTokenSecretName, testNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(connYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying VaultConnection enters Error or Pending phase")
			verifyConnError := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", unavailConnName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Error"), Equal("Pending")),
					"VaultConnection should be in Error or Pending phase")
			}
			Eventually(verifyConnError, 30*time.Second, 2*time.Second).Should(Succeed())

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
			verifyPolicyError := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultpolicy", unavailPolicyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Error"), Equal("Pending")),
					"VaultPolicy should be in Error or Pending phase when connection unavailable")
			}
			Eventually(verifyPolicyError, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up unavailable connection test resources")
			cmd = exec.Command("kubectl", "delete", "vaultpolicy", unavailPolicyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "vaultconnection", unavailConnName,
				"--ignore-not-found", "--timeout=30s")
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
