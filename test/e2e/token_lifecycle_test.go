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

var _ = Describe("Token Lifecycle", Ordered, func() {
	const (
		tokenLifecycleNamespace = "e2e-token-lifecycle"
		bootstrapSecretName     = "vault-bootstrap-token"
		bootstrapConnectionName = "e2e-bootstrap-conn"
		k8sAuthConnectionName   = "e2e-k8s-auth-conn"
		operatorRole            = "vault-access-operator"
		operatorPolicy          = "vault-access-operator"
	)

	BeforeAll(func() {
		By("creating token lifecycle test namespace")
		cmd := exec.Command("kubectl", "create", "ns", tokenLifecycleNamespace)
		_, _ = utils.Run(cmd) // Ignore if exists

		// Wait for Vault to be ready (CI deploys it first, but local dev might need this)
		By("waiting for Vault to be ready")
		verifyVaultReady := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods", "-n", vaultNamespace,
				"-l", "app=vault", "-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"))
		}
		Eventually(verifyVaultReady, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating bootstrap token secret with Vault root token")
		cmd = exec.Command("kubectl", "create", "secret", "generic", bootstrapSecretName,
			"-n", tokenLifecycleNamespace,
			"--from-literal=token=root")
		_, _ = utils.Run(cmd) // Ignore if exists

		By("creating operator policy in Vault")
		// This policy allows the operator to manage auth methods, roles, and policies
		policyHCL := `
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/kubernetes/config" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/auth" {
  capabilities = ["read"]
}
path "sys/auth/*" {
  capabilities = ["sudo", "create", "read", "update", "delete", "list"]
}
path "sys/mounts" {
  capabilities = ["read"]
}
`
		// Use kubectl exec to create the policy in Vault
		// Note: -i flag is required to pass stdin to the pod
		cmd = exec.Command("kubectl", "exec", "-i", "-n", vaultNamespace, "vault-0", "--",
			"vault", "policy", "write", operatorPolicy, "-")
		cmd.Stdin = stringReader(policyHCL)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create operator policy in Vault")
	})

	AfterAll(func() {
		By("cleaning up token lifecycle test resources")

		// Delete VaultConnections
		cmd := exec.Command("kubectl", "delete", "vaultconnection", bootstrapConnectionName,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)

		cmd = exec.Command("kubectl", "delete", "vaultconnection", k8sAuthConnectionName,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)

		// Wait for VaultConnections to be fully deleted (finalizers complete)
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName)
			_, err := utils.Run(cmd)
			g.Expect(err).To(HaveOccurred(), "VaultConnection should be deleted")
		}, 60*time.Second, 2*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "vaultconnection", k8sAuthConnectionName)
			_, err := utils.Run(cmd)
			g.Expect(err).To(HaveOccurred(), "VaultConnection should be deleted")
		}, 60*time.Second, 2*time.Second).Should(Succeed())

		// Clean up Vault resources created during bootstrap
		By("cleaning up Vault auth method and role")
		cmd = exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
			"vault", "auth", "disable", "kubernetes")
		_, _ = utils.Run(cmd) // Ignore errors

		cmd = exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
			"vault", "policy", "delete", operatorPolicy)
		_, _ = utils.Run(cmd)

		// Delete namespace
		cmd = exec.Command("kubectl", "delete", "ns", tokenLifecycleNamespace,
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
	})

	SetDefaultEventuallyTimeout(3 * time.Minute)
	SetDefaultEventuallyPollingInterval(3 * time.Second)

	Context("Bootstrap Flow", func() {
		It("should bootstrap Kubernetes auth using bootstrap token", func() {
			By("creating VaultConnection with bootstrap configuration")
			connectionYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: %s
spec:
  address: http://vault.%s.svc.cluster.local:8200
  auth:
    bootstrap:
      secretRef:
        name: %s
        namespace: %s
        key: token
      autoRevoke: false
    kubernetes:
      role: %s
      authPath: kubernetes
      tokenDuration: 1h
  healthCheckInterval: "30s"
`, bootstrapConnectionName, vaultNamespace, bootstrapSecretName, tokenLifecycleNamespace, operatorRole)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(connectionYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultConnection with bootstrap")

			By("waiting for VaultConnection to become Active")
			verifyConnectionActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultConnection not active, got: %s", output)
			}
			Eventually(verifyConnectionActive, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should complete bootstrap and transition to Kubernetes auth", func() {
			By("verifying bootstrapComplete is true")
			verifyBootstrapComplete := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
					"-o", "jsonpath={.status.authStatus.bootstrapComplete}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "Bootstrap not complete, got: %s", output)
			}
			Eventually(verifyBootstrapComplete).Should(Succeed())

			By("verifying authMethod is kubernetes")
			cmd := exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
				"-o", "jsonpath={.status.authStatus.authMethod}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("kubernetes"))

			By("verifying bootstrapCompletedAt is set")
			cmd = exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
				"-o", "jsonpath={.status.authStatus.bootstrapCompletedAt}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "bootstrapCompletedAt should be set")
		})

		It("should have Kubernetes auth enabled in Vault", func() {
			By("verifying Kubernetes auth method is enabled")
			verifyK8sAuthEnabled := func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
					"vault", "auth", "list", "-format=json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("kubernetes/"),
					"Kubernetes auth method not found in vault auth list")
			}
			Eventually(verifyK8sAuthEnabled).Should(Succeed())
		})

		It("should have operator role created in Vault", func() {
			By("verifying operator role exists with correct configuration")
			verifyRoleExists := func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", "-n", vaultNamespace, "vault-0", "--",
					"vault", "read", fmt.Sprintf("auth/kubernetes/role/%s", operatorRole))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				// The role should be bound to the operator's service account
				g.Expect(output).To(ContainSubstring("bound_service_account_names"))
			}
			Eventually(verifyRoleExists).Should(Succeed())
		})

		It("should not re-bootstrap on subsequent reconciles", func() {
			By("getting current bootstrapCompletedAt timestamp and resourceVersion")
			cmd := exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
				"-o", "jsonpath={.status.authStatus.bootstrapCompletedAt}")
			originalTimestamp, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(originalTimestamp).NotTo(BeEmpty())

			cmd = exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
				"-o", "jsonpath={.metadata.resourceVersion}")
			originalResourceVersion, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("triggering reconciliation via annotation")
			cmd = exec.Command("kubectl", "annotate", "vaultconnection", bootstrapConnectionName,
				fmt.Sprintf("reconcile-trigger=%d", time.Now().Unix()), "--overwrite")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			// Wait for reconciliation to complete by checking resourceVersion changed
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
					"-o", "jsonpath={.metadata.resourceVersion}")
				newResourceVersion, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(newResourceVersion).NotTo(Equal(originalResourceVersion),
					"resourceVersion should change after annotation")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying bootstrapCompletedAt timestamp hasn't changed")
			cmd = exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
				"-o", "jsonpath={.status.authStatus.bootstrapCompletedAt}")
			newTimestamp, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(newTimestamp).To(Equal(originalTimestamp),
				"bootstrapCompletedAt should not change after re-reconcile")

			By("verifying connection is still Active")
			cmd = exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
				"-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("Active"))
		})

		It("should have token expiration information", func() {
			By("verifying tokenExpiration is set")
			cmd := exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
				"-o", "jsonpath={.status.authStatus.tokenExpiration}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "tokenExpiration should be set")
		})

		It("should have Vault version in status", func() {
			By("verifying vaultVersion is set")
			cmd := exec.Command("kubectl", "get", "vaultconnection", bootstrapConnectionName,
				"-o", "jsonpath={.status.vaultVersion}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("1."), "Expected Vault version like 1.x.x")
		})
	})

	Context("Kubernetes Auth Without Bootstrap", func() {
		// This context tests direct K8s auth when Vault is already configured
		// (e.g., by the previous bootstrap test or external configuration)

		It("should connect using pre-configured Kubernetes auth", func() {
			By("creating VaultConnection with only Kubernetes auth (no bootstrap)")
			connectionYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: %s
spec:
  address: http://vault.%s.svc.cluster.local:8200
  auth:
    kubernetes:
      role: %s
      authPath: kubernetes
      tokenDuration: 1h
  healthCheckInterval: "30s"
`, k8sAuthConnectionName, vaultNamespace, operatorRole)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(connectionYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create VaultConnection with K8s auth")

			By("waiting for VaultConnection to become Active")
			verifyConnectionActive := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", k8sAuthConnectionName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"), "VaultConnection not active, got: %s", output)
			}
			Eventually(verifyConnectionActive, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should NOT have bootstrapComplete set", func() {
			By("verifying bootstrapComplete is NOT true")
			cmd := exec.Command("kubectl", "get", "vaultconnection", k8sAuthConnectionName,
				"-o", "jsonpath={.status.authStatus.bootstrapComplete}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			// bootstrapComplete should be empty or false (not "true")
			Expect(output).NotTo(Equal("true"),
				"bootstrapComplete should not be true when no bootstrap was configured")
		})

		It("should have authMethod set to kubernetes", func() {
			By("verifying authMethod is kubernetes")
			cmd := exec.Command("kubectl", "get", "vaultconnection", k8sAuthConnectionName,
				"-o", "jsonpath={.status.authStatus.authMethod}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("kubernetes"))
		})

		It("should have Vault version in status", func() {
			By("verifying vaultVersion is set")
			cmd := exec.Command("kubectl", "get", "vaultconnection", k8sAuthConnectionName,
				"-o", "jsonpath={.status.vaultVersion}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("1."), "Expected Vault version like 1.x.x")
		})

		It("should have token expiration information", func() {
			By("verifying tokenExpiration is set")
			cmd := exec.Command("kubectl", "get", "vaultconnection", k8sAuthConnectionName,
				"-o", "jsonpath={.status.authStatus.tokenExpiration}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "tokenExpiration should be set")
		})
	})

	// Token renewal tests are labeled "slow" because they require waiting for token
	// expiration threshold (~90s for 2m TTL). Skip with: --label-filter '!slow'
	Context("Token Lifecycle - Renewal", Label("slow"), func() {
		const renewalConnectionName = "e2e-renewal-conn"

		AfterEach(func() {
			By("cleaning up renewal test connection")
			cmd := exec.Command("kubectl", "delete", "vaultconnection", renewalConnectionName,
				"--ignore-not-found", "--timeout=30s")
			_, _ = utils.Run(cmd)
		})

		It("TC-LC07: Renew token when approaching expiration", Label("slow"), func() {
			By("creating VaultConnection with short token duration (2m)")
			connectionYAML := fmt.Sprintf(`
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: %s
spec:
  address: http://vault.%s.svc.cluster.local:8200
  auth:
    kubernetes:
      role: %s
      authPath: kubernetes
      tokenDuration: 2m
  healthCheckInterval: "10s"
`, renewalConnectionName, vaultNamespace, operatorRole)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = stringReader(connectionYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultConnection to become Active")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", renewalConnectionName,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("getting initial tokenLastRenewed timestamp")
			cmd = exec.Command("kubectl", "get", "vaultconnection", renewalConnectionName,
				"-o", "jsonpath={.status.authStatus.tokenLastRenewed}")
			initialRenewed, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for token renewal (happens at ~75% of 2m TTL = ~90s)")
			// Token renewal happens at ~75% of TTL, so for 2m = 120s, renewal at ~90s
			// Use Eventually with 3m timeout to allow for timing variations
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "vaultconnection", renewalConnectionName,
					"-o", "jsonpath={.status.authStatus.tokenRenewalCount}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(Equal(""), "Expected tokenRenewalCount to be set")
				g.Expect(output).NotTo(Equal("0"), "Expected token to have been renewed")
			}, 3*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying tokenLastRenewed has been updated")
			cmd = exec.Command("kubectl", "get", "vaultconnection", renewalConnectionName,
				"-o", "jsonpath={.status.authStatus.tokenLastRenewed}")
			newRenewed, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(newRenewed).NotTo(Equal(initialRenewed),
				"tokenLastRenewed should have been updated after renewal")

			By("verifying connection is still Active after renewal")
			cmd = exec.Command("kubectl", "get", "vaultconnection", renewalConnectionName,
				"-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("Active"))
		})
	})
})
