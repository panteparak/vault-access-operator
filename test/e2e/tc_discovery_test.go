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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Discovery Tests", Ordered, Label("discovery"), func() {
	ctx := context.Background()

	// Discovery requires its own VaultConnection with discovery enabled
	const (
		discoveryConnectionName = "e2e-discovery"
		discoveryTokenSecret    = "vault-token-discovery"
	)

	BeforeAll(func() {
		By("creating token secret for discovery connection")
		// Reuse the same Vault client - get a new token
		vaultClient, err := utils.GetTestVaultClient()
		Expect(err).NotTo(HaveOccurred())

		// Create a new operator token for the discovery connection
		operatorToken, err := vaultClient.CreateToken(ctx, []string{operatorPolicyName}, "1h")
		Expect(err).NotTo(HaveOccurred())

		err = utils.CreateSecret(ctx, testNamespace, discoveryTokenSecret,
			map[string][]byte{"token": []byte(operatorToken)})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("cleaning up discovery connection")
		_ = utils.DeleteVaultConnectionCR(ctx, discoveryConnectionName)
		_ = utils.DeleteSecret(ctx, testNamespace, discoveryTokenSecret)
	})

	Context("TC-DISC: Resource Discovery", func() {
		It("TC-DISC01-POLICY: Discovery finds unmanaged policies", func() {
			unmanagedPolicyName := "tc-disc01-unmanaged-policy"

			By("creating an unmanaged policy directly in Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			policyHCL := `path "secret/data/unmanaged/*" { capabilities = ["read"] }`
			err = vaultClient.WritePolicy(ctx, unmanagedPolicyName, policyHCL)
			Expect(err).NotTo(HaveOccurred())

			By("creating VaultConnection with discovery enabled")
			boolTrue := true
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name: discoveryConnectionName,
				},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: fmt.Sprintf("http://vault.%s.svc.cluster.local:8200", vaultNamespace),
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name:      discoveryTokenSecret,
								Namespace: testNamespace,
								Key:       "token",
							},
						},
					},
					Discovery: &vaultv1alpha1.DiscoveryConfig{
						Enabled:               true,
						Interval:              "30s", // Short interval for testing
						PolicyPatterns:        []string{"tc-disc*"},
						ExcludeSystemPolicies: &boolTrue,
					},
				},
			}
			err = utils.CreateVaultConnectionCR(ctx, conn)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultConnection to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultConnectionStatus(ctx, discoveryConnectionName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for discovery scan to complete and find the unmanaged policy")
			Eventually(func(g Gomega) {
				vc, err := utils.GetVaultConnection(ctx, discoveryConnectionName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(vc.Status.DiscoveryStatus).NotTo(BeNil(),
					"DiscoveryStatus should be populated")
				g.Expect(vc.Status.DiscoveryStatus.LastScanAt).NotTo(BeNil(),
					"LastScanAt should be set after scan")
				g.Expect(vc.Status.DiscoveryStatus.UnmanagedPolicies).To(BeNumerically(">=", 1),
					"Should find at least 1 unmanaged policy")

				// Verify the specific policy is discovered
				found := false
				for _, res := range vc.Status.DiscoveryStatus.DiscoveredResources {
					if res.Type == "policy" && res.Name == unmanagedPolicyName {
						found = true
						g.Expect(res.AdoptionStatus).To(Equal("discovered"))
						break
					}
				}
				g.Expect(found).To(BeTrue(),
					"Should find the unmanaged policy '%s' in discovered resources", unmanagedPolicyName)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up the unmanaged policy")
			_ = vaultClient.DeletePolicy(ctx, unmanagedPolicyName)

			By("cleaning up discovery connection for next test")
			_ = utils.DeleteVaultConnectionCR(ctx, discoveryConnectionName)
			Eventually(func(g Gomega) {
				_, err := utils.GetVaultConnection(ctx, discoveryConnectionName, "")
				g.Expect(err).To(HaveOccurred()) // Should be deleted
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-DISC02-ROLE: Discovery finds unmanaged roles", func() {
			unmanagedRoleName := "tc-disc02-unmanaged-role"

			By("creating an unmanaged role directly in Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			roleData := map[string]interface{}{
				"bound_service_account_names":      []string{"unmanaged-sa"},
				"bound_service_account_namespaces": []string{testNamespace},
				"policies":                         []string{"default"},
				"ttl":                              "5m",
			}
			err = vaultClient.WriteAuthRole(ctx, "kubernetes", unmanagedRoleName, roleData)
			Expect(err).NotTo(HaveOccurred())

			By("creating VaultConnection with discovery enabled for roles")
			boolTrue := true
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name: discoveryConnectionName,
				},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: fmt.Sprintf("http://vault.%s.svc.cluster.local:8200", vaultNamespace),
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name:      discoveryTokenSecret,
								Namespace: testNamespace,
								Key:       "token",
							},
						},
					},
					Discovery: &vaultv1alpha1.DiscoveryConfig{
						Enabled:               true,
						Interval:              "30s",
						RolePatterns:          []string{"tc-disc*"},
						ExcludeSystemPolicies: &boolTrue,
					},
				},
			}
			err = utils.CreateVaultConnectionCR(ctx, conn)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultConnection to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultConnectionStatus(ctx, discoveryConnectionName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for discovery scan to find the unmanaged role")
			Eventually(func(g Gomega) {
				vc, err := utils.GetVaultConnection(ctx, discoveryConnectionName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(vc.Status.DiscoveryStatus).NotTo(BeNil())
				g.Expect(vc.Status.DiscoveryStatus.UnmanagedRoles).To(BeNumerically(">=", 1),
					"Should find at least 1 unmanaged role")

				// Verify the specific role is discovered
				found := false
				for _, res := range vc.Status.DiscoveryStatus.DiscoveredResources {
					if res.Type == "role" && res.Name == unmanagedRoleName {
						found = true
						break
					}
				}
				g.Expect(found).To(BeTrue(),
					"Should find the unmanaged role '%s' in discovered resources", unmanagedRoleName)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up the unmanaged role")
			_ = vaultClient.DeleteAuthRole(ctx, "kubernetes", unmanagedRoleName)

			By("cleaning up discovery connection for next test")
			_ = utils.DeleteVaultConnectionCR(ctx, discoveryConnectionName)
			Eventually(func(g Gomega) {
				_, err := utils.GetVaultConnection(ctx, discoveryConnectionName, "")
				g.Expect(err).To(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-DISC03-PATTERN: Discovery respects patterns", func() {
			matchingPolicy := "tc-disc03-matching-policy"
			nonMatchingPolicy := "other-nonmatching-policy"

			By("creating policies in Vault - one matching pattern, one not")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			policyHCL := `path "secret/data/test/*" { capabilities = ["read"] }`
			err = vaultClient.WritePolicy(ctx, matchingPolicy, policyHCL)
			Expect(err).NotTo(HaveOccurred())
			err = vaultClient.WritePolicy(ctx, nonMatchingPolicy, policyHCL)
			Expect(err).NotTo(HaveOccurred())

			By("creating VaultConnection with specific pattern filter")
			boolTrue := true
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name: discoveryConnectionName,
				},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: fmt.Sprintf("http://vault.%s.svc.cluster.local:8200", vaultNamespace),
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name:      discoveryTokenSecret,
								Namespace: testNamespace,
								Key:       "token",
							},
						},
					},
					Discovery: &vaultv1alpha1.DiscoveryConfig{
						Enabled:               true,
						Interval:              "30s",
						PolicyPatterns:        []string{"tc-disc03-*"}, // Only match tc-disc03-* policies
						ExcludeSystemPolicies: &boolTrue,
					},
				},
			}
			err = utils.CreateVaultConnectionCR(ctx, conn)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for discovery scan")
			Eventually(func(g Gomega) {
				vc, err := utils.GetVaultConnection(ctx, discoveryConnectionName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(vc.Status.DiscoveryStatus).NotTo(BeNil())
				g.Expect(vc.Status.DiscoveryStatus.LastScanAt).NotTo(BeNil())

				// Should find the matching policy
				foundMatching := false
				foundNonMatching := false
				for _, res := range vc.Status.DiscoveryStatus.DiscoveredResources {
					if res.Name == matchingPolicy {
						foundMatching = true
					}
					if res.Name == nonMatchingPolicy {
						foundNonMatching = true
					}
				}
				g.Expect(foundMatching).To(BeTrue(),
					"Should discover policy matching pattern: %s", matchingPolicy)
				g.Expect(foundNonMatching).To(BeFalse(),
					"Should NOT discover policy not matching pattern: %s", nonMatchingPolicy)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up policies")
			_ = vaultClient.DeletePolicy(ctx, matchingPolicy)
			_ = vaultClient.DeletePolicy(ctx, nonMatchingPolicy)
			_ = utils.DeleteVaultConnectionCR(ctx, discoveryConnectionName)
			Eventually(func(g Gomega) {
				_, err := utils.GetVaultConnection(ctx, discoveryConnectionName, "")
				g.Expect(err).To(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-DISC04-EXCLUDE: Discovery excludes system policies by default", func() {
			By("creating VaultConnection with discovery enabled (default excludeSystemPolicies)")
			boolTrue := true
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name: discoveryConnectionName,
				},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: fmt.Sprintf("http://vault.%s.svc.cluster.local:8200", vaultNamespace),
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name:      discoveryTokenSecret,
								Namespace: testNamespace,
								Key:       "token",
							},
						},
					},
					Discovery: &vaultv1alpha1.DiscoveryConfig{
						Enabled:               true,
						Interval:              "30s",
						PolicyPatterns:        []string{"*"}, // Match all
						ExcludeSystemPolicies: &boolTrue,
					},
				},
			}
			err := utils.CreateVaultConnectionCR(ctx, conn)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for discovery scan")
			Eventually(func(g Gomega) {
				vc, err := utils.GetVaultConnection(ctx, discoveryConnectionName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(vc.Status.DiscoveryStatus).NotTo(BeNil())
				g.Expect(vc.Status.DiscoveryStatus.LastScanAt).NotTo(BeNil())

				// System policies (root, default) should NOT be discovered
				for _, res := range vc.Status.DiscoveryStatus.DiscoveredResources {
					g.Expect(res.Name).NotTo(Equal("root"),
						"System policy 'root' should be excluded")
					g.Expect(res.Name).NotTo(Equal("default"),
						"System policy 'default' should be excluded")
				}
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up")
			_ = utils.DeleteVaultConnectionCR(ctx, discoveryConnectionName)
		})
	})
})
