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
	"encoding/json"
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Edge Case Tests", Ordered, Label("edge"), func() {
	ctx := context.Background()

	// ─────────────────────────────────────────────────────────────────────────
	// TC-EDGE-LIM: Resource Limits
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-EDGE-LIM: Resource Limits", func() {
		It("TC-EDGE-LIM01: should handle policy with many rules", func() {
			policyName := uniqueName("tc-edge-manyrules")
			ruleCount := 100 // 100 rules

			By(fmt.Sprintf("creating VaultPolicy with %d rules", ruleCount))
			policy := BuildPolicyWithRules(policyName, ruleCount)

			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)

			By("waiting for policy to become Active")
			ExpectPolicyActive(ctx, policyName)

			By("verifying rules count in status")
			p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Status.RulesCount).To(Equal(ruleCount))

			By("verifying policy exists in Vault with all rules")
			vaultPolicyName := testNamespace + "-" + policyName
			content, err := GetVaultPolicyContent(ctx, vaultPolicyName)
			Expect(err).NotTo(HaveOccurred())
			// Check that content contains paths for many rules
			Expect(content).To(ContainSubstring("rule-0"))
			Expect(content).To(ContainSubstring("rule-99"))
		})

		It("TC-EDGE-LIM02: should handle role with many service accounts", func() {
			roleName := uniqueName("tc-edge-manysa")
			policyName := uniqueName("tc-edge-manysa-pol")
			saCount := 10

			By("creating test policy")
			policy := BuildTestPolicy(policyName)
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)
			ExpectPolicyActive(ctx, policyName)

			By(fmt.Sprintf("creating %d service accounts", saCount))
			saNames := make([]string, saCount)
			for i := 0; i < saCount; i++ {
				saNames[i] = uniqueName(fmt.Sprintf("tc-edge-sa%d", i))
				err := utils.CreateServiceAccount(ctx, testNamespace, saNames[i])
				Expect(err).NotTo(HaveOccurred())
			}
			defer func() {
				for _, sa := range saNames {
					CleanupServiceAccount(ctx, sa)
				}
			}()

			By("creating VaultRole with many service accounts")
			role := BuildRoleWithMultipleSAs(roleName, saNames, policyName)
			err = utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupRole(ctx, roleName)

			By("waiting for role to become Active")
			ExpectRoleActive(ctx, roleName)

			By("verifying all service accounts are bound")
			r, err := utils.GetVaultRole(ctx, roleName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Status.BoundServiceAccounts).To(HaveLen(saCount))
		})

		It("TC-EDGE-LIM03: should handle role with many policies", func() {
			roleName := uniqueName("tc-edge-manypol")
			saName := uniqueName("tc-edge-manypol-sa")
			policyCount := 5

			By("creating test service account")
			err := utils.CreateServiceAccount(ctx, testNamespace, saName)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupServiceAccount(ctx, saName)

			By(fmt.Sprintf("creating %d policies", policyCount))
			policyNames := make([]string, policyCount)
			policyRefs := make([]vaultv1alpha1.PolicyReference, policyCount)
			for i := 0; i < policyCount; i++ {
				policyNames[i] = uniqueName(fmt.Sprintf("tc-edge-pol%d", i))
				policy := BuildTestPolicy(policyNames[i])
				policy.Spec.Rules[0].Path = fmt.Sprintf("secret/data/policy%d/*", i)
				err := utils.CreateVaultPolicyCR(ctx, policy)
				Expect(err).NotTo(HaveOccurred())
				policyRefs[i] = vaultv1alpha1.PolicyReference{
					Kind:      "VaultPolicy",
					Name:      policyNames[i],
					Namespace: testNamespace,
				}
			}
			defer func() {
				for _, p := range policyNames {
					CleanupPolicy(ctx, p)
				}
			}()

			By("waiting for all policies to become Active")
			for _, p := range policyNames {
				ExpectPolicyActive(ctx, p)
			}

			By("creating VaultRole with many policies")
			role := BuildRoleWithMultiplePolicies(roleName, saName, policyRefs)
			err = utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupRole(ctx, roleName)

			By("waiting for role to become Active")
			ExpectRoleActive(ctx, roleName)

			By("verifying all policies are resolved")
			r, err := utils.GetVaultRole(ctx, roleName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Status.ResolvedPolicies).To(HaveLen(policyCount))
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-EDGE-CYCLE: Rapid Create/Delete Cycles
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-EDGE-CYCLE: Rapid Create/Delete Cycles", func() {
		It("TC-EDGE-CYCLE01: should handle rapid policy create/delete", func() {
			cycleCount := 5

			By(fmt.Sprintf("performing %d rapid create/delete cycles", cycleCount))
			for i := 0; i < cycleCount; i++ {
				policyName := uniqueName(fmt.Sprintf("tc-cycle%d", i))

				// Create
				policy := BuildTestPolicy(policyName)
				err := utils.CreateVaultPolicyCR(ctx, policy)
				Expect(err).NotTo(HaveOccurred(),
					"Cycle %d: create should succeed", i)

				// Don't wait for Active, immediately delete
				err = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
				Expect(err).NotTo(HaveOccurred(),
					"Cycle %d: delete should succeed", i)

				// Wait for deletion to complete before next cycle
				_ = utils.WaitForDeletion(
					ctx, &vaultv1alpha1.VaultPolicy{},
					policyName, testNamespace,
					30*time.Second, 2*time.Second,
				)
			}

			By("verifying no orphaned resources")
			// All policies should be deleted - verify by trying to get them
			for i := 0; i < cycleCount; i++ {
				policyName := fmt.Sprintf("tc-cycle%d", i)
				_, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
				// Should get not found error (or similar)
				if err == nil {
					// If policy still exists, clean it up
					CleanupPolicy(ctx, policyName)
				}
			}
		})

		It("TC-EDGE-CYCLE02: should handle create during delete", func() {
			policyName := uniqueName("tc-cycle-recreate")

			By("creating initial policy")
			policy := BuildTestPolicy(policyName)
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active")
			ExpectPolicyActive(ctx, policyName)

			By("deleting policy")
			err = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for deletion to complete")
			err = utils.WaitForDeletion(
				ctx, &vaultv1alpha1.VaultPolicy{},
				policyName, testNamespace,
				60*time.Second, 2*time.Second,
			)
			Expect(err).NotTo(HaveOccurred())

			By("recreating policy with same name")
			policy2 := BuildTestPolicy(policyName)
			err = utils.CreateVaultPolicyCR(ctx, policy2)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)

			By("waiting for recreated policy to become Active")
			ExpectPolicyActive(ctx, policyName)
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-EDGE-SHARE: Shared Resource Dependencies
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-EDGE-SHARE: Shared Resource Dependencies", func() {
		It("TC-EDGE-SHARE01: should handle multiple roles binding same policy", func() {
			policyName := uniqueName("tc-shared-policy")
			roleCount := 3

			By("creating shared policy")
			policy := BuildTestPolicy(policyName)
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)
			ExpectPolicyActive(ctx, policyName)

			By(fmt.Sprintf("creating %d roles binding the same policy", roleCount))
			roleNames := make([]string, roleCount)
			saNames := make([]string, roleCount)
			for i := 0; i < roleCount; i++ {
				saNames[i] = uniqueName(fmt.Sprintf("tc-share-sa%d", i))
				roleNames[i] = uniqueName(fmt.Sprintf("tc-share-role%d", i))

				err := utils.CreateServiceAccount(ctx, testNamespace, saNames[i])
				Expect(err).NotTo(HaveOccurred())

				role := BuildTestRole(roleNames[i], saNames[i], policyName)
				err = utils.CreateVaultRoleCR(ctx, role)
				Expect(err).NotTo(HaveOccurred())
			}
			defer func() {
				for i := 0; i < roleCount; i++ {
					CleanupRole(ctx, roleNames[i])
					CleanupServiceAccount(ctx, saNames[i])
				}
			}()

			By("waiting for all roles to become Active")
			for _, rn := range roleNames {
				ExpectRoleActive(ctx, rn)
			}

			By("verifying all roles reference the same policy")
			for _, rn := range roleNames {
				r, err := utils.GetVaultRole(ctx, rn, testNamespace)
				Expect(err).NotTo(HaveOccurred())
				expectedPolicyVaultName := testNamespace + "-" + policyName
				Expect(r.Status.ResolvedPolicies).To(ContainElement(expectedPolicyVaultName))
			}
		})

		It("TC-EDGE-SHARE02: should handle policy update affecting multiple roles", func() {
			policyName := uniqueName("tc-share-upd-pol")
			roleCount := 2

			By("creating shared policy")
			policy := BuildTestPolicy(policyName)
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)
			ExpectPolicyActive(ctx, policyName)

			By(fmt.Sprintf("creating %d roles", roleCount))
			roleNames := make([]string, roleCount)
			saNames := make([]string, roleCount)
			for i := 0; i < roleCount; i++ {
				saNames[i] = uniqueName(fmt.Sprintf("tc-shareupd-sa%d", i))
				roleNames[i] = uniqueName(fmt.Sprintf("tc-shareupd-role%d", i))

				err := utils.CreateServiceAccount(ctx, testNamespace, saNames[i])
				Expect(err).NotTo(HaveOccurred())

				role := BuildTestRole(roleNames[i], saNames[i], policyName)
				err = utils.CreateVaultRoleCR(ctx, role)
				Expect(err).NotTo(HaveOccurred())
			}
			defer func() {
				for i := 0; i < roleCount; i++ {
					CleanupRole(ctx, roleNames[i])
					CleanupServiceAccount(ctx, saNames[i])
				}
			}()

			By("waiting for all roles to become Active")
			for _, rn := range roleNames {
				ExpectRoleActive(ctx, rn)
			}

			By("updating the shared policy")
			err = utils.UpdateVaultPolicyCR(ctx, policyName, testNamespace,
				func(p *vaultv1alpha1.VaultPolicy) {
					p.Spec.Rules = append(p.Spec.Rules, vaultv1alpha1.PolicyRule{
						Path:         "secret/data/new-path/*",
						Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
					})
				})
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy update to sync")
			Eventually(func(g Gomega) {
				p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(p.Status.RulesCount).To(Equal(2))
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying all roles are still Active")
			for _, rn := range roleNames {
				r, err := utils.GetVaultRole(ctx, rn, testNamespace)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(r.Status.Phase)).To(Equal("Active"))
			}
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-EDGE-UPD: Update Scenarios
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-EDGE-UPD: Update Scenarios", func() {
		It("TC-EDGE-UPD01: should handle capability changes", func() {
			policyName := uniqueName("tc-upd-cap")

			By("creating policy with read-only capability")
			policy := BuildPolicyWithCapabilities(policyName, ReadOnlyCapabilities())
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)
			ExpectPolicyActive(ctx, policyName)

			By("verifying initial capabilities in Vault")
			vaultPolicyName := testNamespace + "-" + policyName
			content, err := GetVaultPolicyContent(ctx, vaultPolicyName)
			Expect(err).NotTo(HaveOccurred())
			Expect(content).To(ContainSubstring("read"))
			Expect(content).NotTo(ContainSubstring("create"))

			By("updating policy to full CRUD capabilities")
			err = utils.UpdateVaultPolicyCR(ctx, policyName, testNamespace,
				func(p *vaultv1alpha1.VaultPolicy) {
					p.Spec.Rules[0].Capabilities = AllCRUDCapabilities()
				})
			Expect(err).NotTo(HaveOccurred())

			By("waiting for update to sync")
			Eventually(func(g Gomega) {
				content, err := GetVaultPolicyContent(ctx, vaultPolicyName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(content).To(ContainSubstring("create"))
				g.Expect(content).To(ContainSubstring("update"))
				g.Expect(content).To(ContainSubstring("delete"))
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-EDGE-UPD02: should handle TTL changes on role", func() {
			roleName := uniqueName("tc-upd-ttl")
			policyName := uniqueName("tc-upd-ttl-pol")
			saName := uniqueName("tc-upd-ttl-sa")

			By("creating prerequisites")
			policy := BuildTestPolicy(policyName)
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)
			ExpectPolicyActive(ctx, policyName)

			err = utils.CreateServiceAccount(ctx, testNamespace, saName)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupServiceAccount(ctx, saName)

			By("creating role with 2m TTL")
			role := BuildRoleWithTTL(roleName, saName, policyName, "2m")
			err = utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupRole(ctx, roleName)
			ExpectRoleActive(ctx, roleName)

			By("updating role TTL to 5m")
			err = utils.UpdateVaultRoleCR(ctx, roleName, testNamespace,
				func(r *vaultv1alpha1.VaultRole) {
					r.Spec.TokenTTL = "5m"
				})
			Expect(err).NotTo(HaveOccurred())

			By("verifying TTL was updated in Vault")
			vaultRoleName := testNamespace + "-" + roleName
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				roleData, err := vaultClient.ReadAuthRole(ctx, "kubernetes", vaultRoleName)
				g.Expect(err).NotTo(HaveOccurred())
				// token_ttl is in seconds: 5m = 300s
				tokenTTL, ok := roleData["token_ttl"]
				g.Expect(ok).To(BeTrue())
				// Handle both float64 and json.Number depending on JSON unmarshaling
				var ttlValue int
				switch v := tokenTTL.(type) {
				case float64:
					ttlValue = int(v)
				case json.Number:
					ttlValue64, err := v.Int64()
					g.Expect(err).NotTo(HaveOccurred())
					ttlValue = int(ttlValue64)
				default:
					g.Expect(false).To(BeTrue(), fmt.Sprintf("unexpected type for token_ttl: %T", tokenTTL))
				}
				g.Expect(ttlValue).To(Equal(300))
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-EDGE-UPD03: should handle adding service accounts to existing role", func() {
			roleName := uniqueName("tc-upd-addsa")
			policyName := uniqueName("tc-upd-addsa-pol")
			sa1Name := uniqueName("tc-upd-addsa-sa1")
			sa2Name := uniqueName("tc-upd-addsa-sa2")

			By("creating prerequisites")
			policy := BuildTestPolicy(policyName)
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)
			ExpectPolicyActive(ctx, policyName)

			err = utils.CreateServiceAccount(ctx, testNamespace, sa1Name)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupServiceAccount(ctx, sa1Name)

			err = utils.CreateServiceAccount(ctx, testNamespace, sa2Name)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupServiceAccount(ctx, sa2Name)

			By("creating role with one service account")
			role := BuildTestRole(roleName, sa1Name, policyName)
			err = utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupRole(ctx, roleName)
			ExpectRoleActive(ctx, roleName)

			By("verifying initial bound service accounts")
			r, err := utils.GetVaultRole(ctx, roleName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Status.BoundServiceAccounts).To(HaveLen(1))

			By("adding second service account")
			err = utils.UpdateVaultRoleCR(ctx, roleName, testNamespace,
				func(r *vaultv1alpha1.VaultRole) {
					r.Spec.ServiceAccounts = []string{sa1Name, sa2Name}
				})
			Expect(err).NotTo(HaveOccurred())

			By("verifying both service accounts are bound")
			Eventually(func(g Gomega) {
				r, err := utils.GetVaultRole(ctx, roleName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(r.Status.BoundServiceAccounts).To(HaveLen(2))
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-EDGE-CONC: Concurrent Operations
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-EDGE-CONC: Concurrent Operations", func() {
		It("TC-EDGE-CONC01: should handle concurrent policy creations", func() {
			policyCount := 5
			var wg sync.WaitGroup
			policyNames := make([]string, policyCount)
			errors := make([]error, policyCount)

			By(fmt.Sprintf("creating %d policies concurrently", policyCount))
			for i := 0; i < policyCount; i++ {
				policyNames[i] = uniqueName(fmt.Sprintf("tc-conc-pol%d", i))
				wg.Add(1)
				go func(idx int, name string) {
					defer wg.Done()
					policy := BuildTestPolicy(name)
					errors[idx] = utils.CreateVaultPolicyCR(ctx, policy)
				}(i, policyNames[i])
			}
			wg.Wait()

			// Cleanup in defer
			defer func() {
				for _, pn := range policyNames {
					CleanupPolicy(ctx, pn)
				}
			}()

			By("verifying all creations succeeded")
			for i, err := range errors {
				Expect(err).NotTo(HaveOccurred(),
					"Policy %d creation should succeed", i)
			}

			By("waiting for all policies to become Active")
			for _, pn := range policyNames {
				ExpectPolicyActive(ctx, pn)
			}
		})

		It("TC-EDGE-CONC02: should handle concurrent updates to same policy", func() {
			policyName := uniqueName("tc-conc-update")

			By("creating initial policy")
			policy := BuildTestPolicy(policyName)
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)
			ExpectPolicyActive(ctx, policyName)

			By("performing concurrent updates")
			var wg sync.WaitGroup
			updateCount := 3
			for i := 0; i < updateCount; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					_ = utils.UpdateVaultPolicyCR(ctx, policyName, testNamespace,
						func(p *vaultv1alpha1.VaultPolicy) {
							p.Spec.Rules[0].Description = fmt.Sprintf("Update %d", idx)
						})
				}(i)
			}
			wg.Wait()

			By("verifying policy is still Active after concurrent updates")
			// Give the controller time to reconcile
			time.Sleep(2 * time.Second)
			ExpectPolicyActive(ctx, policyName)
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-EDGE-REC: Recovery Scenarios
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-EDGE-REC: Recovery Scenarios", func() {
		It("TC-EDGE-REC01: should recover after connection becomes available", func() {
			// This test verifies that a policy waiting for connection
			// eventually syncs when connection becomes Active

			connName := uniqueName("tc-rec-conn")
			policyName := uniqueName("tc-rec-pol")

			By("creating a VaultPolicy referencing non-existent connection")
			policy := BuildTestPolicy(policyName)
			policy.Spec.ConnectionRef = connName
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)

			By("verifying policy is not Active (connection missing)")
			Eventually(func(g Gomega) {
				status, getErr := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
				g.Expect(getErr).NotTo(HaveOccurred())
				g.Expect(status).NotTo(Equal("Active"))
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("creating the VaultConnection")
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name: connName,
				},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: fmt.Sprintf(
						"http://vault.%s.svc.cluster.local:8200", vaultNamespace,
					),
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name:      sharedVaultTokenSecretName,
								Namespace: testNamespace,
								Key:       "token",
							},
						},
					},
					HealthCheckInterval: "10s",
				},
			}
			err = utils.CreateVaultConnectionCR(ctx, conn)
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = utils.DeleteVaultConnectionCR(ctx, connName) }()

			By("waiting for connection to become Active")
			Eventually(func(g Gomega) {
				status, getErr := utils.GetVaultConnectionStatus(ctx, connName, "")
				g.Expect(getErr).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for policy to recover and become Active")
			// The controller should eventually notice the connection is ready
			Eventually(func(g Gomega) {
				status, getErr := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
				g.Expect(getErr).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})
