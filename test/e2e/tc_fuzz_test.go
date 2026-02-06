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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"pgregory.net/rapid"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Fuzz Tests", Ordered, Label("fuzz"), func() {
	ctx := context.Background()

	// Shared resources
	var sharedPolicyName, sharedSAName string

	BeforeAll(func() {
		By("creating shared resources for fuzz tests")
		sharedPolicyName = uniqueName("tc-fuzz-policy")
		sharedSAName = uniqueName("tc-fuzz-sa")

		_ = utils.CreateServiceAccount(ctx, testNamespace, sharedSAName)

		policy := BuildTestPolicy(sharedPolicyName)
		err := utils.CreateVaultPolicyCR(ctx, policy)
		Expect(err).NotTo(HaveOccurred())

		ExpectPolicyActive(ctx, sharedPolicyName)
	})

	AfterAll(func() {
		By("cleaning up shared fuzz test resources")
		CleanupPolicy(ctx, sharedPolicyName)
		CleanupServiceAccount(ctx, sharedSAName)
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-FUZZ-PATH: Fuzz Testing for Policy Paths
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-FUZZ-PATH: Policy Path Fuzzing", func() {
		It("TC-FUZZ-PATH01: should handle random valid path patterns without panicking", func() {
			rapid.Check(GinkgoT(), func(t *rapid.T) {
				// Generate random paths using allowed characters
				// CRD pattern: ^[a-zA-Z0-9/_*{}+-]+$
				path := rapid.StringMatching(`[a-zA-Z0-9/_*+-]{1,50}`).Draw(t, "path")

				// Skip empty paths (not valid)
				if path == "" {
					return
				}

				policyName := uniqueName("tc-fuzz-path")
				policy := BuildPolicyWithPath(policyName, path, false)

				err := utils.CreateVaultPolicyCR(ctx, policy)
				// Always cleanup
				defer CleanupPolicy(ctx, policyName)

				// The system should either:
				// 1. Accept the path and become Active
				// 2. Reject with a validation error
				// 3. Enter Error state with meaningful message
				// It should NEVER panic or hang

				if err != nil {
					// Validation error is acceptable
					t.Logf("Path %q rejected: %v", path, err)
				} else {
					// Wait a short time for reconciliation
					time.Sleep(2 * time.Second)

					status, getErr := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
					if getErr == nil {
						// Should be in a valid state
						Expect(status).To(Or(
							Equal("Active"),
							Equal("Error"),
							Equal("Pending"),
							Equal("Syncing"),
						), "Path %q resulted in invalid state: %s", path, status)
					}
				}
			})
		})

		It("TC-FUZZ-PATH02: should handle random namespace template paths", func() {
			rapid.Check(GinkgoT(), func(t *rapid.T) {
				// Generate path with {{namespace}} in random position
				prefix := rapid.StringMatching(`[a-z0-9/]{0,20}`).Draw(t, "prefix")
				suffix := rapid.StringMatching(`[a-z0-9/*]{0,20}`).Draw(t, "suffix")
				path := prefix + "{{namespace}}" + suffix

				policyName := uniqueName("tc-fuzz-ns")
				policy := BuildPolicyWithPath(policyName, path, true)

				err := utils.CreateVaultPolicyCR(ctx, policy)
				defer CleanupPolicy(ctx, policyName)

				if err == nil {
					// Wait for reconciliation
					time.Sleep(2 * time.Second)

					p, getErr := utils.GetVaultPolicy(ctx, policyName, testNamespace)
					if getErr == nil && p.Status.Phase == vaultv1alpha1.PhaseActive {
						// If Active, verify namespace was substituted
						vaultPolicyName := testNamespace + "-" + policyName
						content, contentErr := GetVaultPolicyContent(ctx, vaultPolicyName)
						if contentErr == nil {
							Expect(content).NotTo(ContainSubstring("{{namespace}}"),
								"Namespace template should be substituted")
						}
					}
				}
			})
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-FUZZ-TTL: Fuzz Testing for TTL Values
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-FUZZ-TTL: Token TTL Fuzzing", func() {
		It("TC-FUZZ-TTL01: should handle random duration-like strings", func() {
			rapid.Check(GinkgoT(), func(t *rapid.T) {
				// Generate various TTL-like strings
				ttl := rapid.OneOf(
					// Valid Go duration patterns
					rapid.StringMatching(`[0-9]{1,3}[smh]`),
					// Compound durations
					rapid.StringMatching(`[0-9]{1,2}h[0-9]{1,2}m`),
					// Pure numbers (should be invalid)
					rapid.StringMatching(`[0-9]{1,5}`),
					// Random text
					rapid.StringMatching(`[a-z]{1,10}`),
					// Empty
					rapid.Just(""),
				).Draw(t, "ttl")

				roleName := uniqueName("tc-fuzz-ttl")
				role := BuildRoleWithTTL(roleName, sharedSAName, sharedPolicyName, ttl)

				err := utils.CreateVaultRoleCR(ctx, role)
				defer CleanupRole(ctx, roleName)

				if err != nil {
					// Validation rejection is acceptable
					t.Logf("TTL %q rejected: %v", ttl, err)
				} else {
					// Wait for reconciliation
					time.Sleep(2 * time.Second)

					status, getErr := utils.GetVaultRoleStatus(ctx, roleName, testNamespace)
					if getErr == nil {
						// Should be in a valid state
						Expect(status).To(Or(
							Equal("Active"),
							Equal("Error"),
							Equal("Pending"),
							Equal("Syncing"),
						), "TTL %q resulted in invalid state: %s", ttl, status)
					}
				}
			})
		})

		It("TC-FUZZ-TTL02: should handle extreme TTL values", func() {
			testCases := []string{
				"0s",
				"1ns",
				"1ms",
				"999999h",
				"2147483647s",           // Max int32
				"9223372036854775807ns", // Max int64
			}

			for _, ttl := range testCases {
				roleName := uniqueName("tc-fuzz-extreme")
				role := BuildRoleWithTTL(roleName, sharedSAName, sharedPolicyName, ttl)

				err := utils.CreateVaultRoleCR(ctx, role)

				if err == nil {
					// Give controller time to process
					time.Sleep(2 * time.Second)
				}

				// Cleanup regardless of outcome
				CleanupRole(ctx, roleName)

				// Should not panic - test passes if we get here
			}
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-FUZZ-NAME: Fuzz Testing for Resource Names
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-FUZZ-NAME: Resource Name Fuzzing", func() {
		It("TC-FUZZ-NAME01: should handle DNS-1123 compliant names", func() {
			rapid.Check(GinkgoT(), func(t *rapid.T) {
				// Generate DNS-1123 subdomain pattern names
				// Must start with alphanumeric, contain alphanumeric and hyphens
				name := rapid.StringMatching(`[a-z0-9]([a-z0-9-]*[a-z0-9])?`).Draw(t, "name")

				// Kubernetes name length limit is 253, but keep it shorter
				if len(name) == 0 || len(name) > 63 {
					return
				}

				// Ensure it doesn't start or end with hyphen
				if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
					return
				}

				policyName := fmt.Sprintf("tc-fuzz-%s", name)
				// Truncate if too long
				if len(policyName) > 63 {
					policyName = policyName[:63]
				}

				policy := BuildTestPolicy(policyName)

				err := utils.CreateVaultPolicyCR(ctx, policy)
				defer CleanupPolicy(ctx, policyName)

				if err == nil {
					// Wait for reconciliation
					time.Sleep(2 * time.Second)

					status, getErr := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
					if getErr == nil {
						Expect(status).To(Or(
							Equal("Active"),
							Equal("Error"),
							Equal("Pending"),
							Equal("Syncing"),
						))
					}
				}
			})
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-FUZZ-CAP: Fuzz Testing for Capability Combinations
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-FUZZ-CAP: Capability Combination Fuzzing", func() {
		It("TC-FUZZ-CAP01: should handle random capability subsets", func() {
			allCaps := []vaultv1alpha1.Capability{
				vaultv1alpha1.CapabilityCreate,
				vaultv1alpha1.CapabilityRead,
				vaultv1alpha1.CapabilityUpdate,
				vaultv1alpha1.CapabilityDelete,
				vaultv1alpha1.CapabilityList,
				vaultv1alpha1.CapabilitySudo,
				vaultv1alpha1.CapabilityDeny,
			}

			rapid.Check(GinkgoT(), func(t *rapid.T) {
				// Generate random subset of capabilities
				capCount := rapid.IntRange(0, len(allCaps)).Draw(t, "capCount")
				selectedCaps := make([]vaultv1alpha1.Capability, 0, capCount)

				// Random selection
				for i := 0; i < capCount; i++ {
					idx := rapid.IntRange(0, len(allCaps)-1).Draw(t, fmt.Sprintf("idx%d", i))
					selectedCaps = append(selectedCaps, allCaps[idx])
				}

				policyName := uniqueName("tc-fuzz-cap")
				policy := BuildPolicyWithCapabilities(policyName, selectedCaps)

				err := utils.CreateVaultPolicyCR(ctx, policy)
				defer CleanupPolicy(ctx, policyName)

				if err != nil {
					// Empty capabilities should be rejected
					if len(selectedCaps) == 0 {
						t.Logf("Empty capabilities correctly rejected")
					}
				} else {
					// Wait for reconciliation
					time.Sleep(2 * time.Second)

					status, getErr := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
					if getErr == nil {
						Expect(status).To(Or(
							Equal("Active"),
							Equal("Error"),
							Equal("Pending"),
							Equal("Syncing"),
						))
					}
				}
			})
		})

		It("TC-FUZZ-CAP02: should handle duplicate capabilities gracefully", func() {
			rapid.Check(GinkgoT(), func(t *rapid.T) {
				// Generate capabilities with intentional duplicates
				baseCaps := []vaultv1alpha1.Capability{
					vaultv1alpha1.CapabilityRead,
					vaultv1alpha1.CapabilityList,
				}

				// Add 0-5 duplicates of random capabilities
				dupCount := rapid.IntRange(0, 5).Draw(t, "dupCount")
				caps := make([]vaultv1alpha1.Capability, len(baseCaps))
				copy(caps, baseCaps)

				for i := 0; i < dupCount; i++ {
					idx := rapid.IntRange(0, len(baseCaps)-1).Draw(t, fmt.Sprintf("dup%d", i))
					caps = append(caps, baseCaps[idx])
				}

				policyName := uniqueName("tc-fuzz-dup")
				policy := BuildPolicyWithCapabilities(policyName, caps)

				err := utils.CreateVaultPolicyCR(ctx, policy)
				defer CleanupPolicy(ctx, policyName)

				// Duplicates should be accepted (Vault dedupes)
				if err == nil {
					ExpectPolicyActive(ctx, policyName)
				}
			})
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-FUZZ-RULE: Fuzz Testing for Multiple Rules
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-FUZZ-RULE: Multiple Rules Fuzzing", func() {
		It("TC-FUZZ-RULE01: should handle random number of rules", func() {
			rapid.Check(GinkgoT(), func(t *rapid.T) {
				// Generate 1-20 rules
				ruleCount := rapid.IntRange(1, 20).Draw(t, "ruleCount")

				policyName := uniqueName("tc-fuzz-rules")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      policyName,
						Namespace: testNamespace,
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: sharedVaultConnectionName,
						Rules:         make([]vaultv1alpha1.PolicyRule, ruleCount),
					},
				}

				for i := 0; i < ruleCount; i++ {
					// Generate random path segment
					segment := rapid.StringMatching(`[a-z0-9]{1,10}`).Draw(t, fmt.Sprintf("seg%d", i))
					policy.Spec.Rules[i] = vaultv1alpha1.PolicyRule{
						Path: fmt.Sprintf("secret/data/rule%d/%s/*", i, segment),
						Capabilities: []vaultv1alpha1.Capability{
							vaultv1alpha1.CapabilityRead,
						},
					}
				}

				err := utils.CreateVaultPolicyCR(ctx, policy)
				defer CleanupPolicy(ctx, policyName)

				if err == nil {
					// Wait for reconciliation
					time.Sleep(3 * time.Second)

					p, getErr := utils.GetVaultPolicy(ctx, policyName, testNamespace)
					if getErr == nil && p.Status.Phase == vaultv1alpha1.PhaseActive {
						Expect(p.Status.RulesCount).To(Equal(ruleCount))
					}
				}
			})
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-FUZZ-STRESS: Stress Testing with Random Operations
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-FUZZ-STRESS: Stress Testing", func() {
		It("TC-FUZZ-STRESS01: should survive rapid random policy operations", func() {
			policyNames := make([]string, 0)

			rapid.Check(GinkgoT(), func(t *rapid.T) {
				operation := rapid.IntRange(0, 2).Draw(t, "operation")

				switch operation {
				case 0: // Create
					policyName := uniqueName("tc-fuzz-stress")
					policy := BuildTestPolicy(policyName)
					err := utils.CreateVaultPolicyCR(ctx, policy)
					if err == nil {
						policyNames = append(policyNames, policyName)
					}

				case 1: // Delete (if we have any)
					if len(policyNames) > 0 {
						idx := rapid.IntRange(0, len(policyNames)-1).Draw(t, "delIdx")
						_ = utils.DeleteVaultPolicyCR(ctx, policyNames[idx], testNamespace)
						// Remove from list
						policyNames = append(policyNames[:idx], policyNames[idx+1:]...)
					}

				case 2: // Update (if we have any)
					if len(policyNames) > 0 {
						idx := rapid.IntRange(0, len(policyNames)-1).Draw(t, "updIdx")
						_ = utils.UpdateVaultPolicyCR(ctx, policyNames[idx], testNamespace,
							func(p *vaultv1alpha1.VaultPolicy) {
								p.Spec.Rules[0].Description = fmt.Sprintf("Updated at %d", time.Now().UnixNano())
							})
					}
				}

				// Small delay between operations
				time.Sleep(100 * time.Millisecond)
			})

			// Cleanup any remaining policies
			for _, pn := range policyNames {
				CleanupPolicy(ctx, pn)
			}
		})
	})
})
