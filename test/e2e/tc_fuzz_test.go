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
	"math/rand/v2"
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
			RunFuzzBatch(ctx,
				func(rng *rand.Rand, _ int) FuzzBatchItem {
					// Generate random paths using allowed characters
					// CRD pattern: ^[a-zA-Z0-9/_*{}+-]+$
					path := randPath(rng)
					return FuzzBatchItem{
						Name: uniqueName("tc-fuzz-path"),
						Data: path,
					}
				},
				func(ctx context.Context, item FuzzBatchItem) error {
					path := item.Data.(string)
					policy := BuildPolicyWithPath(item.Name, path, false)
					return utils.CreateVaultPolicyCR(ctx, policy)
				},
				func(ctx context.Context, item FuzzBatchItem) {
					path := item.Data.(string)
					// The system should either:
					// 1. Accept the path and become Active
					// 2. Reject with a validation error
					// 3. Enter Error state with meaningful message
					// It should NEVER panic or hang
					status, getErr := utils.GetVaultPolicyStatus(ctx, item.Name, testNamespace)
					if getErr == nil {
						Expect(status).To(Or(
							Equal("Active"),
							Equal("Error"),
							Equal("Pending"),
							Equal("Syncing"),
						), "Path %q resulted in invalid state: %s", path, status)
					}
				},
				func(ctx context.Context, item FuzzBatchItem) {
					CleanupPolicy(ctx, item.Name)
				},
			)
		})

		It("TC-FUZZ-PATH02: should handle random namespace template paths", func() {
			RunFuzzBatch(ctx,
				func(rng *rand.Rand, _ int) FuzzBatchItem {
					// Generate path with {{namespace}} in random position
					prefix := randStringFromCharset(rng, "abcdefghijklmnopqrstuvwxyz0123456789/", 0, 20)
					suffix := randStringFromCharset(rng, "abcdefghijklmnopqrstuvwxyz0123456789/*", 0, 20)
					path := prefix + "{{namespace}}" + suffix
					return FuzzBatchItem{
						Name: uniqueName("tc-fuzz-ns"),
						Data: path,
					}
				},
				func(ctx context.Context, item FuzzBatchItem) error {
					path := item.Data.(string)
					policy := BuildPolicyWithPath(item.Name, path, true)
					return utils.CreateVaultPolicyCR(ctx, policy)
				},
				func(ctx context.Context, item FuzzBatchItem) {
					p, getErr := utils.GetVaultPolicy(ctx, item.Name, testNamespace)
					if getErr == nil && p.Status.Phase == vaultv1alpha1.PhaseActive {
						// If Active, verify namespace was substituted
						vaultPolicyName := testNamespace + "-" + item.Name
						content, contentErr := GetVaultPolicyContent(ctx, vaultPolicyName)
						if contentErr == nil {
							Expect(content).NotTo(ContainSubstring("{{namespace}}"),
								"Namespace template should be substituted")
						}
					}
				},
				func(ctx context.Context, item FuzzBatchItem) {
					CleanupPolicy(ctx, item.Name)
				},
			)
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-FUZZ-TTL: Fuzz Testing for TTL Values
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-FUZZ-TTL: Token TTL Fuzzing", func() {
		It("TC-FUZZ-TTL01: should handle random duration-like strings", func() {
			RunFuzzBatch(ctx,
				func(rng *rand.Rand, _ int) FuzzBatchItem {
					ttl := randTTL(rng)
					return FuzzBatchItem{
						Name: uniqueName("tc-fuzz-ttl"),
						Data: ttl,
					}
				},
				func(ctx context.Context, item FuzzBatchItem) error {
					ttl := item.Data.(string)
					role := BuildRoleWithTTL(item.Name, sharedSAName, sharedPolicyName, ttl)
					return utils.CreateVaultRoleCR(ctx, role)
				},
				func(ctx context.Context, item FuzzBatchItem) {
					ttl := item.Data.(string)
					status, getErr := utils.GetVaultRoleStatus(ctx, item.Name, testNamespace)
					if getErr == nil {
						Expect(status).To(Or(
							Equal("Active"),
							Equal("Error"),
							Equal("Pending"),
							Equal("Syncing"),
						), "TTL %q resulted in invalid state: %s", ttl, status)
					}
				},
				func(ctx context.Context, item FuzzBatchItem) {
					CleanupRole(ctx, item.Name)
				},
			)
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
			RunFuzzBatch(ctx,
				func(rng *rand.Rand, _ int) FuzzBatchItem {
					name := randDNSName(rng)
					policyName := fmt.Sprintf("tc-fuzz-%s", name)
					// Truncate if too long
					if len(policyName) > 63 {
						policyName = policyName[:63]
					}
					return FuzzBatchItem{
						Name: policyName,
						Data: nil,
					}
				},
				func(ctx context.Context, item FuzzBatchItem) error {
					policy := BuildTestPolicy(item.Name)
					return utils.CreateVaultPolicyCR(ctx, policy)
				},
				func(ctx context.Context, item FuzzBatchItem) {
					status, getErr := utils.GetVaultPolicyStatus(ctx, item.Name, testNamespace)
					if getErr == nil {
						Expect(status).To(Or(
							Equal("Active"),
							Equal("Error"),
							Equal("Pending"),
							Equal("Syncing"),
						))
					}
				},
				func(ctx context.Context, item FuzzBatchItem) {
					CleanupPolicy(ctx, item.Name)
				},
			)
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

			RunFuzzBatch(ctx,
				func(rng *rand.Rand, _ int) FuzzBatchItem {
					caps := randCapSubset(rng, allCaps)
					return FuzzBatchItem{
						Name: uniqueName("tc-fuzz-cap"),
						Data: caps,
					}
				},
				func(ctx context.Context, item FuzzBatchItem) error {
					caps := item.Data.([]vaultv1alpha1.Capability)
					policy := BuildPolicyWithCapabilities(item.Name, caps)
					return utils.CreateVaultPolicyCR(ctx, policy)
				},
				func(ctx context.Context, item FuzzBatchItem) {
					status, getErr := utils.GetVaultPolicyStatus(ctx, item.Name, testNamespace)
					if getErr == nil {
						Expect(status).To(Or(
							Equal("Active"),
							Equal("Error"),
							Equal("Pending"),
							Equal("Syncing"),
						))
					}
				},
				func(ctx context.Context, item FuzzBatchItem) {
					CleanupPolicy(ctx, item.Name)
				},
			)
		})

		It("TC-FUZZ-CAP02: should handle duplicate capabilities gracefully", func() {
			baseCaps := []vaultv1alpha1.Capability{
				vaultv1alpha1.CapabilityRead,
				vaultv1alpha1.CapabilityList,
			}

			RunFuzzBatch(ctx,
				func(rng *rand.Rand, _ int) FuzzBatchItem {
					// Start with base capabilities, then add 0-5 random duplicates
					caps := make([]vaultv1alpha1.Capability, len(baseCaps))
					copy(caps, baseCaps)
					dupCount := rng.IntN(6)
					for i := 0; i < dupCount; i++ {
						caps = append(caps, baseCaps[rng.IntN(len(baseCaps))])
					}
					return FuzzBatchItem{
						Name: uniqueName("tc-fuzz-dup"),
						Data: caps,
					}
				},
				func(ctx context.Context, item FuzzBatchItem) error {
					caps := item.Data.([]vaultv1alpha1.Capability)
					policy := BuildPolicyWithCapabilities(item.Name, caps)
					return utils.CreateVaultPolicyCR(ctx, policy)
				},
				func(ctx context.Context, item FuzzBatchItem) {
					// Duplicates should be accepted (Vault dedupes)
					ExpectPolicyActive(ctx, item.Name)
				},
				func(ctx context.Context, item FuzzBatchItem) {
					CleanupPolicy(ctx, item.Name)
				},
			)
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-FUZZ-RULE: Fuzz Testing for Multiple Rules
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-FUZZ-RULE: Multiple Rules Fuzzing", func() {
		It("TC-FUZZ-RULE01: should handle random number of rules", func() {
			// ruleData holds the generated rule count and path segments for
			// building and verifying the policy.
			type ruleData struct {
				ruleCount int
				segments  []string
			}

			RunFuzzBatch(ctx,
				func(rng *rand.Rand, _ int) FuzzBatchItem {
					rc := rng.IntN(20) + 1
					segs := make([]string, rc)
					for i := range segs {
						segs[i] = randSegment(rng)
					}
					return FuzzBatchItem{
						Name: uniqueName("tc-fuzz-rules"),
						Data: ruleData{ruleCount: rc, segments: segs},
					}
				},
				func(ctx context.Context, item FuzzBatchItem) error {
					rd := item.Data.(ruleData)
					policy := &vaultv1alpha1.VaultPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      item.Name,
							Namespace: testNamespace,
						},
						Spec: vaultv1alpha1.VaultPolicySpec{
							ConnectionRef: sharedVaultConnectionName,
							Rules:         make([]vaultv1alpha1.PolicyRule, rd.ruleCount),
						},
					}
					for i := 0; i < rd.ruleCount; i++ {
						policy.Spec.Rules[i] = vaultv1alpha1.PolicyRule{
							Path: fmt.Sprintf("secret/data/rule%d/%s/*", i, rd.segments[i]),
							Capabilities: []vaultv1alpha1.Capability{
								vaultv1alpha1.CapabilityRead,
							},
						}
					}
					return utils.CreateVaultPolicyCR(ctx, policy)
				},
				func(ctx context.Context, item FuzzBatchItem) {
					rd := item.Data.(ruleData)
					p, getErr := utils.GetVaultPolicy(ctx, item.Name, testNamespace)
					if getErr == nil && p.Status.Phase == vaultv1alpha1.PhaseActive {
						Expect(p.Status.RulesCount).To(Equal(rd.ruleCount))
					}
				},
				func(ctx context.Context, item FuzzBatchItem) {
					CleanupPolicy(ctx, item.Name)
				},
			)
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-FUZZ-STRESS: Stress Testing with Random Operations
	// (Not batched — state-machine test where iterations depend on accumulated state)
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
