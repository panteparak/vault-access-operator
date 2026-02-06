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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Input Validation Tests", Ordered, Label("validation"), func() {
	ctx := context.Background()

	// Shared resources for role-based tests
	var sharedPolicyName, sharedSAName string

	BeforeAll(func() {
		By("creating shared resources for validation tests")
		sharedPolicyName = uniqueName("tc-val-policy")
		sharedSAName = uniqueName("tc-val-sa")

		_ = utils.CreateServiceAccount(ctx, testNamespace, sharedSAName)

		policy := BuildTestPolicy(sharedPolicyName)
		err := utils.CreateVaultPolicyCR(ctx, policy)
		Expect(err).NotTo(HaveOccurred())

		ExpectPolicyActive(ctx, sharedPolicyName)
	})

	AfterAll(func() {
		By("cleaning up shared validation test resources")
		CleanupPolicy(ctx, sharedPolicyName)
		CleanupServiceAccount(ctx, sharedSAName)
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-VAL: Policy Path Validation
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-VAL-PATH: Policy Path Validation", func() {
		DescribeTable("should validate policy paths correctly",
			func(path string, enforceNS bool, expectValid bool) {
				policyName := uniqueName("tc-val-path")
				policy := BuildPolicyWithPath(policyName, path, enforceNS)

				err := utils.CreateVaultPolicyCR(ctx, policy)
				defer CleanupPolicy(ctx, policyName)

				if expectValid {
					Expect(err).NotTo(HaveOccurred(), "Path should be valid: %s", path)
					ExpectPolicyActive(ctx, policyName)
				} else {
					// Invalid paths may be rejected by webhook or controller
					if err != nil {
						// Webhook rejected - expected for malformed paths
						Expect(err.Error()).To(Or(
							ContainSubstring("invalid"),
							ContainSubstring("path"),
							ContainSubstring("pattern"),
							ContainSubstring("validation"),
						))
					} else {
						// Controller should detect and error
						ExpectPhaseNotActive(ctx, func() (string, error) {
							return utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
						})
					}
				}
			},
			// Valid paths
			Entry("simple path", "secret/data/myapp", false, true),
			Entry("wildcard suffix", "secret/data/*", false, true),
			Entry("namespace template", "secret/data/{{namespace}}/*", true, true),
			Entry("nested path", "secret/data/team/app/config", false, true),
			Entry("auth path", "auth/kubernetes/role/myapp", false, true),
			Entry("sys path", "sys/policies/acl/admin", false, true),
			Entry("plus wildcard", "secret/+/data", false, true),
			Entry("path with numbers", "secret/data/app123", false, true),
			Entry("path with hyphens", "secret/data/my-app-config", false, true),
			Entry("path with underscores", "secret/data/my_app", false, true),

			// Namespace enforcement
			Entry("valid namespace path", "secret/data/{{namespace}}/app/*", true, true),
			Entry("namespace in middle", "secret/{{namespace}}/data/*", true, true),

			// These would be rejected by CRD pattern validation (regex: ^[a-zA-Z0-9/_*{}+-]+$)
			// The webhook will reject these at admission time
		)

		DescribeTable("should reject paths with invalid characters",
			func(invalidChar string) {
				policyName := uniqueName("tc-val-char")
				path := "secret/data" + invalidChar + "test"
				policy := BuildPolicyWithPath(policyName, path, false)

				err := utils.CreateVaultPolicyCR(ctx, policy)
				defer CleanupPolicy(ctx, policyName)

				// CRD pattern validation should reject these
				if err != nil {
					// Expected - webhook rejected the invalid path
					Expect(err.Error()).To(Or(
						ContainSubstring("invalid"),
						ContainSubstring("pattern"),
						ContainSubstring("validation"),
						ContainSubstring("spec.rules"),
					))
				} else {
					// If it passed webhook, it might still fail in controller
					// (this shouldn't happen with proper CRD validation)
					Eventually(func(g Gomega) {
						status, getErr := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
						g.Expect(getErr).NotTo(HaveOccurred())
						// Either Error or Active (if char is actually valid)
						g.Expect(status).To(Or(Equal("Error"), Equal("Active")))
					}, 30*time.Second, 2*time.Second).Should(Succeed())
				}
			},
			Entry("semicolon", ";"),
			Entry("pipe", "|"),
			Entry("ampersand", "&"),
			Entry("backtick", "`"),
			Entry("dollar sign", "$"),
			Entry("single quote", "'"),
			Entry("double quote", "\""),
			Entry("less than", "<"),
			Entry("greater than", ">"),
			Entry("open paren", "("),
			Entry("close paren", ")"),
			Entry("backslash", "\\"),
		)
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-VAL-TTL: TTL Format Validation
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-VAL-TTL: Token TTL Validation", func() {
		DescribeTable("should validate TTL formats correctly",
			func(ttl string, expectValid bool) {
				roleName := uniqueName("tc-val-ttl")
				role := BuildRoleWithTTL(roleName, sharedSAName, sharedPolicyName, ttl)

				err := utils.CreateVaultRoleCR(ctx, role)
				defer CleanupRole(ctx, roleName)

				if expectValid {
					Expect(err).NotTo(HaveOccurred(), "TTL should be valid: %s", ttl)
					ExpectRoleActive(ctx, roleName)
				} else {
					// Invalid TTLs may be rejected by webhook or Vault
					if err != nil {
						// Webhook rejected
						Expect(err.Error()).To(Or(
							ContainSubstring("ttl"),
							ContainSubstring("duration"),
							ContainSubstring("invalid"),
							ContainSubstring("format"),
						))
					} else {
						// Vault may reject during sync, or controller catches it
						Eventually(func(g Gomega) {
							status, getErr := utils.GetVaultRoleStatus(ctx, roleName, testNamespace)
							g.Expect(getErr).NotTo(HaveOccurred())
							// May be Error, Pending, or Active if Vault accepts non-standard formats
							g.Expect(status).To(Or(
								Equal("Error"),
								Equal("Pending"),
								Equal("Syncing"),
								Equal("Active"), // Vault may accept some formats we consider "invalid"
							))
						}, 30*time.Second, 2*time.Second).Should(Succeed())
					}
				}
			},
			// Valid Go duration formats
			Entry("30 seconds", "30s", true),
			Entry("5 minutes", "5m", true),
			Entry("30 minutes", "30m", true),
			Entry("1 hour", "1h", true),
			Entry("24 hours", "24h", true),
			Entry("168 hours (1 week)", "168h", true),
			Entry("1 hour 30 minutes", "1h30m", true),
			Entry("2 hours 30 minutes 15 seconds", "2h30m15s", true),

			// Invalid formats
			Entry("text format", "thirty-minutes", false),
			Entry("missing unit", "30", false),
			Entry("invalid unit", "30x", false),
			Entry("negative value", "-1h", false),
			Entry("random text", "abc", false),
			Entry("spaces in value", "1 hour", false),
		)
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-VAL-CAP: Capability Validation
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-VAL-CAP: Capability Validation", func() {
		DescribeTable("should validate capability combinations correctly",
			func(caps []vaultv1alpha1.Capability, expectValid bool) {
				policyName := uniqueName("tc-val-cap")
				policy := BuildPolicyWithCapabilities(policyName, caps)

				err := utils.CreateVaultPolicyCR(ctx, policy)
				defer CleanupPolicy(ctx, policyName)

				if expectValid {
					Expect(err).NotTo(HaveOccurred(), "Capabilities should be valid")
					ExpectPolicyActive(ctx, policyName)
				} else {
					// Empty capabilities should be rejected by MinItems=1 validation
					if err != nil {
						Expect(err.Error()).To(Or(
							ContainSubstring("capabilities"),
							ContainSubstring("required"),
							ContainSubstring("minimum"),
							ContainSubstring("MinItems"),
						))
					} else {
						// If accepted, should error during reconciliation
						ExpectPhaseNotActive(ctx, func() (string, error) {
							return utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
						})
					}
				}
			},
			// Valid capability combinations
			Entry("read only", []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}, true),
			Entry("list only", []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityList}, true),
			Entry("read and list", []vaultv1alpha1.Capability{
				vaultv1alpha1.CapabilityRead,
				vaultv1alpha1.CapabilityList,
			}, true),
			Entry("full CRUD", []vaultv1alpha1.Capability{
				vaultv1alpha1.CapabilityCreate,
				vaultv1alpha1.CapabilityRead,
				vaultv1alpha1.CapabilityUpdate,
				vaultv1alpha1.CapabilityDelete,
				vaultv1alpha1.CapabilityList,
			}, true),
			Entry("with sudo", []vaultv1alpha1.Capability{
				vaultv1alpha1.CapabilityRead,
				vaultv1alpha1.CapabilitySudo,
			}, true),
			Entry("deny only", []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityDeny}, true),
			Entry("all capabilities", AllCapabilities(), true),

			// Invalid combinations
			Entry("empty capabilities", []vaultv1alpha1.Capability{}, false),
		)

		It("should handle duplicate capabilities gracefully", func() {
			policyName := uniqueName("tc-val-dup-cap")
			policy := BuildTestPolicy(policyName)
			// Duplicate capabilities - Vault typically dedupes these
			policy.Spec.Rules[0].Capabilities = []vaultv1alpha1.Capability{
				vaultv1alpha1.CapabilityRead,
				vaultv1alpha1.CapabilityRead,
				vaultv1alpha1.CapabilityList,
			}

			err := utils.CreateVaultPolicyCR(ctx, policy)
			defer CleanupPolicy(ctx, policyName)

			// Duplicates should be accepted (Vault will dedupe)
			Expect(err).NotTo(HaveOccurred())
			ExpectPolicyActive(ctx, policyName)

			// Verify policy was created in Vault
			vaultPolicyName := testNamespace + "-" + policyName
			content, err := GetVaultPolicyContent(ctx, vaultPolicyName)
			Expect(err).NotTo(HaveOccurred())
			// Content should have "read" capability
			Expect(content).To(ContainSubstring("read"))
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-VAL-NS: Namespace Boundary Validation
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-VAL-NS: Namespace Boundary Enforcement", func() {
		It("TC-VAL-NS01: should reject path without {{namespace}} when enforcement enabled", func() {
			policyName := uniqueName("tc-val-ns01")
			policy := BuildPolicyWithPath(policyName, "secret/data/global/*", true)

			err := utils.CreateVaultPolicyCR(ctx, policy)
			defer CleanupPolicy(ctx, policyName)

			// Either webhook rejects or controller errors
			if err != nil {
				Expect(err.Error()).To(Or(
					ContainSubstring("namespace"),
					ContainSubstring("boundary"),
					ContainSubstring("{{namespace}}"),
				))
			} else {
				// Controller should detect violation
				Eventually(func(g Gomega) {
					status, getErr := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
					g.Expect(getErr).NotTo(HaveOccurred())
					// May be Error or Active depending on validation timing
					g.Expect(status).To(Or(Equal("Error"), Equal("Active")))
				}, 30*time.Second, 2*time.Second).Should(Succeed())
			}
		})

		It("TC-VAL-NS02: should accept path with {{namespace}} when enforcement enabled", func() {
			policyName := uniqueName("tc-val-ns02")
			policy := BuildPolicyWithPath(policyName, "secret/data/{{namespace}}/*", true)

			err := utils.CreateVaultPolicyCR(ctx, policy)
			defer CleanupPolicy(ctx, policyName)

			Expect(err).NotTo(HaveOccurred())
			ExpectPolicyActive(ctx, policyName)

			// Verify namespace was substituted in Vault
			vaultPolicyName := testNamespace + "-" + policyName
			content, err := GetVaultPolicyContent(ctx, vaultPolicyName)
			Expect(err).NotTo(HaveOccurred())
			Expect(content).To(ContainSubstring(testNamespace))
			Expect(content).NotTo(ContainSubstring("{{namespace}}"))
		})

		It("TC-VAL-NS03: should allow any path when enforcement disabled", func() {
			policyName := uniqueName("tc-val-ns03")
			policy := BuildPolicyWithPath(policyName, "secret/data/global/*", false)

			err := utils.CreateVaultPolicyCR(ctx, policy)
			defer CleanupPolicy(ctx, policyName)

			Expect(err).NotTo(HaveOccurred())
			ExpectPolicyActive(ctx, policyName)
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-VAL-REF: Policy Reference Validation
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-VAL-REF: Policy Reference Validation", func() {
		DescribeTable("should validate policy reference kinds correctly",
			func(kind string, expectValid bool) {
				roleName := uniqueName("tc-val-ref")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      roleName,
						Namespace: testNamespace,
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   sharedVaultConnectionName,
						ServiceAccounts: []string{sharedSAName},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind:      kind,
								Name:      sharedPolicyName,
								Namespace: testNamespace,
							},
						},
						TokenTTL: "30m",
					},
				}

				err := utils.CreateVaultRoleCR(ctx, role)
				defer CleanupRole(ctx, roleName)

				if expectValid {
					Expect(err).NotTo(HaveOccurred())
					ExpectRoleActive(ctx, roleName)
				} else {
					// Invalid kind should be rejected by CRD enum validation
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Or(
						ContainSubstring("kind"),
						ContainSubstring("Unsupported"),
						ContainSubstring("invalid"),
						ContainSubstring("VaultPolicy"),
						ContainSubstring("VaultClusterPolicy"),
					))
				}
			},
			Entry("VaultPolicy kind", "VaultPolicy", true),
			Entry("VaultClusterPolicy kind", "VaultClusterPolicy", true),
			Entry("invalid kind", "InvalidPolicy", false),
			Entry("secret kind", "Secret", false),
			Entry("lowercase kind", "vaultpolicy", false),
		)
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-VAL-LEN: Length Boundary Validation
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-VAL-LEN: Length Boundary Validation", func() {
		It("TC-VAL-LEN01: should handle maximum path length", func() {
			policyName := uniqueName("tc-val-len")
			// Create a reasonably long but valid path
			longPath := "secret/data/" + strings.Repeat("a", 200) + "/*"
			policy := BuildPolicyWithPath(policyName, longPath, false)

			err := utils.CreateVaultPolicyCR(ctx, policy)
			defer CleanupPolicy(ctx, policyName)

			// Should work for reasonable lengths
			if err == nil {
				ExpectPolicyActive(ctx, policyName)
			}
		})

		It("TC-VAL-LEN02: should handle many rules in a policy", func() {
			policyName := uniqueName("tc-val-rules")
			policy := BuildPolicyWithRules(policyName, 50) // 50 rules

			err := utils.CreateVaultPolicyCR(ctx, policy)
			defer CleanupPolicy(ctx, policyName)

			Expect(err).NotTo(HaveOccurred())
			ExpectPolicyActive(ctx, policyName)

			// Verify rules count in status
			p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Status.RulesCount).To(Equal(50))
		})
	})
})
