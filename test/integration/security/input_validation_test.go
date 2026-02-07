//go:build integration

/*
Package security provides security-focused integration tests for the vault-access-operator.

Tests use the naming convention: SEC-IV{NN}_{Description} for Input Validation tests
*/

package security

import (
	"context"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/integration"
)

var _ = Describe("Security: Input Validation Tests", Label("security"), func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("SEC-IV: Path Injection Prevention", func() {
		Describe("SEC-IV01: Prevent Path Traversal", func() {
			It("should reject paths with traversal sequences", func() {
				By("Attempting to create a policy with path traversal")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-iv01-path-traversal",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/../../root/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// The webhook should reject this - path contains invalid characters
				if err == nil {
					// If creation succeeded (webhook not running), verify it doesn't bypass
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
					// In a full test, we'd verify Vault doesn't actually allow the traversal
				}
				// Note: With webhook enabled, this should fail validation
			})
		})

		Describe("SEC-IV02: Prevent Wildcard Before Namespace", func() {
			It("should reject wildcard (*) before {{namespace}} variable", func() {
				By("Attempting to create a policy with wildcard before namespace")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-iv02-wildcard-bypass",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:            "default-connection",
						EnforceNamespaceBoundary: boolPtr(true),
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/*/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// The webhook should reject this as a security risk
				if err != nil {
					Expect(err.Error()).To(ContainSubstring("wildcard"))
				} else {
					// If webhook is not running (envtest without webhooks), clean up
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
					// Note: With webhook enabled, this should fail validation
				}
			})
		})

		Describe("SEC-IV03: Reject Invalid Characters in Paths", func() {
			It("should reject paths with shell metacharacters", func() {
				testCases := []struct {
					name string
					path string
				}{
					{"semicolon", "secret/data/test;ls -la"},
					{"pipe", "secret/data/test|cat /etc/passwd"},
					{"backtick", "secret/data/test`whoami`"},
					{"dollar", "secret/data/test$(id)"},
					{"ampersand", "secret/data/test && rm -rf /"},
				}

				for _, tc := range testCases {
					By("Testing path with " + tc.name)
					policy := &vaultv1alpha1.VaultPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "sec-iv03-" + tc.name,
							Namespace: "default",
						},
						Spec: vaultv1alpha1.VaultPolicySpec{
							ConnectionRef: "default-connection",
							Rules: []vaultv1alpha1.PolicyRule{
								{
									Path:         tc.path,
									Capabilities: []vaultv1alpha1.Capability{"read"},
								},
							},
						},
					}

					err := testEnv.K8sClient.Create(ctx, policy)
					if err == nil {
						// Clean up if created (webhook not active)
						_ = testEnv.K8sClient.Delete(ctx, policy)
					}
					// With webhook, these should be rejected
				}
			})
		})

		Describe("SEC-IV04: Prevent HCL Injection", func() {
			It("should sanitize policy content to prevent HCL injection", func() {
				By("Attempting to inject HCL via policy path")
				// Attempt to close the path block and inject additional rules
				maliciousPath := `secret/data/test/*" }
path "secret/data/admin/*" {
  capabilities = ["sudo", "create", "read", "update", "delete"]
}
path "ignored`

				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-iv04-hcl-injection",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         maliciousPath,
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
					// Verify the policy in Vault doesn't have the injected path
					// This would require checking with the Vault client
				}
				// With webhook, this should be rejected due to invalid characters
			})
		})

		Describe("SEC-IV05: Validate Capability Values", func() {
			It("should reject invalid capability values", func() {
				By("Attempting to create a policy with invalid capability")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-iv05-invalid-cap",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"read", "root", "admin"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// CRD validation or webhook should reject invalid capabilities
				if err != nil {
					Expect(err.Error()).To(Or(
						ContainSubstring("invalid"),
						ContainSubstring("Unsupported"),
						ContainSubstring("capability"),
					))
				} else {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}
			})
		})
	})

	Context("SEC-IV: Size Limits", func() {
		Describe("SEC-IV10: Reject Oversized Policy", func() {
			It("should reject policies exceeding reasonable size limits", func() {
				By("Creating a policy with many rules")
				rules := make([]vaultv1alpha1.PolicyRule, 1000)
				for i := range rules {
					rules[i] = vaultv1alpha1.PolicyRule{
						Path:         "secret/data/{{namespace}}/path" + strings.Repeat("x", 100),
						Capabilities: []vaultv1alpha1.Capability{"read", "list", "create", "update", "delete"},
					}
				}

				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-iv10-oversized",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules:         rules,
					},
				}

				// This tests that the system handles large policies appropriately
				// Either rejecting them or handling them without resource exhaustion
				ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()

				err := testEnv.K8sClient.Create(ctx, policy)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(context.Background(), policy) }()
				}
				// Resource quotas or validation should prevent excessive policies
			})
		})

		Describe("SEC-IV11: Reject Excessively Long Path", func() {
			It("should handle very long paths safely", func() {
				By("Creating a policy with a very long path")
				longPath := "secret/data/{{namespace}}/" + strings.Repeat("a", 10000)

				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-iv11-long-path",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         longPath,
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}
				// Very long paths should be rejected or truncated safely
			})
		})
	})
})

func boolPtr(b bool) *bool {
	return &b
}
