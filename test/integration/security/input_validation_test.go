//go:build integration

/*
Package security provides security-focused integration tests for the vault-access-operator.

Tests use the naming convention: SEC-IV{NN}_{Description} for Input Validation tests

IMPROVEMENTS §38: this suite runs envtest (a real kube-apiserver) + Vault, but
WITHOUT the operator manager or the admission webhook. So the only validations it
can observe are those enforced by the CRD's structural OpenAPI schema (Pattern,
Enum, MinItems, MaxLength, ...). Blocks split accordingly:

  - SEC-IV03/04/05 assert UNCONDITIONALLY — the bad input violates the CRD schema
    (the spec.rules[].path Pattern or the capabilities Enum), so the apiserver
    rejects the create regardless of webhook state. These give real signal.
  - SEC-IV01/02/10/11 are Skipped with a documented reason: the rejection they
    describe is either enforced by the admission webhook / reconcile handler
    (not deployed in this suite) or not enforced at any layer today. Skipping
    avoids the previous "passes regardless of outcome" anti-pattern while making
    the gap explicit. Where the check exists, it is covered by internal/webhook
    unit tests.
*/

package security

import (
	"context"

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
				// The CRD path Pattern (^[a-zA-Z0-9/_*.{}+-]+$) permits '.', so
				// "secret/data/../../root/*" passes schema validation. Vault treats
				// policy paths literally (they are not filesystem paths), so '..' is
				// not a traversal vector and no layer rejects it. Nothing to assert
				// here without inventing a check that doesn't (and need not) exist.
				Skip("path '..' is permitted by the CRD pattern and is not a traversal " +
					"vector for Vault policy paths; no rejection is enforced or required")
			})
		})

		Describe("SEC-IV02: Prevent Wildcard Before Namespace", func() {
			It("should reject wildcard (*) before {{namespace}} variable", func() {
				// Enforced by the admission webhook (validateNoWildcardBeforeNamespace
				// in internal/webhook/vaultpolicy_webhook.go) and by the reconcile
				// handler (validateNamespaceBoundary). Neither runs in this envtest
				// suite. Covered by internal/webhook unit tests.
				Skip("wildcard-before-namespace is an admission-webhook / reconcile check; " +
					"the webhook is not deployed in this envtest suite")
			})
		})

		Describe("SEC-IV03: Reject Invalid Characters in Paths", func() {
			It("should reject paths with shell metacharacters via the CRD path pattern", func() {
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
					Expect(err).To(HaveOccurred(),
						"CRD path pattern must reject metacharacter path (%s)", tc.name)
					Expect(err.Error()).To(ContainSubstring("should match"),
						"rejection should cite the spec.rules[].path Pattern constraint")
				}
			})
		})

		Describe("SEC-IV04: Prevent HCL Injection", func() {
			It("should reject HCL-injection payloads via the CRD path pattern", func() {
				By("Attempting to inject HCL via policy path")
				// Closes the path block and tries to inject additional rules. The
				// payload contains '"', spaces, '[', ']', '=' and newlines — none of
				// which are in the CRD path Pattern, so the apiserver rejects it
				// before any HCL is ever generated.
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
				Expect(err).To(HaveOccurred(),
					"CRD path pattern must reject an HCL-injection payload")
				Expect(err.Error()).To(ContainSubstring("should match"),
					"rejection should cite the spec.rules[].path Pattern constraint")
			})
		})

		Describe("SEC-IV05: Validate Capability Values", func() {
			It("should reject invalid capability values via the CRD enum", func() {
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
				Expect(err).To(HaveOccurred(),
					"CRD capability enum must reject 'root'/'admin'")
				Expect(err.Error()).To(ContainSubstring("Unsupported value"),
					"rejection should cite the capabilities Enum constraint")
			})
		})
	})

	Context("SEC-IV: Size Limits", func() {
		Describe("SEC-IV10: Reject Oversized Policy", func() {
			It("should reject policies exceeding reasonable size limits", func() {
				// No MaxItems is declared on VaultPolicySpec.Rules, and no webhook
				// rule-count cap exists, so a policy with thousands of rules is
				// accepted at every layer today. Asserting acceptance would document
				// a DoS gap as if intended, so this is skipped pending a decision to
				// add a cap (tracked separately).
				Skip("no rule-count cap is enforced on spec.rules at the CRD or webhook layer today")
			})
		})

		Describe("SEC-IV11: Reject Excessively Long Path", func() {
			It("should handle very long paths safely", func() {
				// Only PolicyRule.Description carries a MaxLength (256); PolicyRule.Path
				// has a Pattern but no length bound, so an arbitrarily long path of
				// valid characters is accepted. Same gap as SEC-IV10.
				Skip("no MaxLength is enforced on spec.rules[].path at the CRD layer today")
			})
		})
	})
})

func boolPtr(b bool) *bool {
	return &b
}
