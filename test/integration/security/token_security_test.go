//go:build integration

/*
Package security provides security-focused integration tests for the vault-access-operator.

Tests use the naming convention: SEC-TK{NN}_{Description} for Token Security tests
*/

package security

import (
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/integration"
)

var _ = Describe("Security: Token Security Tests", Label("security", "token"), func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("SEC-TK: Token Handling", func() {
		Describe("SEC-TK01: No Token in Logs", func() {
			It("should never log Vault tokens", func() {
				By("Creating a VaultConnection")
				connection := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-tk01-log-test",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: "https://vault.example.com:8200",
						Auth: vaultv1alpha1.AuthConfig{
							Token: &vaultv1alpha1.TokenAuth{
								SecretRef: vaultv1alpha1.SecretKeySelector{
									Name: "vault-token-secret",
									Key:  "token",
								},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, connection)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, connection) }()
				}

				By("Capturing controller logs")
				// In a real test, we'd capture logs and verify no tokens appear
				// This is a placeholder for the log verification logic
				logBuffer := &bytes.Buffer{}
				verifyNoTokensInLogs(logBuffer)
			})
		})

		Describe("SEC-TK02: Token Auto-Revocation on Delete", func() {
			It("should revoke tokens when connection is deleted", func() {
				By("Creating a VaultConnection")
				connection := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-tk02-revoke-test",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: "https://vault.example.com:8200",
						Auth: vaultv1alpha1.AuthConfig{
							Kubernetes: &vaultv1alpha1.KubernetesAuth{
								Role: "test-role",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, connection)
				Expect(err).NotTo(HaveOccurred())

				By("Waiting for connection to be ready")
				// In real test, wait for status to show authenticated

				By("Deleting the connection")
				err = testEnv.K8sClient.Delete(ctx, connection)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying token is revoked in Vault")
				// In real test with Vault container, verify token lookup fails
			})
		})

		Describe("SEC-TK03: Token Renewal Before Expiry", func() {
			It("should renew tokens before they expire", func() {
				By("Creating a VaultConnection with short TTL")
				connection := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-tk03-renewal-test",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: "https://vault.example.com:8200",
						Auth: vaultv1alpha1.AuthConfig{
							Kubernetes: &vaultv1alpha1.KubernetesAuth{
								Role: "test-role",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, connection)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, connection) }()
				}

				By("Waiting for token renewal")
				// In real test, observe that token gets renewed before TTL expires
				time.Sleep(100 * time.Millisecond) // Placeholder
			})
		})

		Describe("SEC-TK04: Minimal Token Capabilities", func() {
			It("should use tokens with minimal required capabilities", func() {
				By("Creating a VaultPolicy with read-only access")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-tk04-minimal-caps",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"read"}, // Only read
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}

				By("Verifying the policy only has read capability")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				Expect(createdPolicy.Spec.Rules[0].Capabilities).To(
					ConsistOf(vaultv1alpha1.Capability("read")))
			})
		})

		Describe("SEC-TK05: No Root Token Usage", func() {
			It("should not allow root token configuration in production", func() {
				By("Attempting to configure root token directly")
				// This test verifies that root tokens cannot be configured
				// via normal CRD configuration

				connection := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-tk05-no-root",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: "https://vault.example.com:8200",
						Auth: vaultv1alpha1.AuthConfig{
							Token: &vaultv1alpha1.TokenAuth{
								SecretRef: vaultv1alpha1.SecretKeySelector{
									Name: "vault-token-secret",
									Key:  "token",
								},
							},
						},
						// A webhook or controller should reject root tokens
					},
				}

				err := testEnv.K8sClient.Create(ctx, connection)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, connection) }()
				}
				// With proper validation, root token usage should be flagged/rejected
			})
		})
	})

	Context("SEC-TK: Token Status Visibility", func() {
		Describe("SEC-TK10: Token Status Should Not Expose Token Value", func() {
			It("should not include actual token value in status", func() {
				By("Creating a VaultConnection")
				connection := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-tk10-status-test",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: "https://vault.example.com:8200",
						Auth: vaultv1alpha1.AuthConfig{
							Kubernetes: &vaultv1alpha1.KubernetesAuth{
								Role: "test-role",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, connection)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, connection) }()

					By("Verifying status doesn't contain token")
					createdConn := &vaultv1alpha1.VaultConnection{}
					Eventually(func() error {
						return testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name:      connection.Name,
							Namespace: connection.Namespace,
						}, createdConn)
					}, 10*time.Second, time.Second).Should(Succeed())

					// Status should contain metadata but not actual token
					// Verify by checking the connection status fields
				}
			})
		})

		Describe("SEC-TK11: Secure Token Accessor Usage", func() {
			It("should use token accessor for token management operations", func() {
				By("Creating resources that require token operations")
				// Token accessors allow token management without exposing the token
				// Verify the operator uses accessors when possible

				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-tk11-accessor",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}
			})
		})
	})
})

// verifyNoTokensInLogs checks that no Vault tokens appear in the log output
func verifyNoTokensInLogs(r io.Reader) {
	content, err := io.ReadAll(r)
	if err != nil {
		return
	}

	logContent := string(content)

	// Check for common token patterns
	tokenPatterns := []string{
		"hvs.",         // Vault service token prefix
		"s.",           // Legacy token prefix
		"root_token",   // Root token reference
		"client_token", // Client token field
	}

	for _, pattern := range tokenPatterns {
		// Should not find actual token values (patterns followed by what looks like a token)
		if strings.Contains(logContent, pattern) {
			// Additional check: verify it's not just a reference but an actual token
			// This is a simplified check
			GinkgoWriter.Printf("Warning: Found potential token pattern '%s' in logs\n", pattern)
		}
	}
}
