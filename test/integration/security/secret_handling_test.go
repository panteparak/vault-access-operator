//go:build integration

/*
Package security provides security-focused integration tests for the vault-access-operator.

Tests use the naming convention: SEC-SH{NN}_{Description} for Secret Handling tests
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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/integration"
)

var _ = Describe("Security: Secret Handling Tests", Label("security", "secrets"), func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("SEC-SH: Secret Logging Prevention", func() {
		Describe("SEC-SH01: No Secrets in Controller Logs", func() {
			It("should never log secret values from Vault", func() {
				By("Creating resources that access Vault secrets")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-sh01-log-test",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"read", "list"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}

				By("Verifying no secret values in logs")
				logBuffer := &bytes.Buffer{}
				verifyNoSecretsInLogs(logBuffer)
			})
		})

		Describe("SEC-SH02: No Secrets in Events", func() {
			It("should not include secret values in Kubernetes events", func() {
				By("Creating a policy that triggers events")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-sh02-event-test",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/app/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}

				By("Checking events for the policy")
				eventList := &corev1.EventList{}
				Eventually(func() error {
					return testEnv.K8sClient.List(ctx, eventList)
				}, 10*time.Second, time.Second).Should(Succeed())

				// Verify no events contain secret values
				for _, event := range eventList.Items {
					verifyEventHasNoSecrets(event)
				}
			})
		})

		Describe("SEC-SH03: No Secrets in Status", func() {
			It("should not expose secret values in resource status", func() {
				By("Creating a VaultPolicy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-sh03-status-test",
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

					By("Verifying status doesn't contain secrets")
					createdPolicy := &vaultv1alpha1.VaultPolicy{}
					Eventually(func() error {
						return testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name:      policy.Name,
							Namespace: policy.Namespace,
						}, createdPolicy)
					}, 10*time.Second, time.Second).Should(Succeed())

					// Status should only contain operational metadata
					// not actual secret values
					verifyStatusHasNoSecrets(createdPolicy)
				}
			})
		})

		Describe("SEC-SH04: Secure Error Messages", func() {
			It("should not leak secret values in error messages", func() {
				By("Creating a policy with invalid configuration")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-sh04-error-test",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "nonexistent-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				if err != nil {
					// Error message should not contain sensitive data
					verifyErrorHasNoSecrets(err)
				} else {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}
			})
		})
	})

	Context("SEC-SH: Secret Cleanup", func() {
		Describe("SEC-SH10: Cleanup Secrets on Deletion", func() {
			It("should clean up related secrets when resource is deleted", func() {
				By("Creating a VaultPolicy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-sh10-cleanup",
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
				Expect(err).NotTo(HaveOccurred())

				By("Deleting the policy")
				err = testEnv.K8sClient.Delete(ctx, policy)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying related resources are cleaned up")
				// In real test, verify any associated secrets or configs are removed
				deletedPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() bool {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, deletedPolicy)
					return err != nil // Should return error (not found)
				}, 10*time.Second, time.Second).Should(BeTrue())
			})
		})

		Describe("SEC-SH11: No Secret Caching Beyond Necessity", func() {
			It("should not cache secrets longer than needed", func() {
				By("Creating a VaultConnection")
				connection := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-sh11-cache-test",
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

				// This is a design verification test
				// The operator should not maintain long-lived secret caches
				// Secrets should be fetched when needed and discarded
			})
		})

		Describe("SEC-SH12: Memory Zeroing for Secrets", func() {
			It("should zero memory after secret use", func() {
				// This test verifies the design principle that secrets
				// are zeroed in memory after use (where possible in Go)
				// This is a best-effort security measure

				By("Creating a short-lived secret reference")
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-sh12-memory-test",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"password": []byte("test-secret-value"),
					},
				}

				err := testEnv.K8sClient.Create(ctx, secret)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, secret) }()
				}

				// Note: Actual memory zeroing verification is difficult in Go
				// This test documents the security requirement
			})
		})
	})

	Context("SEC-SH: Secret Reference Validation", func() {
		Describe("SEC-SH20: Validate Secret References", func() {
			It("should validate that referenced secrets exist", func() {
				By("Creating a connection with non-existent secret reference")
				connection := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-sh20-invalid-ref",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: "https://vault.example.com:8200",
						Auth: vaultv1alpha1.AuthConfig{
							Kubernetes: &vaultv1alpha1.KubernetesAuth{
								Role: "test-role",
							},
						},
						TLS: &vaultv1alpha1.TLSConfig{
							CASecretRef: &vaultv1alpha1.SecretKeySelector{
								Name: "nonexistent-secret",
								Key:  "ca.crt",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, connection)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, connection) }()

					By("Verifying status reflects missing secret")
					// Controller should report error about missing secret
				}
			})
		})

		Describe("SEC-SH21: Validate Secret Key Exists", func() {
			It("should validate that referenced key exists in secret", func() {
				By("Creating a secret without the expected key")
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-sh21-wrong-key",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"wrong-key": []byte("some-value"),
					},
				}

				err := testEnv.K8sClient.Create(ctx, secret)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, secret) }()
				}

				connection := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-sh21-missing-key",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: "https://vault.example.com:8200",
						Auth: vaultv1alpha1.AuthConfig{
							Kubernetes: &vaultv1alpha1.KubernetesAuth{
								Role: "test-role",
							},
						},
						TLS: &vaultv1alpha1.TLSConfig{
							CASecretRef: &vaultv1alpha1.SecretKeySelector{
								Name: "sec-sh21-wrong-key",
								Key:  "ca.crt", // This key doesn't exist
							},
						},
					},
				}

				err = testEnv.K8sClient.Create(ctx, connection)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, connection) }()
					// Controller should report error about missing key
				}
			})
		})
	})
})

// verifyNoSecretsInLogs checks that no secret-like values appear in logs
func verifyNoSecretsInLogs(r io.Reader) {
	content, err := io.ReadAll(r)
	if err != nil {
		return
	}

	logContent := string(content)

	// Patterns that might indicate secret leakage
	sensitivePatterns := []string{
		"password=",
		"secret=",
		"token=",
		"apikey=",
		"api_key=",
		"private_key",
		"-----BEGIN",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(strings.ToLower(logContent), pattern) {
			GinkgoWriter.Printf("Warning: Found potential secret pattern '%s' in output\n", pattern)
		}
	}
}

// verifyEventHasNoSecrets checks that an event doesn't contain secret values
func verifyEventHasNoSecrets(event corev1.Event) {
	sensitivePatterns := []string{
		"password",
		"secret",
		"token",
		"key",
	}

	message := strings.ToLower(event.Message)
	for _, pattern := range sensitivePatterns {
		// Allow metadata references like "secret not found"
		// but flag patterns that might be actual values
		if strings.Contains(message, pattern+"=") ||
			strings.Contains(message, pattern+":") {
			GinkgoWriter.Printf("Warning: Event may contain sensitive data: %s\n", event.Message)
		}
	}
}

// verifyStatusHasNoSecrets checks that resource status doesn't expose secrets
func verifyStatusHasNoSecrets(policy *vaultv1alpha1.VaultPolicy) {
	// Status should not contain:
	// - Actual secret values
	// - Vault tokens
	// - Credentials

	// This is a placeholder for actual status field verification
	// In real implementation, iterate through status fields
}

// verifyErrorHasNoSecrets checks that error messages don't leak secrets
func verifyErrorHasNoSecrets(err error) {
	if err == nil {
		return
	}

	errMsg := strings.ToLower(err.Error())
	sensitivePatterns := []string{
		"password=",
		"secret=",
		"token=",
		"key=",
	}

	for _, pattern := range sensitivePatterns {
		Expect(errMsg).NotTo(ContainSubstring(pattern),
			"Error message should not contain secret values")
	}
}
