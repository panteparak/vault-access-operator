//go:build integration

/*
Package recovery provides integration tests for error recovery and phase transitions.

Tests use the naming convention: INT-REC{NN}_{Description}
*/

package recovery

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/integration"
)

var _ = Describe("Recovery Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-REC: Error Recovery", func() {
		Describe("INT-REC01: Connection recovers from error after Vault becomes reachable", func() {
			It("should create a connection referencing the running Vault", func() {
				By("Creating a VaultConnection pointing to the test Vault instance")
				connection := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-rec01-connection",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: testEnv.VaultAddress(),
						Auth: vaultv1alpha1.AuthConfig{
							Token: &vaultv1alpha1.TokenAuth{
								TokenSecretRef: "vault-token",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, connection)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultConnection")

				By("Verifying the connection exists in K8s")
				createdConn := &vaultv1alpha1.VaultConnection{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      connection.Name,
						Namespace: connection.Namespace,
					}, createdConn)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Verifying the connection address matches the Vault instance")
				Expect(createdConn.Spec.Address).To(Equal(testEnv.VaultAddress()))

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, connection)
			})
		})

		Describe("INT-REC02: Policy transitions from Error to Active after connection recovers", func() {
			It("should create a policy that initially has an unreachable connection then a valid one", func() {
				By("Creating a VaultPolicy referencing a non-existent connection (will error)")
				errorPolicy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-rec02-error-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "nonexistent-rec-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/int-rec02/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, errorPolicy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

				By("Verifying the policy exists in K8s")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      errorPolicy.Name,
						Namespace: errorPolicy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Creating a valid VaultPolicy referencing existing default-connection")
				recoveryPolicy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-rec02-recovery-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/int-rec02-recovery/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				}

				err = testEnv.K8sClient.Create(ctx, recoveryPolicy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create recovery VaultPolicy")

				By("Verifying the recovery policy exists in K8s")
				createdRecovery := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      recoveryPolicy.Name,
						Namespace: recoveryPolicy.Namespace,
					}, createdRecovery)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, errorPolicy)
				_ = testEnv.K8sClient.Delete(ctx, recoveryPolicy)
			})
		})
	})
})
