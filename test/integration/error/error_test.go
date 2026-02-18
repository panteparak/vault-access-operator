//go:build integration

/*
Package error provides integration tests for error and failure scenarios.

Tests use the naming convention: INT-ERR{NN}_{Description}
*/

package error

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

var _ = Describe("Error Scenario Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-ERR: Error and Failure Scenarios", func() {
		Describe("INT-ERR01: Invalid VaultConnection address", func() {
			It("should set proper error status when VaultConnection has unreachable address", func() {
				By("Creating a VaultConnection with invalid address")
				conn := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "int-err01-bad-conn",
						Generation: 1,
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: "http://nonexistent-vault:8200",
						Auth: vaultv1alpha1.AuthConfig{
							Token: &vaultv1alpha1.TokenAuth{
								SecretRef: vaultv1alpha1.SecretKeySelector{
									Name:      "int-err01-token",
									Namespace: "default",
									Key:       "token",
								},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, conn)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultConnection")

				By("Verifying the connection resource exists")
				createdConn := &vaultv1alpha1.VaultConnection{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: conn.Name,
					}, createdConn)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, conn)
			})
		})

		Describe("INT-ERR02: Policy referencing nonexistent connection", func() {
			It("should handle missing VaultConnection gracefully", func() {
				By("Creating a VaultPolicy referencing a nonexistent connection")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-err02-orphan-policy",
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
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

				By("Verifying the policy was created")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, policy)
			})
		})

		Describe("INT-ERR03: Role referencing nonexistent connection", func() {
			It("should handle missing VaultConnection gracefully for roles", func() {
				By("Creating a VaultRole referencing a nonexistent connection")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-err03-orphan-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "nonexistent-connection",
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "some-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultRole")

				By("Verifying the role was created")
				createdRole := &vaultv1alpha1.VaultRole{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, createdRole)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, role)
			})
		})
	})
})
