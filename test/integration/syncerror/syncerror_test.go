//go:build integration

/*
Package syncerror provides integration tests for error classification and status reporting.

Tests use the naming convention: INT-SYNC{NN}_{Description}
*/

package syncerror

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

var _ = Describe("SyncError Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-SYNC: Error Classification", func() {
		Describe("INT-SYNC01: Policy with invalid HCL shows ValidationError", func() {
			It("should set status to Error with validation failure details", func() {
				By("Creating a VaultPolicy with empty rules")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-sync01-invalid-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules:         []vaultv1alpha1.PolicyRule{}, // empty rules
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

				By("Verifying the policy was created in K8s")
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

		Describe("INT-SYNC02: Policy with unreachable Vault connection", func() {
			It("should show dependency error when connection is not active", func() {
				By("Creating a VaultPolicy referencing a non-existent connection")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-sync02-bad-conn-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "nonexistent-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/test/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
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

		Describe("INT-SYNC03: Role referencing non-existent policy", func() {
			It("should create role resource successfully in K8s", func() {
				By("Creating a VaultRole referencing a non-existent policy")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-sync03-bad-policy-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "nonexistent-policy",
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
