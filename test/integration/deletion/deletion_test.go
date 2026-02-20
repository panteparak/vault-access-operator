//go:build integration

/*
Package deletion provides integration tests for resource deletion and cleanup behavior.

Tests use the naming convention: INT-DEL{NN}_{Description}
*/

package deletion

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

var _ = Describe("Deletion Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-DEL: Deletion Policy Behavior", func() {
		Describe("INT-DEL01: Delete VaultPolicy with DeletionPolicy=Delete", func() {
			It("should create and then delete the policy from K8s", func() {
				By("Creating a VaultPolicy with DeletionPolicy=Delete")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-del01-delete-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:  "default-connection",
						DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/int-del01/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

				By("Verifying the policy exists in K8s")
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, &vaultv1alpha1.VaultPolicy{})
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Deleting the VaultPolicy from K8s")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())

				By("Verifying the policy is removed from K8s")
				Eventually(func() bool {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, &vaultv1alpha1.VaultPolicy{})
					return err != nil // Should be NotFound
				}, 15*time.Second, time.Second).Should(BeTrue())
			})
		})

		Describe("INT-DEL02: Delete VaultPolicy with DeletionPolicy=Retain", func() {
			It("should remove K8s resource while keeping Vault policy", func() {
				By("Creating a VaultPolicy with DeletionPolicy=Retain")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-del02-retain-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:  "default-connection",
						DeletionPolicy: vaultv1alpha1.DeletionPolicyRetain,
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/int-del02/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

				By("Verifying the policy exists in K8s")
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, &vaultv1alpha1.VaultPolicy{})
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Deleting the VaultPolicy from K8s")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())

				By("Verifying the K8s resource is removed")
				Eventually(func() bool {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, &vaultv1alpha1.VaultPolicy{})
					return err != nil
				}, 15*time.Second, time.Second).Should(BeTrue())
			})
		})

		Describe("INT-DEL03: Delete VaultPolicy when Vault unreachable", func() {
			It("should still remove the K8s resource (finalizer not stuck)", func() {
				By("Creating a VaultPolicy referencing a non-existent connection")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-del03-unreachable-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:  "unreachable-connection",
						DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/int-del03/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

				By("Verifying the policy exists in K8s")
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, &vaultv1alpha1.VaultPolicy{})
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Deleting the VaultPolicy")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())

				By("Verifying the K8s resource is eventually removed (finalizer not stuck)")
				Eventually(func() bool {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, &vaultv1alpha1.VaultPolicy{})
					return err != nil
				}, 30*time.Second, time.Second).Should(BeTrue())
			})
		})
	})
})
