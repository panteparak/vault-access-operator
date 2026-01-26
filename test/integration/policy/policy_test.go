/*
Package policy provides integration tests for VaultPolicy and VaultClusterPolicy resources.

Tests use the naming convention: INT-POL{NN}_{Description}
*/
package policy

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

var _ = Describe("Policy Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-POL: VaultPolicy CRUD Operations", func() {
		Describe("INT-POL01: Create VaultPolicy", func() {
			It("should create a VaultPolicy and sync to Vault", func() {
				By("Creating a VaultPolicy resource")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-pol01-test-policy",
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
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

				By("Verifying the policy exists in Kubernetes")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				Expect(createdPolicy.Spec.Rules).To(HaveLen(1))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})

		Describe("INT-POL02: Update VaultPolicy", func() {
			It("should update a VaultPolicy and sync changes to Vault", func() {
				By("Creating initial VaultPolicy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-pol02-update-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/app1/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred())

				By("Updating the policy with additional capabilities")
				Eventually(func() error {
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, policy); err != nil {
						return err
					}
					policy.Spec.Rules[0].Capabilities = []vaultv1alpha1.Capability{"read", "list", "create"}
					return testEnv.K8sClient.Update(ctx, policy)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Verifying the update")
				updatedPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func(g Gomega) []vaultv1alpha1.Capability {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, updatedPolicy)
					g.Expect(err).NotTo(HaveOccurred())
					if len(updatedPolicy.Spec.Rules) > 0 {
						return updatedPolicy.Spec.Rules[0].Capabilities
					}
					return nil
				}, 10*time.Second, time.Second).Should(HaveLen(3))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})

		Describe("INT-POL03: Delete VaultPolicy", func() {
			It("should delete a VaultPolicy and remove from Vault", func() {
				By("Creating a VaultPolicy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-pol03-delete-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/temp/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred())

				By("Deleting the policy")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())

				By("Verifying the policy is deleted from Kubernetes")
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

		Describe("INT-POL04: Namespace Boundary Enforcement", func() {
			It("should enforce namespace boundary in policy paths", func() {
				By("Creating a VaultPolicy with namespace boundary enabled")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-pol04-boundary-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:            "default-connection",
						EnforceNamespaceBoundary: boolPtr(true),
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"read", "list"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the policy was created with boundary enforcement")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				Expect(createdPolicy.Spec.IsEnforceNamespaceBoundary()).To(BeTrue())

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})

		Describe("INT-POL05: Multiple Rules", func() {
			It("should handle policies with multiple rules", func() {
				By("Creating a VaultPolicy with multiple rules")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-pol05-multi-rules",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/config/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
							{
								Path:         "secret/data/{{namespace}}/credentials/*",
								Capabilities: []vaultv1alpha1.Capability{"read", "list"},
							},
							{
								Path:         "secret/metadata/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"list"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying all rules are present")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func(g Gomega) int {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
					g.Expect(err).NotTo(HaveOccurred())
					return len(createdPolicy.Spec.Rules)
				}, 10*time.Second, time.Second).Should(Equal(3))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})
	})

	Context("INT-POL: VaultClusterPolicy Operations", func() {
		Describe("INT-POL10: Create VaultClusterPolicy", func() {
			It("should create a cluster-scoped policy", func() {
				By("Creating a VaultClusterPolicy resource")
				policy := &vaultv1alpha1.VaultClusterPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "int-pol10-cluster-policy",
					},
					Spec: vaultv1alpha1.VaultClusterPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/shared/*",
								Capabilities: []vaultv1alpha1.Capability{"read", "list"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the cluster policy exists")
				createdPolicy := &vaultv1alpha1.VaultClusterPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: policy.Name,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				Expect(createdPolicy.Spec.Rules).To(HaveLen(1))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})
	})
})

func boolPtr(b bool) *bool {
	return &b
}
