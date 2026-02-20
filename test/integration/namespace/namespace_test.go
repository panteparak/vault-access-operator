//go:build integration

/*
Package namespace provides integration tests for namespace boundary enforcement and variable substitution.

Tests use the naming convention: INT-NS{NN}_{Description}
*/

package namespace

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

func boolPtr(b bool) *bool {
	return &b
}

var _ = Describe("Namespace Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-NS: Namespace Boundary Enforcement", func() {
		Describe("INT-NS01: VaultPolicy with enforceNamespaceBoundary blocks wildcard-before-namespace paths", func() {
			It("should create the policy resource with namespace boundary enforcement enabled", func() {
				By("Creating a VaultPolicy with enforceNamespaceBoundary=true and a wildcard-before-namespace path")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-ns01-wildcard-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:            "default-connection",
						EnforceNamespaceBoundary: boolPtr(true),
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

				By("Verifying the policy exists in K8s")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Verifying enforceNamespaceBoundary is set")
				Expect(createdPolicy.Spec.IsEnforceNamespaceBoundary()).To(BeTrue())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, policy)
			})
		})

		Describe("INT-NS02: VaultClusterRole referencing VaultPolicy without namespace", func() {
			It("should create a cluster role with a policy reference missing namespace", func() {
				By("Creating a VaultClusterRole referencing a VaultPolicy without explicit namespace")
				clusterRole := &vaultv1alpha1.VaultClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "int-ns02-cluster-role",
					},
					Spec: vaultv1alpha1.VaultClusterRoleSpec{
						ConnectionRef: "default-connection",
						ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
							{Name: "default", Namespace: "default"},
						},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "some-namespaced-policy",
								// Namespace intentionally omitted — cluster-scoped role
								// must provide explicit namespace for VaultPolicy references
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, clusterRole)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultClusterRole")

				By("Verifying the cluster role exists in K8s")
				createdRole := &vaultv1alpha1.VaultClusterRole{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: clusterRole.Name,
					}, createdRole)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Verifying the policy reference has no namespace set")
				Expect(createdRole.Spec.Policies[0].Namespace).To(BeEmpty())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, clusterRole)
			})
		})

		Describe("INT-NS03: VaultPolicy namespace substitution produces correct path", func() {
			It("should create a policy with {{namespace}} variable in path", func() {
				By("Creating a VaultPolicy with {{namespace}} in the path")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-ns03-namespace-sub",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:            "default-connection",
						EnforceNamespaceBoundary: boolPtr(true),
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead, vaultv1alpha1.CapabilityList},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

				By("Verifying the policy exists in K8s with correct spec")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Verifying the rule path contains namespace variable")
				Expect(createdPolicy.Spec.Rules[0].Path).To(ContainSubstring("{{namespace}}"))

				By("Verifying namespace boundary enforcement is enabled")
				Expect(createdPolicy.Spec.IsEnforceNamespaceBoundary()).To(BeTrue())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, policy)
			})
		})
	})
})
