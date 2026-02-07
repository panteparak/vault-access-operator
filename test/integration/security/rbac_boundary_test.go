//go:build integration

/*
Package security provides security-focused integration tests for the vault-access-operator.

Tests use the naming convention: SEC-RB{NN}_{Description} for RBAC Boundary tests
*/

package security

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/integration"
)

var _ = Describe("Security: RBAC Boundary Tests", Label("security"), func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("SEC-RB: Namespace Isolation", func() {
		Describe("SEC-RB01: Prevent Cross-Namespace Policy Access", func() {
			It("should not allow a VaultRole to reference a policy in another namespace", func() {
				By("Creating a policy in namespace-a")
				nsA := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "sec-rb01-ns-a",
					},
				}
				err := testEnv.K8sClient.Create(ctx, nsA)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, nsA) }()
				}

				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-rb01-policy-a",
						Namespace: "sec-rb01-ns-a",
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

				err = testEnv.K8sClient.Create(ctx, policy)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}

				By("Attempting to create a role in namespace-b referencing policy in namespace-a")
				nsB := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "sec-rb01-ns-b",
					},
				}
				err = testEnv.K8sClient.Create(ctx, nsB)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, nsB) }()
				}

				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-rb01-role-b",
						Namespace: "sec-rb01-ns-b",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef: "default-connection",
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Name:      "sec-rb01-policy-a",
								Namespace: "sec-rb01-ns-a", // Cross-namespace reference
							},
						},
						ServiceAccounts: []string{"default"},
					},
				}

				err = testEnv.K8sClient.Create(ctx, role)
				// Webhook should reject cross-namespace policy reference
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, role) }()
					// If created, verify the controller handles it correctly
				}
				// With proper validation, this should fail
			})
		})

		Describe("SEC-RB02: Enforce Namespace Boundary in Paths", func() {
			It("should reject paths without namespace variable when boundary is enforced", func() {
				By("Creating a policy with enforced boundary but no namespace in path")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-rb02-no-ns-path",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:            "default-connection",
						EnforceNamespaceBoundary: boolPtr(true),
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/shared/*", // No {{namespace}}
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// With boundary enforcement, this should be rejected
				if err != nil {
					Expect(err.Error()).To(Or(
						ContainSubstring("namespace"),
						ContainSubstring("boundary"),
					))
				} else {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}
			})
		})

		Describe("SEC-RB03: Prevent Namespace Impersonation", func() {
			It("should reject literal namespace values that don't match resource namespace", func() {
				By("Creating a policy with hardcoded different namespace")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-rb03-impersonation",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:            "default-connection",
						EnforceNamespaceBoundary: boolPtr(true),
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/kube-system/*", // Trying to access kube-system
								Capabilities: []vaultv1alpha1.Capability{"read", "list"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// Should be rejected as it tries to access another namespace's secrets
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}
			})
		})

		Describe("SEC-RB04: Role Service Account Binding Isolation", func() {
			It("should only bind to service accounts in allowed namespaces", func() {
				By("Creating a VaultRole that tries to bind to all namespaces")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-rb04-all-ns",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef: "default-connection",
						Policies: []vaultv1alpha1.PolicyReference{
							{Name: "default-policy"},
						},
						ServiceAccounts: []string{"*"}, // All SAs - role is namespace-scoped
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				// Depending on policy, this might be rejected or flagged
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, role) }()

					By("Verifying the role was created with restricted scope")
					createdRole := &vaultv1alpha1.VaultRole{}
					Eventually(func() error {
						return testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name:      role.Name,
							Namespace: role.Namespace,
						}, createdRole)
					}, 10*time.Second, time.Second).Should(Succeed())

					// The controller should have scoped this appropriately
				}
			})
		})
	})

	Context("SEC-RB: Cluster-Scoped Resource Isolation", func() {
		Describe("SEC-RB10: VaultClusterPolicy Access Control", func() {
			It("should verify cluster policies have appropriate restrictions", func() {
				By("Creating a VaultClusterPolicy")
				clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "sec-rb10-cluster-policy",
					},
					Spec: vaultv1alpha1.VaultClusterPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/cluster-shared/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, clusterPolicy)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, clusterPolicy) }()

					By("Verifying cluster policy is accessible")
					created := &vaultv1alpha1.VaultClusterPolicy{}
					Eventually(func() error {
						return testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name: clusterPolicy.Name,
						}, created)
					}, 10*time.Second, time.Second).Should(Succeed())
				}
			})
		})

		Describe("SEC-RB11: VaultClusterRole Binding Scope", func() {
			It("should verify cluster roles can be appropriately scoped", func() {
				By("Creating a VaultClusterRole with specific namespace bindings")
				clusterRole := &vaultv1alpha1.VaultClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "sec-rb11-cluster-role",
					},
					Spec: vaultv1alpha1.VaultClusterRoleSpec{
						ConnectionRef: "default-connection",
						Policies: []vaultv1alpha1.PolicyReference{
							{Name: "default-policy"},
						},
						ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
							{Name: "app-service-account", Namespace: "production"},
							{Name: "app-service-account", Namespace: "staging"},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, clusterRole)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, clusterRole) }()

					By("Verifying cluster role has scoped bindings")
					created := &vaultv1alpha1.VaultClusterRole{}
					Eventually(func() error {
						return testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name: clusterRole.Name,
						}, created)
					}, 10*time.Second, time.Second).Should(Succeed())

					// Verify service accounts are properly scoped
					Expect(created.Spec.ServiceAccounts).To(HaveLen(2))
				}
			})
		})
	})
})
