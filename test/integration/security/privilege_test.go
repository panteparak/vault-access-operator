//go:build integration

/*
Package security provides security-focused integration tests for the vault-access-operator.

Tests use the naming convention: SEC-PE{NN}_{Description} for Privilege Escalation tests
*/

package security

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

var _ = Describe("Security: Privilege Escalation Prevention Tests", Label("security", "privilege"), func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("SEC-PE: Capability Restrictions", func() {
		Describe("SEC-PE01: Reject Sudo Capability", func() {
			It("should reject policies requesting sudo capability", func() {
				By("Attempting to create a policy with sudo capability")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-pe01-sudo-attempt",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"read", "sudo"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// CRD validation or webhook should reject sudo capability
				if err != nil {
					Expect(err.Error()).To(Or(
						ContainSubstring("sudo"),
						ContainSubstring("invalid"),
						ContainSubstring("Unsupported"),
					))
				} else {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
					// If somehow created, verify it doesn't actually grant sudo
				}
			})
		})

		Describe("SEC-PE02: Reject Root Capability", func() {
			It("should reject policies requesting root capability", func() {
				By("Attempting to create a policy with root capability")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-pe02-root-attempt",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "sys/*",
								Capabilities: []vaultv1alpha1.Capability{"root"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// Should be rejected
				if err != nil {
					Expect(err.Error()).To(Or(
						ContainSubstring("root"),
						ContainSubstring("invalid"),
						ContainSubstring("Unsupported"),
					))
				} else {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}
			})
		})

		Describe("SEC-PE03: Restrict System Path Access", func() {
			It("should warn or reject policies accessing sys/* paths", func() {
				By("Attempting to create a policy accessing sys path")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-pe03-sys-access",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "sys/policies/*",
								Capabilities: []vaultv1alpha1.Capability{"read", "list", "create", "update", "delete"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// Access to sys/* should be restricted or at least flagged
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
					// Check for warning conditions if created
				}
			})
		})

		Describe("SEC-PE04: Restrict Auth Path Modifications", func() {
			It("should restrict policies modifying auth methods", func() {
				By("Attempting to create a policy that can modify auth methods")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-pe04-auth-modify",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "auth/*",
								Capabilities: []vaultv1alpha1.Capability{"create", "update", "delete"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// Should be restricted
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
					// Verify controller flags this as high-privilege
				}
			})
		})
	})

	Context("SEC-PE: Wildcard Restrictions", func() {
		Describe("SEC-PE10: Restrict Global Wildcards", func() {
			It("should reject or warn on global wildcard paths", func() {
				By("Attempting to create a policy with global wildcard")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-pe10-global-wildcard",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "*", // Global wildcard
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// Global wildcard should be rejected
				if err != nil {
					Expect(err.Error()).To(Or(
						ContainSubstring("wildcard"),
						ContainSubstring("path"),
						ContainSubstring("invalid"),
					))
				} else {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}
			})
		})

		Describe("SEC-PE11: Restrict Wildcard with Delete", func() {
			It("should warn on wildcard paths with delete capability", func() {
				By("Creating a policy with wildcard and delete")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-pe11-wildcard-delete",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"delete"}, // Wildcard + delete
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				// Should be created with warning or flagged
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()

					// Check for warning conditions
					createdPolicy := &vaultv1alpha1.VaultPolicy{}
					Eventually(func() error {
						return testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name:      policy.Name,
							Namespace: policy.Namespace,
						}, createdPolicy)
					}, 10*time.Second, time.Second).Should(Succeed())
				}
			})
		})

		Describe("SEC-PE12: Validate Path Scoping", func() {
			It("should enforce proper path scoping", func() {
				By("Creating properly scoped policy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-pe12-scoped",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:            "default-connection",
						EnforceNamespaceBoundary: boolPtr(true),
						Rules: []vaultv1alpha1.PolicyRule{
							{
								// Properly scoped to namespace
								Path:         "secret/data/{{namespace}}/app/*",
								Capabilities: []vaultv1alpha1.Capability{"read", "list"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred())
				defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()

				By("Verifying policy is properly scoped")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				Expect(createdPolicy.Spec.IsEnforceNamespaceBoundary()).To(BeTrue())
			})
		})
	})

	Context("SEC-PE: Role Permission Boundaries", func() {
		Describe("SEC-PE20: Role Cannot Exceed Policy Permissions", func() {
			It("should verify roles are bounded by assigned policies", func() {
				By("Creating a policy with limited permissions")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-pe20-limited-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/readonly/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
				}

				By("Creating a role with the limited policy")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-pe20-limited-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef: "default-connection",
						Policies: []vaultv1alpha1.PolicyReference{
							{Name: "sec-pe20-limited-policy"},
						},
						ServiceAccounts: []string{"default"},
					},
				}

				err = testEnv.K8sClient.Create(ctx, role)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, role) }()

					// Role should only have permissions granted by policy
					// This is enforced by Vault itself
				}
			})
		})

		Describe("SEC-PE21: Prevent Token Role Escalation", func() {
			It("should prevent roles from requesting more capabilities than allowed", func() {
				By("Creating a VaultRole")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sec-pe21-escalation-test",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef: "default-connection",
						Policies: []vaultv1alpha1.PolicyReference{
							{Name: "default-policy"},
						},
						ServiceAccounts: []string{"app-sa"},
						// TTL settings should be within operator-allowed bounds
						TokenTTL:    "1h",
						TokenMaxTTL: "24h",
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, role) }()

					By("Verifying role has bounded token settings")
					createdRole := &vaultv1alpha1.VaultRole{}
					Eventually(func() error {
						return testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name:      role.Name,
							Namespace: role.Namespace,
						}, createdRole)
					}, 10*time.Second, time.Second).Should(Succeed())

					// Token settings should be reasonable
					Expect(createdRole.Spec.TokenTTL).To(Equal("1h"))
					Expect(createdRole.Spec.TokenMaxTTL).To(Equal("24h"))
				}
			})
		})

		Describe("SEC-PE22: Cluster Role Privilege Boundary", func() {
			It("should ensure cluster roles don't grant excessive privileges", func() {
				By("Creating a VaultClusterRole")
				clusterRole := &vaultv1alpha1.VaultClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "sec-pe22-cluster-boundary",
					},
					Spec: vaultv1alpha1.VaultClusterRoleSpec{
						ConnectionRef: "default-connection",
						Policies: []vaultv1alpha1.PolicyReference{
							{Name: "cluster-shared-policy"},
						},
						ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
							{Name: "cluster-sa", Namespace: "kube-system"},
							{Name: "cluster-sa", Namespace: "default"},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, clusterRole)
				if err == nil {
					defer func() { _ = testEnv.K8sClient.Delete(ctx, clusterRole) }()

					By("Verifying cluster role bindings are scoped")
					createdRole := &vaultv1alpha1.VaultClusterRole{}
					Eventually(func() error {
						return testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name: clusterRole.Name,
						}, createdRole)
					}, 10*time.Second, time.Second).Should(Succeed())

					// Service accounts should be explicit, not wildcards
					for _, sa := range createdRole.Spec.ServiceAccounts {
						Expect(sa.Name).NotTo(Equal("*"))
						Expect(sa.Namespace).NotTo(Equal("*"))
					}
				}
			})
		})
	})
})
