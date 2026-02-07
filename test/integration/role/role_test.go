//go:build integration

/*
Package role provides integration tests for VaultRole and VaultClusterRole resources.

Tests use the naming convention: INT-ROL{NN}_{Description}
*/

package role

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

var _ = Describe("Role Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-ROL: VaultRole CRUD Operations", func() {
		Describe("INT-ROL01: Create VaultRole", func() {
			It("should create a VaultRole and sync to Vault", func() {
				By("Creating a VaultRole resource")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-rol01-test-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "test-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultRole")

				By("Verifying the role exists in Kubernetes")
				createdRole := &vaultv1alpha1.VaultRole{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, createdRole)
				}, 10*time.Second, time.Second).Should(Succeed())

				Expect(createdRole.Spec.ServiceAccounts).To(HaveLen(1))
				Expect(createdRole.Spec.Policies).To(HaveLen(1))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})

		Describe("INT-ROL02: Update VaultRole", func() {
			It("should update a VaultRole and sync changes to Vault", func() {
				By("Creating initial VaultRole")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-rol02-update-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "test-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Updating the role with additional service account")
				Eventually(func() error {
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, role); err != nil {
						return err
					}
					role.Spec.ServiceAccounts = []string{"default", "another-sa"}
					return testEnv.K8sClient.Update(ctx, role)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Verifying the update")
				updatedRole := &vaultv1alpha1.VaultRole{}
				Eventually(func(g Gomega) int {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, updatedRole)
					g.Expect(err).NotTo(HaveOccurred())
					return len(updatedRole.Spec.ServiceAccounts)
				}, 10*time.Second, time.Second).Should(Equal(2))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})

		Describe("INT-ROL03: Delete VaultRole", func() {
			It("should delete a VaultRole and remove from Vault", func() {
				By("Creating a VaultRole")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-rol03-delete-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "test-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Deleting the role")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())

				By("Verifying the role is deleted from Kubernetes")
				deletedRole := &vaultv1alpha1.VaultRole{}
				Eventually(func() bool {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, deletedRole)
					return err != nil // Should return error (not found)
				}, 10*time.Second, time.Second).Should(BeTrue())
			})
		})

		Describe("INT-ROL04: Token TTL Configuration", func() {
			It("should configure token TTL settings", func() {
				By("Creating a VaultRole with TTL configuration")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-rol04-ttl-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "test-policy",
							},
						},
						TokenTTL:    "1h",
						TokenMaxTTL: "24h",
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the TTL configuration")
				createdRole := &vaultv1alpha1.VaultRole{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, createdRole)
				}, 10*time.Second, time.Second).Should(Succeed())

				Expect(createdRole.Spec.TokenTTL).To(Equal("1h"))
				Expect(createdRole.Spec.TokenMaxTTL).To(Equal("24h"))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})

		Describe("INT-ROL05: Multiple Policies", func() {
			It("should handle roles with multiple policy references", func() {
				By("Creating a VaultRole with multiple policies")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-rol05-multi-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "policy-one",
							},
							{
								Kind: "VaultPolicy",
								Name: "policy-two",
							},
							{
								Kind: "VaultClusterPolicy",
								Name: "cluster-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying all policies are referenced")
				createdRole := &vaultv1alpha1.VaultRole{}
				Eventually(func(g Gomega) int {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, createdRole)
					g.Expect(err).NotTo(HaveOccurred())
					return len(createdRole.Spec.Policies)
				}, 10*time.Second, time.Second).Should(Equal(3))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})

		Describe("INT-ROL06: Multiple Service Accounts", func() {
			It("should handle roles with multiple service accounts", func() {
				By("Creating a VaultRole with multiple service accounts")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-rol06-multi-sa",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default", "app-sa", "worker-sa"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "test-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying all service accounts are configured")
				createdRole := &vaultv1alpha1.VaultRole{}
				Eventually(func(g Gomega) int {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, createdRole)
					g.Expect(err).NotTo(HaveOccurred())
					return len(createdRole.Spec.ServiceAccounts)
				}, 10*time.Second, time.Second).Should(Equal(3))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})

		Describe("INT-ROL07: Deletion Policy Retain", func() {
			It("should respect deletionPolicy Retain", func() {
				By("Creating a VaultRole with Retain deletion policy")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-rol07-retain",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
						DeletionPolicy:  vaultv1alpha1.DeletionPolicyRetain,
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "test-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the deletion policy is set")
				createdRole := &vaultv1alpha1.VaultRole{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, createdRole)
				}, 10*time.Second, time.Second).Should(Succeed())

				Expect(createdRole.Spec.DeletionPolicy).To(Equal(vaultv1alpha1.DeletionPolicyRetain))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})
	})

	Context("INT-ROL: VaultClusterRole Operations", func() {
		Describe("INT-ROL10: Create VaultClusterRole", func() {
			It("should create a cluster-scoped role", func() {
				By("Creating a VaultClusterRole resource")
				role := &vaultv1alpha1.VaultClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "int-rol10-cluster-role",
					},
					Spec: vaultv1alpha1.VaultClusterRoleSpec{
						ConnectionRef: "default-connection",
						ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
							{
								Name:      "default",
								Namespace: "default",
							},
						},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultClusterPolicy",
								Name: "cluster-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the cluster role exists")
				createdRole := &vaultv1alpha1.VaultClusterRole{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: role.Name,
					}, createdRole)
				}, 10*time.Second, time.Second).Should(Succeed())

				Expect(createdRole.Spec.ServiceAccounts).To(HaveLen(1))
				Expect(createdRole.Spec.Policies).To(HaveLen(1))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})

		Describe("INT-ROL11: VaultClusterRole Multi-Namespace Service Accounts", func() {
			It("should support service accounts from multiple namespaces", func() {
				By("Creating a VaultClusterRole with multi-namespace service accounts")
				role := &vaultv1alpha1.VaultClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "int-rol11-multi-ns-role",
					},
					Spec: vaultv1alpha1.VaultClusterRoleSpec{
						ConnectionRef: "default-connection",
						ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
							{
								Name:      "app-sa",
								Namespace: "namespace-a",
							},
							{
								Name:      "app-sa",
								Namespace: "namespace-b",
							},
							{
								Name:      "worker-sa",
								Namespace: "namespace-c",
							},
						},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultClusterPolicy",
								Name: "shared-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying all service accounts from different namespaces are configured")
				createdRole := &vaultv1alpha1.VaultClusterRole{}
				Eventually(func(g Gomega) int {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: role.Name,
					}, createdRole)
					g.Expect(err).NotTo(HaveOccurred())
					return len(createdRole.Spec.ServiceAccounts)
				}, 10*time.Second, time.Second).Should(Equal(3))

				// Verify namespaces are preserved
				namespaces := make(map[string]bool)
				for _, sa := range createdRole.Spec.ServiceAccounts {
					namespaces[sa.Namespace] = true
				}
				Expect(namespaces).To(HaveLen(3))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})

		Describe("INT-ROL12: VaultClusterRole Update", func() {
			It("should update a VaultClusterRole", func() {
				By("Creating initial VaultClusterRole")
				role := &vaultv1alpha1.VaultClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "int-rol12-update-cluster",
					},
					Spec: vaultv1alpha1.VaultClusterRoleSpec{
						ConnectionRef: "default-connection",
						ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
							{
								Name:      "default",
								Namespace: "default",
							},
						},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultClusterPolicy",
								Name: "test-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Updating the cluster role with TTL settings")
				Eventually(func() error {
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: role.Name,
					}, role); err != nil {
						return err
					}
					role.Spec.TokenTTL = "2h"
					role.Spec.TokenMaxTTL = "48h"
					return testEnv.K8sClient.Update(ctx, role)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Verifying the update")
				updatedRole := &vaultv1alpha1.VaultClusterRole{}
				Eventually(func(g Gomega) string {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: role.Name,
					}, updatedRole)
					g.Expect(err).NotTo(HaveOccurred())
					return updatedRole.Spec.TokenTTL
				}, 10*time.Second, time.Second).Should(Equal("2h"))

				Expect(updatedRole.Spec.TokenMaxTTL).To(Equal("48h"))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})

		Describe("INT-ROL13: VaultClusterRole Delete", func() {
			It("should delete a VaultClusterRole", func() {
				By("Creating a VaultClusterRole")
				role := &vaultv1alpha1.VaultClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "int-rol13-delete-cluster",
					},
					Spec: vaultv1alpha1.VaultClusterRoleSpec{
						ConnectionRef: "default-connection",
						ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
							{
								Name:      "default",
								Namespace: "default",
							},
						},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultClusterPolicy",
								Name: "test-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Deleting the cluster role")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())

				By("Verifying the cluster role is deleted")
				deletedRole := &vaultv1alpha1.VaultClusterRole{}
				Eventually(func() bool {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: role.Name,
					}, deletedRole)
					return err != nil // Should return error (not found)
				}, 10*time.Second, time.Second).Should(BeTrue())
			})
		})
	})
})
