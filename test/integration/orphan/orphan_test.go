//go:build integration

/*
Package orphan provides integration tests for orphan detection.

Tests use the naming convention: INT-ORP{NN}_{Description}
*/

package orphan

import (
	"context"
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/test/integration"
)

var _ = Describe("Orphan Detection Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-ORP: Policy Orphan Detection", func() {
		Describe("INT-ORP01: Detect orphaned policy when K8s resource is deleted", func() {
			It("should detect a policy as orphaned when its K8s resource no longer exists", func() {
				By("Creating a VaultPolicy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-orp01-test-policy",
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

				By("Waiting for the policy to become Active")
				Eventually(func() vaultv1alpha1.Phase {
					createdPolicy := &vaultv1alpha1.VaultPolicy{}
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy); err != nil {
						return ""
					}
					return createdPolicy.Status.Phase
				}, 30*time.Second, time.Second).Should(Equal(vaultv1alpha1.PhaseActive))

				By("Verifying the policy exists in Vault")
				vaultClient := testEnv.VaultClient
				Expect(vaultClient).NotTo(BeNil())

				// The policy should be marked as managed in Vault
				managedPolicies, err := vaultClient.ListManagedPolicies(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(managedPolicies).To(HaveKey("default-int-orp01-test-policy"))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())

				// Wait for policy to be fully deleted
				Eventually(func() bool {
					createdPolicy := &vaultv1alpha1.VaultPolicy{}
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
					return err != nil
				}, 30*time.Second, time.Second).Should(BeTrue())
			})
		})

		Describe("INT-ORP02: No orphan when K8s resource exists", func() {
			It("should not report a policy as orphaned when K8s resource exists", func() {
				By("Creating a VaultPolicy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-orp02-active-policy",
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
				Expect(err).NotTo(HaveOccurred())

				By("Waiting for the policy to become Active")
				Eventually(func() vaultv1alpha1.Phase {
					createdPolicy := &vaultv1alpha1.VaultPolicy{}
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy); err != nil {
						return ""
					}
					return createdPolicy.Status.Phase
				}, 30*time.Second, time.Second).Should(Equal(vaultv1alpha1.PhaseActive))

				By("Verifying managed metadata contains correct K8s resource reference")
				vaultClient := testEnv.VaultClient
				managedPolicies, err := vaultClient.ListManagedPolicies(ctx)
				Expect(err).NotTo(HaveOccurred())

				managedInfo, exists := managedPolicies["default-int-orp02-active-policy"]
				Expect(exists).To(BeTrue())
				Expect(managedInfo.K8sResource).To(Equal("default/int-orp02-active-policy"))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())

				Eventually(func() bool {
					createdPolicy := &vaultv1alpha1.VaultPolicy{}
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
					return err != nil
				}, 30*time.Second, time.Second).Should(BeTrue())
			})
		})
	})

	Context("INT-ORP: Role Orphan Detection", func() {
		Describe("INT-ORP03: Detect orphaned role when K8s resource is deleted", func() {
			It("should detect a role as orphaned when its K8s resource no longer exists", func() {
				// First, ensure we have an active policy for the role to reference
				By("Creating a VaultClusterPolicy for the role")
				clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "int-orp03-cluster-policy",
					},
					Spec: vaultv1alpha1.VaultClusterPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, clusterPolicy)
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() vaultv1alpha1.Phase {
					p := &vaultv1alpha1.VaultClusterPolicy{}
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: clusterPolicy.Name,
					}, p); err != nil {
						return ""
					}
					return p.Status.Phase
				}, 30*time.Second, time.Second).Should(Equal(vaultv1alpha1.PhaseActive))

				By("Creating a VaultRole")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-orp03-test-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultClusterPolicy",
								Name: "int-orp03-cluster-policy",
							},
						},
					},
				}

				err = testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Waiting for the role to become Active")
				Eventually(func() vaultv1alpha1.Phase {
					createdRole := &vaultv1alpha1.VaultRole{}
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, createdRole); err != nil {
						return ""
					}
					return createdRole.Status.Phase
				}, 30*time.Second, time.Second).Should(Equal(vaultv1alpha1.PhaseActive))

				By("Verifying the role is marked as managed in Vault")
				vaultClient := testEnv.VaultClient
				managedRoles, err := vaultClient.ListManagedRoles(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(managedRoles).To(HaveKey("default-int-orp03-test-role"))

				By("Cleaning up role and policy")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
				Eventually(func() bool {
					r := &vaultv1alpha1.VaultRole{}
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, r)
					return err != nil
				}, 30*time.Second, time.Second).Should(BeTrue())

				Expect(testEnv.K8sClient.Delete(ctx, clusterPolicy)).To(Succeed())
				Eventually(func() bool {
					p := &vaultv1alpha1.VaultClusterPolicy{}
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: clusterPolicy.Name,
					}, p)
					return err != nil
				}, 30*time.Second, time.Second).Should(BeTrue())
			})
		})
	})

	Context("INT-ORP: Managed Metadata Storage", func() {
		Describe("INT-ORP04: Verify managed metadata structure", func() {
			It("should store correct metadata for managed resources", func() {
				By("Creating a VaultPolicy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-orp04-metadata-policy",
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

				By("Waiting for the policy to become Active")
				Eventually(func() vaultv1alpha1.Phase {
					createdPolicy := &vaultv1alpha1.VaultPolicy{}
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy); err != nil {
						return ""
					}
					return createdPolicy.Status.Phase
				}, 30*time.Second, time.Second).Should(Equal(vaultv1alpha1.PhaseActive))

				By("Reading managed metadata directly from Vault")
				vaultClient := testEnv.VaultClient
				metadataPath := vault.ManagedPoliciesPath + "/default-int-orp04-metadata-policy"
				secret, err := vaultClient.Logical().ReadWithContext(ctx, metadataPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(secret).NotTo(BeNil())
				Expect(secret.Data).To(HaveKey("data"))

				data := secret.Data["data"].(map[string]interface{})
				Expect(data).To(HaveKey("metadata"))

				var metadata vault.ManagedResource
				err = json.Unmarshal([]byte(data["metadata"].(string)), &metadata)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying metadata fields")
				Expect(metadata.K8sResource).To(Equal("default/int-orp04-metadata-policy"))
				Expect(metadata.ManagedAt).NotTo(BeZero())
				Expect(metadata.LastUpdated).NotTo(BeZero())

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())

				Eventually(func() bool {
					createdPolicy := &vaultv1alpha1.VaultPolicy{}
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
					return err != nil
				}, 30*time.Second, time.Second).Should(BeTrue())
			})
		})

		Describe("INT-ORP05: Cluster-scoped resource metadata", func() {
			It("should store correct metadata for cluster-scoped resources", func() {
				By("Creating a VaultClusterPolicy")
				clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "int-orp05-cluster-metadata",
					},
					Spec: vaultv1alpha1.VaultClusterPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, clusterPolicy)
				Expect(err).NotTo(HaveOccurred())

				By("Waiting for the cluster policy to become Active")
				Eventually(func() vaultv1alpha1.Phase {
					p := &vaultv1alpha1.VaultClusterPolicy{}
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: clusterPolicy.Name,
					}, p); err != nil {
						return ""
					}
					return p.Status.Phase
				}, 30*time.Second, time.Second).Should(Equal(vaultv1alpha1.PhaseActive))

				By("Verifying metadata has cluster-scoped resource reference (no namespace)")
				vaultClient := testEnv.VaultClient
				managedPolicies, err := vaultClient.ListManagedPolicies(ctx)
				Expect(err).NotTo(HaveOccurred())

				managedInfo, exists := managedPolicies["int-orp05-cluster-metadata"]
				Expect(exists).To(BeTrue())
				// Cluster-scoped resources don't have namespace prefix
				Expect(managedInfo.K8sResource).To(Equal("int-orp05-cluster-metadata"))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, clusterPolicy)).To(Succeed())

				Eventually(func() bool {
					p := &vaultv1alpha1.VaultClusterPolicy{}
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: clusterPolicy.Name,
					}, p)
					return err != nil
				}, 30*time.Second, time.Second).Should(BeTrue())
			})
		})
	})
})
