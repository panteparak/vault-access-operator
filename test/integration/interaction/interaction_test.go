//go:build integration

/*
Package interaction provides integration tests for multi-resource interactions.

Tests use the naming convention: INT-INT{NN}_{Description}
*/

package interaction

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

var _ = Describe("Multi-Resource Interaction Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-INT: Cross-Resource Interactions", func() {
		Describe("INT-INT01: Delete policy while role references it", func() {
			It("should handle policy deletion when referenced by a role", func() {
				By("Creating a policy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-int01-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/app/*",
								Capabilities: []vaultv1alpha1.Capability{"read", "list"},
							},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())

				By("Creating a role that references the policy")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-int01-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "int-int01-policy",
							},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, role)).To(Succeed())

				By("Verifying both resources exist")
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: "int-int01-policy", Namespace: "default",
					}, &vaultv1alpha1.VaultPolicy{})
				}, 10*time.Second, time.Second).Should(Succeed())

				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: "int-int01-role", Namespace: "default",
					}, &vaultv1alpha1.VaultRole{})
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Deleting the policy while role still references it")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())

				By("Verifying policy is deleted")
				Eventually(func() bool {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: "int-int01-policy", Namespace: "default",
					}, &vaultv1alpha1.VaultPolicy{})
					return err != nil
				}, 10*time.Second, time.Second).Should(BeTrue())

				By("Verifying role still exists")
				existingRole := &vaultv1alpha1.VaultRole{}
				Expect(testEnv.K8sClient.Get(ctx, types.NamespacedName{
					Name: "int-int01-role", Namespace: "default",
				}, existingRole)).To(Succeed())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{Name: "int-int01-role", Namespace: "default"},
				})
			})
		})

		Describe("INT-INT02: Delete connection while resources exist", func() {
			It("should handle connection deletion when policies and roles reference it", func() {
				By("Creating a VaultConnection")
				conn := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "int-int02-conn",
						Generation: 1,
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: testEnv.VaultAddress(),
						Auth: vaultv1alpha1.AuthConfig{
							Token: &vaultv1alpha1.TokenAuth{
								SecretRef: vaultv1alpha1.SecretKeySelector{
									Name:      "int-int02-token",
									Namespace: "default",
									Key:       "token",
								},
							},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, conn)).To(Succeed())

				By("Creating a policy referencing the connection")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-int02-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "int-int02-conn",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())

				By("Deleting the connection")
				Expect(testEnv.K8sClient.Delete(ctx, conn)).To(Succeed())

				By("Verifying connection is deleted")
				Eventually(func() bool {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: "int-int02-conn",
					}, &vaultv1alpha1.VaultConnection{})
					return err != nil
				}, 10*time.Second, time.Second).Should(BeTrue())

				By("Verifying policy still exists (orphaned)")
				existingPolicy := &vaultv1alpha1.VaultPolicy{}
				Expect(testEnv.K8sClient.Get(ctx, types.NamespacedName{
					Name: "int-int02-policy", Namespace: "default",
				}, existingPolicy)).To(Succeed())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, policy)
			})
		})

		Describe("INT-INT03: Recreate deleted connection", func() {
			It("should allow resources to resume syncing after connection is recreated", func() {
				By("Creating a VaultConnection")
				connName := "int-int03-conn"
				conn := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:       connName,
						Generation: 1,
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: testEnv.VaultAddress(),
						Auth: vaultv1alpha1.AuthConfig{
							Token: &vaultv1alpha1.TokenAuth{
								SecretRef: vaultv1alpha1.SecretKeySelector{
									Name:      "int-int03-token",
									Namespace: "default",
									Key:       "token",
								},
							},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, conn)).To(Succeed())

				By("Creating a policy using the connection")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-int03-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: connName,
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())

				By("Deleting the connection")
				Expect(testEnv.K8sClient.Delete(ctx, conn)).To(Succeed())

				By("Waiting for connection to be deleted")
				Eventually(func() bool {
					err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: connName,
					}, &vaultv1alpha1.VaultConnection{})
					return err != nil
				}, 10*time.Second, time.Second).Should(BeTrue())

				By("Recreating the connection with same name")
				newConn := &vaultv1alpha1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:       connName,
						Generation: 1,
					},
					Spec: vaultv1alpha1.VaultConnectionSpec{
						Address: testEnv.VaultAddress(),
						Auth: vaultv1alpha1.AuthConfig{
							Token: &vaultv1alpha1.TokenAuth{
								SecretRef: vaultv1alpha1.SecretKeySelector{
									Name:      "int-int03-token",
									Namespace: "default",
									Key:       "token",
								},
							},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, newConn)).To(Succeed())

				By("Verifying the new connection exists")
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: connName,
					}, &vaultv1alpha1.VaultConnection{})
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, policy)
				_ = testEnv.K8sClient.Delete(ctx, newConn)
			})
		})
	})
})
