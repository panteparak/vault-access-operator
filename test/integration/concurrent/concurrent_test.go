//go:build integration

/*
Package concurrent provides integration tests for concurrent Vault resource operations.

Tests use the naming convention: INT-CONC{NN}_{Description}
*/

package concurrent

import (
	"context"
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/integration"
)

var _ = Describe("Concurrent Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-CONC: Concurrent Resource Operations", func() {
		Describe("INT-CONC01: Parallel policy creates", func() {
			It("should create 5 policies simultaneously without errors", func() {
				const count = 5
				var wg sync.WaitGroup
				errs := make([]error, count)

				By("Creating 5 policies concurrently")
				for i := 0; i < count; i++ {
					wg.Add(1)
					go func(idx int) {
						defer wg.Done()
						policy := &vaultv1alpha1.VaultPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      fmt.Sprintf("int-conc01-policy-%d", idx),
								Namespace: "default",
							},
							Spec: vaultv1alpha1.VaultPolicySpec{
								ConnectionRef: "default-connection",
								Rules: []vaultv1alpha1.PolicyRule{
									{
										Path:         fmt.Sprintf("secret/data/{{namespace}}/app%d/*", idx),
										Capabilities: []vaultv1alpha1.Capability{"read", "list"},
									},
								},
							},
						}
						errs[idx] = testEnv.K8sClient.Create(ctx, policy)
					}(i)
				}
				wg.Wait()

				By("Verifying all creations succeeded")
				for i, err := range errs {
					Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Policy %d creation failed", i))
				}

				By("Verifying all policies exist")
				for i := 0; i < count; i++ {
					policy := &vaultv1alpha1.VaultPolicy{}
					Eventually(func() error {
						return testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name:      fmt.Sprintf("int-conc01-policy-%d", i),
							Namespace: "default",
						}, policy)
					}, 10*time.Second, time.Second).Should(Succeed())
				}

				By("Cleaning up")
				for i := 0; i < count; i++ {
					policy := &vaultv1alpha1.VaultPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      fmt.Sprintf("int-conc01-policy-%d", i),
							Namespace: "default",
						},
					}
					_ = testEnv.K8sClient.Delete(ctx, policy)
				}
			})
		})

		Describe("INT-CONC02: Parallel role creates", func() {
			It("should create 5 roles simultaneously without errors", func() {
				const count = 5

				By("Creating prerequisite policy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-conc02-shared-policy",
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
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())

				var wg sync.WaitGroup
				errs := make([]error, count)

				By("Creating 5 roles concurrently")
				for i := 0; i < count; i++ {
					wg.Add(1)
					go func(idx int) {
						defer wg.Done()
						role := &vaultv1alpha1.VaultRole{
							ObjectMeta: metav1.ObjectMeta{
								Name:      fmt.Sprintf("int-conc02-role-%d", idx),
								Namespace: "default",
							},
							Spec: vaultv1alpha1.VaultRoleSpec{
								ConnectionRef:   "default-connection",
								ServiceAccounts: []string{"default"},
								Policies: []vaultv1alpha1.PolicyReference{
									{
										Kind: "VaultPolicy",
										Name: "int-conc02-shared-policy",
									},
								},
							},
						}
						errs[idx] = testEnv.K8sClient.Create(ctx, role)
					}(i)
				}
				wg.Wait()

				By("Verifying all creations succeeded")
				for i, err := range errs {
					Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Role %d creation failed", i))
				}

				By("Verifying all roles exist")
				for i := 0; i < count; i++ {
					role := &vaultv1alpha1.VaultRole{}
					Eventually(func() error {
						return testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name:      fmt.Sprintf("int-conc02-role-%d", i),
							Namespace: "default",
						}, role)
					}, 10*time.Second, time.Second).Should(Succeed())
				}

				By("Cleaning up")
				for i := 0; i < count; i++ {
					role := &vaultv1alpha1.VaultRole{
						ObjectMeta: metav1.ObjectMeta{
							Name:      fmt.Sprintf("int-conc02-role-%d", i),
							Namespace: "default",
						},
					}
					_ = testEnv.K8sClient.Delete(ctx, role)
				}
				_ = testEnv.K8sClient.Delete(ctx, policy)
			})
		})

		Describe("INT-CONC03: Policy update during role sync", func() {
			It("should handle concurrent policy update and role creation without race conditions", func() {
				By("Creating initial policy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-conc03-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/{{namespace}}/app/*",
								Capabilities: []vaultv1alpha1.Capability{"read"},
							},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())

				By("Concurrently updating policy and creating a role that references it")
				var wg sync.WaitGroup
				var updateErr, createErr error

				wg.Add(2)
				go func() {
					defer wg.Done()
					// Update the policy
					Eventually(func() error {
						latestPolicy := &vaultv1alpha1.VaultPolicy{}
						if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
							Name:      "int-conc03-policy",
							Namespace: "default",
						}, latestPolicy); err != nil {
							return err
						}
						latestPolicy.Spec.Rules[0].Capabilities = []vaultv1alpha1.Capability{"read", "list"}
						return testEnv.K8sClient.Update(ctx, latestPolicy)
					}, 10*time.Second, 500*time.Millisecond).Should(Succeed())
					updateErr = nil
				}()

				go func() {
					defer wg.Done()
					role := &vaultv1alpha1.VaultRole{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "int-conc03-role",
							Namespace: "default",
						},
						Spec: vaultv1alpha1.VaultRoleSpec{
							ConnectionRef:   "default-connection",
							ServiceAccounts: []string{"default"},
							Policies: []vaultv1alpha1.PolicyReference{
								{
									Kind: "VaultPolicy",
									Name: "int-conc03-policy",
								},
							},
						},
					}
					createErr = testEnv.K8sClient.Create(ctx, role)
				}()

				wg.Wait()

				By("Verifying no errors occurred")
				Expect(updateErr).NotTo(HaveOccurred(), "Policy update should succeed")
				Expect(createErr).NotTo(HaveOccurred(), "Role creation should succeed")

				By("Verifying both resources exist")
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: "int-conc03-policy", Namespace: "default",
					}, &vaultv1alpha1.VaultPolicy{})
				}, 10*time.Second, time.Second).Should(Succeed())

				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name: "int-conc03-role", Namespace: "default",
					}, &vaultv1alpha1.VaultRole{})
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{Name: "int-conc03-role", Namespace: "default"},
				})
				_ = testEnv.K8sClient.Delete(ctx, policy)
			})
		})
	})
})
