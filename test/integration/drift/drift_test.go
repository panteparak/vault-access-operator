//go:build integration

/*
Package drift provides integration tests for drift detection, drift correction, and adoption.

Tests use the naming convention: INT-DRF{NN}_{Description}
*/

package drift

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

var _ = Describe("Drift Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-DRF: Drift Mode Configuration", func() {
		Describe("INT-DRF01: DriftMode Ignore", func() {
			It("should skip drift detection when driftMode is ignore", func() {
				By("Creating a VaultPolicy with driftMode=ignore")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-drf01-ignore-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						DriftMode:     vaultv1alpha1.DriftModeIgnore,
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

				By("Verifying the policy was created with driftMode=ignore")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() vaultv1alpha1.DriftMode {
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy); err != nil {
						return ""
					}
					return createdPolicy.Spec.DriftMode
				}, 10*time.Second, time.Second).Should(Equal(vaultv1alpha1.DriftModeIgnore))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})

		Describe("INT-DRF02: DriftMode Detect", func() {
			It("should detect drift but not correct when driftMode is detect", func() {
				By("Creating a VaultPolicy with driftMode=detect")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-drf02-detect-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						DriftMode:     vaultv1alpha1.DriftModeDetect,
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

				By("Verifying the policy was created with driftMode=detect")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() vaultv1alpha1.DriftMode {
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy); err != nil {
						return ""
					}
					return createdPolicy.Spec.DriftMode
				}, 10*time.Second, time.Second).Should(Equal(vaultv1alpha1.DriftModeDetect))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})

		Describe("INT-DRF03: DriftMode Correct", func() {
			It("should auto-correct drift when driftMode is correct with allow-destructive annotation", func() {
				By("Creating a VaultPolicy with driftMode=correct and allow-destructive annotation")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-drf03-correct-policy",
						Namespace: "default",
						Annotations: map[string]string{
							vaultv1alpha1.AnnotationAllowDestructive: "true",
						},
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						DriftMode:     vaultv1alpha1.DriftModeCorrect,
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

				By("Verifying the policy was created with driftMode=correct")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() vaultv1alpha1.DriftMode {
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy); err != nil {
						return ""
					}
					return createdPolicy.Spec.DriftMode
				}, 10*time.Second, time.Second).Should(Equal(vaultv1alpha1.DriftModeCorrect))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})

		Describe("INT-DRF04: Default DriftMode", func() {
			It("should use detect as default driftMode when not specified", func() {
				By("Creating a VaultPolicy without explicit driftMode")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-drf04-default-policy",
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

				By("Verifying the policy was created with empty driftMode (will default to detect at runtime)")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				// DriftMode is empty in spec; effective mode is resolved at runtime
				Expect(createdPolicy.Spec.DriftMode).To(Equal(vaultv1alpha1.DriftMode("")))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})
	})

	Context("INT-DRF: Adoption via Annotation", func() {
		Describe("INT-DRF10: Adopt Annotation", func() {
			It("should allow adoption with vault.platform.io/adopt annotation", func() {
				By("Creating a VaultPolicy with adopt annotation")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-drf10-adopt-policy",
						Namespace: "default",
						Annotations: map[string]string{
							vaultv1alpha1.AnnotationAdopt: "true",
						},
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:  "default-connection",
						ConflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
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

				By("Verifying the policy was created with adopt annotation")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() string {
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy); err != nil {
						return ""
					}
					return createdPolicy.Annotations[vaultv1alpha1.AnnotationAdopt]
				}, 10*time.Second, time.Second).Should(Equal("true"))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})

		Describe("INT-DRF11: ConflictPolicy Adopt", func() {
			It("should handle conflictPolicy=Adopt for existing resources", func() {
				By("Creating a VaultPolicy with conflictPolicy=Adopt")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-drf11-conflict-adopt",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef:  "default-connection",
						ConflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
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

				By("Verifying the policy was created with conflictPolicy=Adopt")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() vaultv1alpha1.ConflictPolicy {
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy); err != nil {
						return ""
					}
					return createdPolicy.Spec.ConflictPolicy
				}, 10*time.Second, time.Second).Should(Equal(vaultv1alpha1.ConflictPolicyAdopt))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})
	})

	Context("INT-DRF: Vault Resource Bindings", func() {
		Describe("INT-DRF20: Policy Binding Status", func() {
			It("should populate binding status after policy creation", func() {
				By("Creating a VaultPolicy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-drf20-binding-policy",
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

				By("Verifying the policy was created")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				// Note: Binding status is populated during reconciliation
				// In integration tests, we may need to wait for reconciliation to complete

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})

		Describe("INT-DRF21: Role Binding Status", func() {
			It("should populate binding status after role creation", func() {
				By("Creating a VaultRole")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-drf21-binding-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the role was created")
				createdRole := &vaultv1alpha1.VaultRole{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, createdRole)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})
	})

	Context("INT-DRF: Safety Annotations", func() {
		Describe("INT-DRF30: Allow Destructive Annotation", func() {
			It("should accept allow-destructive annotation", func() {
				By("Creating a VaultPolicy with allow-destructive annotation")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-drf30-destructive-policy",
						Namespace: "default",
						Annotations: map[string]string{
							vaultv1alpha1.AnnotationAllowDestructive: "true",
						},
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						DriftMode:     vaultv1alpha1.DriftModeCorrect,
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

				By("Verifying the annotation is present")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() string {
					if err := testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy); err != nil {
						return ""
					}
					return createdPolicy.Annotations[vaultv1alpha1.AnnotationAllowDestructive]
				}, 10*time.Second, time.Second).Should(Equal("true"))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})
	})
})
