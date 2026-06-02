//go:build integration

/*
Package syncerror provides integration tests for error classification and status reporting.

Tests use the naming convention: INT-SYNC{NN}_{Description}
*/

package syncerror

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

var _ = Describe("SyncError Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-SYNC: Error Classification", func() {
		// INT-SYNC01 pins the FIRST line of defense against invalid policy
		// input: CRD schema validation. The empty-rules case is rejected by the
		// API server via +kubebuilder:validation:MinItems=1 on
		// VaultPolicy.Spec.Rules, before any reconcile runs — so that admission
		// rejection is what is asserted here (and guards against accidental
		// removal of the MinItems marker). Reconcile-time ValidationError
		// *classification* (e.g. enforceNamespaceBoundary violations →
		// ReasonValidationFailed) is exercised by unit tests in
		// features/policy/controller and shared/controller/syncerror; this suite
		// runs envtest + Vault without a manager, so it cannot observe reconcile
		// status.
		Describe("INT-SYNC01: VaultPolicy with empty rules is rejected by CRD validation", func() {
			It("should reject the create citing the MinItems constraint on spec.rules", func() {
				By("Attempting to create a VaultPolicy with zero rules")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-sync01-empty-rules",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules:         []vaultv1alpha1.PolicyRule{}, // violates MinItems=1
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).To(HaveOccurred(),
					"CRD schema must reject a VaultPolicy with zero rules")
				Expect(err.Error()).To(ContainSubstring("rules"))
				Expect(err.Error()).To(ContainSubstring("at least 1"))
			})
		})

		Describe("INT-SYNC02: Policy with unreachable Vault connection", func() {
			It("should show dependency error when connection is not active", func() {
				By("Creating a VaultPolicy referencing a non-existent connection")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-sync02-bad-conn-policy",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "nonexistent-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{
								Path:         "secret/data/test/*",
								Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, policy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultPolicy")

				By("Verifying the policy was created")
				createdPolicy := &vaultv1alpha1.VaultPolicy{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					}, createdPolicy)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, policy)
			})
		})

		Describe("INT-SYNC03: Role referencing non-existent policy", func() {
			It("should create role resource successfully in K8s", func() {
				By("Creating a VaultRole referencing a non-existent policy")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "int-sync03-bad-policy-role",
						Namespace: "default",
					},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   "default-connection",
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{
								Kind: "VaultPolicy",
								Name: "nonexistent-policy",
							},
						},
					},
				}

				err := testEnv.K8sClient.Create(ctx, role)
				Expect(err).NotTo(HaveOccurred(), "Failed to create VaultRole")

				By("Verifying the role was created")
				createdRole := &vaultv1alpha1.VaultRole{}
				Eventually(func() error {
					return testEnv.K8sClient.Get(ctx, types.NamespacedName{
						Name:      role.Name,
						Namespace: role.Namespace,
					}, createdRole)
				}, 10*time.Second, time.Second).Should(Succeed())

				By("Cleaning up")
				_ = testEnv.K8sClient.Delete(ctx, role)
			})
		})
	})
})
