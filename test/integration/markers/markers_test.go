//go:build integration

/*
Package markers provides integration tests for in-band ownership tracking
(ADR 0008).

Tests use the naming convention: INT-MM{NN}_{Description}.
*/

package markers

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/markers"
	"github.com/panteparak/vault-access-operator/test/integration"
)

// eventuallyPhase polls a namespaced object's phase until it matches want.
func eventuallyPhase(
	ctx context.Context, env *integration.TestEnvironment, key types.NamespacedName, want vaultv1alpha1.Phase,
) {
	Eventually(func() vaultv1alpha1.Phase {
		p := &vaultv1alpha1.VaultPolicy{}
		if err := env.K8sClient.Get(ctx, key, p); err != nil {
			return ""
		}
		return p.Status.Phase
	}, 30*time.Second, time.Second).Should(Equal(want))
}

// newTestPolicy returns a minimal VaultPolicy CR for these specs.
func newTestPolicy(name string) *vaultv1alpha1.VaultPolicy {
	return &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: "default-connection",
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/data/{{namespace}}/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}
}

var _ = Describe("In-band Ownership Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-MM: Flag-on in-band ownership", func() {
		Describe("INT-MM01: Ownership header travels inside the policy document", func() {
			It("stamps the header on write and creates NO marker subtree", func() {
				By("Creating a VaultPolicy")
				policy := newTestPolicy("int-mm01-policy")
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())

				By("Waiting for the policy to become Active")
				eventuallyPhase(ctx, testEnv,
					types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, vaultv1alpha1.PhaseActive)

				By("Verifying the written policy carries the in-band ownership header")
				vc := testEnv.VaultClient
				own, err := vc.GetPolicyOwnership(ctx, "default-int-mm01-policy")
				Expect(err).NotTo(HaveOccurred())
				Expect(own).NotTo(BeNil())
				Expect(own.ManagedBy).To(Equal(vault.KVManagedByValue))
				Expect(own.K8sResource).To(Equal("default/int-mm01-policy"))
				Expect(own.K8sKind).To(Equal("VaultPolicy"))

				By("Verifying the dedicated marker subtree is never created (ADR 0008)")
				list, err := vc.Logical().ListWithContext(ctx, "secret/metadata/vault-access-operator")
				Expect(err).NotTo(HaveOccurred())
				Expect(list).To(BeNil(), "secret/metadata/vault-access-operator/ must not exist")

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())

				By("Verifying the ownership record dies with the policy")
				Eventually(func() (string, error) {
					return vc.ReadPolicy(ctx, "default-int-mm01-policy")
				}, 30*time.Second, time.Second).Should(BeEmpty())
			})
		})

		Describe("INT-MM02: Foreign-operator policy cannot be adopted", func() {
			It("conflicts even with the adopt annotation when the header names another operator", func() {
				By("Pre-writing a policy owned by another operator instance (different auth-mount identity)")
				vc := testEnv.VaultClient
				foreign := vault.OwnershipHeader(vault.Ownership{
					ManagedBy:   vault.KVManagedByValue,
					AuthMount:   "k8s-other-cluster",
					K8sResource: "default/int-mm02-policy", // same CR coords — the collision case
					K8sKind:     "VaultPolicy",
				}) + "\npath \"secret/*\" { capabilities = [\"read\"] }"
				Expect(vc.WritePolicy(ctx, "default-int-mm02-policy", foreign)).To(Succeed())

				By("Creating the CR with the adopt annotation → adoption must be blocked")
				policy := newTestPolicy("int-mm02-policy")
				policy.Annotations = map[string]string{
					vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue,
				}
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				key := types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}
				eventuallyPhase(ctx, testEnv, key, vaultv1alpha1.PhaseConflict)

				By("Verifying the foreign policy was not overwritten")
				hcl, err := vc.ReadPolicy(ctx, "default-int-mm02-policy")
				Expect(err).NotTo(HaveOccurred())
				own, ok := vault.ParseOwnership(hcl)
				Expect(ok).To(BeTrue())
				Expect(own.AuthMount).To(Equal("k8s-other-cluster"))

				By("Cleaning up (CR first, then the foreign policy)")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
				Eventually(func() error {
					p := &vaultv1alpha1.VaultPolicy{}
					return testEnv.K8sClient.Get(ctx, key, p)
				}, 30*time.Second, time.Second).ShouldNot(Succeed())

				By("Verifying cleanup refused to delete the foreign-owned policy")
				hcl, err = vc.ReadPolicy(ctx, "default-int-mm02-policy")
				Expect(err).NotTo(HaveOccurred())
				Expect(hcl).NotTo(BeEmpty(), "foreign policy must survive our CR's deletion")
				Expect(vc.DeletePolicy(ctx, "default-int-mm02-policy")).To(Succeed())
			})
		})

		Describe("INT-MM05: Unmanaged-policy conflict and adoption", func() {
			It("fails on an unmanaged existing policy, then adopts with the adopt annotation", func() {
				By("Pre-writing an unmanaged policy (no ownership header)")
				vc := testEnv.VaultClient
				Expect(vc.WritePolicy(ctx, "default-int-mm05-policy",
					`path "secret/*" { capabilities = ["read"] }`)).To(Succeed())

				By("Creating a VaultPolicy that would collide → expect Conflict")
				policy := newTestPolicy("int-mm05-policy")
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				key := types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}
				eventuallyPhase(ctx, testEnv, key, vaultv1alpha1.PhaseConflict)

				By("Adding the adopt annotation → the operator adopts and reaches Active")
				Eventually(func() error {
					fetched := &vaultv1alpha1.VaultPolicy{}
					if err := testEnv.K8sClient.Get(ctx, key, fetched); err != nil {
						return err
					}
					if fetched.Annotations == nil {
						fetched.Annotations = map[string]string{}
					}
					fetched.Annotations[vaultv1alpha1.AnnotationAdopt] = vaultv1alpha1.AnnotationValueTrue
					return testEnv.K8sClient.Update(ctx, fetched)
				}, 10*time.Second, time.Second).Should(Succeed())

				eventuallyPhase(ctx, testEnv, key, vaultv1alpha1.PhaseActive)

				By("Verifying adoption rewrote the policy with our ownership header")
				own, err := vc.GetPolicyOwnership(ctx, "default-int-mm05-policy")
				Expect(err).NotTo(HaveOccurred())
				Expect(own).NotTo(BeNil())
				Expect(own.K8sResource).To(Equal("default/int-mm05-policy"))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})
	})

	Context("INT-MM: Flag-off behavior", func() {
		Describe("INT-MM04: Flag-off existing-object reconcile proceeds without conflict", func() {
			It("write-and-forgets even when a foreign-owned policy already exists", func() {
				By("Disabling markers for this spec only")
				markers.SetEnabled(false)
				DeferCleanup(func() { markers.SetEnabled(true) })

				By("Pre-writing a policy whose header names a foreign owner")
				vc := testEnv.VaultClient
				foreign := vault.OwnershipHeader(vault.Ownership{
					ManagedBy:   vault.KVManagedByValue,
					AuthMount:   "k8s-other-cluster",
					K8sResource: "other-ns/foreign",
					K8sKind:     "VaultPolicy",
				}) + "\npath \"secret/*\" { capabilities = [\"read\"] }"
				Expect(vc.WritePolicy(ctx, "default-int-mm04-policy", foreign)).To(Succeed())

				By("Creating the CR → with markers OFF it reconciles to Active (no conflict check)")
				policy := newTestPolicy("int-mm04-policy")
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				eventuallyPhase(ctx, testEnv,
					types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, vaultv1alpha1.PhaseActive)

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})
	})
})
