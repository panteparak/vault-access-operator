//go:build integration

/*
Package markers provides integration tests for managed-marker tracking.

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

var _ = Describe("Managed Markers Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
	})

	Context("INT-MM: Flag-on marker writes", func() {
		Describe("INT-MM01: Marker written at hierarchical metadata path with no data version", func() {
			It("stores custom_metadata only, never a secret data version", func() {
				By("Creating a VaultPolicy")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "int-mm01-policy", Namespace: "default"},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{Path: "secret/data/{{namespace}}/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())

				By("Waiting for the policy to become Active")
				eventuallyPhase(ctx, testEnv,
					types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, vaultv1alpha1.PhaseActive)

				By("Verifying the marker is custom_metadata at the hierarchical path")
				vc := testEnv.VaultClient
				md, err := vc.ReadKVMetadata(ctx, "secret",
					"vault-access-operator/managed/policies/default/int-mm01-policy")
				Expect(err).NotTo(HaveOccurred())
				Expect(md).NotTo(BeNil())
				Expect(md.CustomMetadata).To(HaveKeyWithValue(vault.KVManagedByKey, vault.KVManagedByValue))
				Expect(md.CustomMetadata).To(HaveKeyWithValue(vault.KVK8sResourceKey, "default/int-mm01-policy"))

				By("Verifying NO secret data version was written (marker is metadata-only)")
				// The marker exists as custom_metadata but has zero data versions.
				Expect(md.CurrentVersion).To(Equal(0))

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})

		Describe("INT-MM02: Auth-mount isolation for same-name roles", func() {
			It("keeps kubernetes vs jwt role markers distinct", func() {
				By("Seeding two same-name role markers on different auth mounts")
				vc := testEnv.VaultClient
				Expect(vc.MarkManaged(ctx,
					vault.MarkerID{Kind: vault.MarkerRole, Mount: "kubernetes", Namespace: "default", Name: "shared"},
					"default/shared-k8s")).To(Succeed())
				Expect(vc.MarkManaged(ctx,
					vault.MarkerID{Kind: vault.MarkerRole, Mount: "jwt", Namespace: "default", Name: "shared"},
					"default/shared-jwt")).To(Succeed())

				By("Listing managed roles — both mounts stay distinct (mount-qualified keys)")
				managed, err := vc.ListManaged(ctx, vault.MarkerRole)
				Expect(err).NotTo(HaveOccurred())
				Expect(managed).To(HaveKey("kubernetes/default-shared"))
				Expect(managed).To(HaveKey("jwt/default-shared"))
				Expect(managed["kubernetes/default-shared"].K8sResource).To(Equal("default/shared-k8s"))
				Expect(managed["jwt/default-shared"].K8sResource).To(Equal("default/shared-jwt"))

				By("Cleaning up the seeded markers")
				Expect(vc.RemoveManaged(ctx,
					vault.MarkerID{Kind: vault.MarkerRole, Mount: "kubernetes", Namespace: "default", Name: "shared"})).To(Succeed())
				Expect(vc.RemoveManaged(ctx,
					vault.MarkerID{Kind: vault.MarkerRole, Mount: "jwt", Namespace: "default", Name: "shared"})).To(Succeed())
			})
		})

		Describe("INT-MM05: Flag-on conflict detection and adoption", func() {
			It("fails on a foreign marker, then adopts with the adopt annotation", func() {
				By("Pre-seeding a foreign ownership marker at the policy's marker path")
				vc := testEnv.VaultClient
				id := vault.MarkerID{Kind: vault.MarkerPolicy, Namespace: "default", Name: "int-mm05-policy"}
				Expect(vc.MarkManaged(ctx, id, "other-ns/other-owner")).To(Succeed())

				By("Also writing the policy itself so the existence check trips")
				Expect(vc.WritePolicy(ctx, "default-int-mm05-policy",
					`path "secret/*" { capabilities = ["read"] }`)).To(Succeed())

				By("Creating a VaultPolicy that would collide → expect Conflict")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "int-mm05-policy", Namespace: "default"},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{Path: "secret/data/{{namespace}}/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
						},
					},
				}
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

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})
	})

	Context("INT-MM: Flag-off behavior", func() {
		Describe("INT-MM04: Flag-off existing-object reconcile proceeds without conflict", func() {
			It("write-and-forgets even when a foreign marker and the object already exist", func() {
				By("Disabling markers for this spec only")
				markers.SetEnabled(false)
				DeferCleanup(func() { markers.SetEnabled(true) })

				By("Pre-seeding an existing policy + a foreign marker that would conflict if markers were on")
				vc := testEnv.VaultClient
				Expect(vc.WritePolicy(ctx, "default-int-mm04-policy",
					`path "secret/*" { capabilities = ["read"] }`)).To(Succeed())
				// Marker written while briefly enabling the flag, so the foreign
				// record genuinely exists in Vault.
				markers.SetEnabled(true)
				Expect(vc.MarkManaged(ctx,
					vault.MarkerID{Kind: vault.MarkerPolicy, Namespace: "default", Name: "int-mm04-policy"},
					"other-ns/foreign")).To(Succeed())
				markers.SetEnabled(false)

				By("Creating the CR → with markers OFF it reconciles to Active (no conflict check)")
				policy := &vaultv1alpha1.VaultPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "int-mm04-policy", Namespace: "default"},
					Spec: vaultv1alpha1.VaultPolicySpec{
						ConnectionRef: "default-connection",
						Rules: []vaultv1alpha1.PolicyRule{
							{Path: "secret/data/{{namespace}}/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				eventuallyPhase(ctx, testEnv,
					types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, vaultv1alpha1.PhaseActive)

				By("Cleaning up")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})
	})
})
