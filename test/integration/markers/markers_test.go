//go:build integration

/*
Package markers provides integration tests for in-band ownership tracking
(ADR 0008) against a real Vault (Testcontainers) and a real API server
(envtest). The policy handler is driven directly — the integration harness
does not run a controller manager — so every assertion is about actual
Vault/K8s state, not reconcile plumbing.

Tests use the naming convention: INT-MM{NN}_{Description}.
*/

package markers

import (
	"context"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	policyctrl "github.com/panteparak/vault-access-operator/features/policy/controller"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
	"github.com/panteparak/vault-access-operator/shared/markers"
	"github.com/panteparak/vault-access-operator/test/integration"
)

const mmConnName = "default-connection"

// setupPolicyHandler builds a policy handler wired to the suite's envtest
// API server and Vault container, plus the Active VaultConnection CR the
// resolver requires. Returns the handler and the operator-side vault client.
func setupPolicyHandler(ctx context.Context, env *integration.TestEnvironment) (*policyctrl.Handler, *vault.Client) {
	GinkgoHelper()

	conn := &vaultv1alpha1.VaultConnection{}
	if err := env.K8sClient.Get(ctx, types.NamespacedName{Name: mmConnName}, conn); err != nil {
		conn = &vaultv1alpha1.VaultConnection{
			ObjectMeta: metav1.ObjectMeta{Name: mmConnName},
			Spec: vaultv1alpha1.VaultConnectionSpec{
				Address: env.VaultAddress(),
				Auth: vaultv1alpha1.AuthConfig{
					Token: &vaultv1alpha1.TokenAuth{
						SecretRef: vaultv1alpha1.SecretKeySelector{Name: "vault-token", Key: "token"},
					},
				},
			},
		}
		Expect(env.K8sClient.Create(ctx, conn)).To(Succeed())
		conn.Status = vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseActive,
			Healthy: true,
			Conditions: []vaultv1alpha1.Condition{{
				Type:               vaultv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionTrue,
				Reason:             vaultv1alpha1.ReasonSucceeded,
				LastTransitionTime: metav1.Now(),
				ObservedGeneration: conn.Generation,
			}},
		}
		Expect(env.K8sClient.Status().Update(ctx, conn)).To(Succeed())
	}

	vc, err := env.NewVaultClient()
	Expect(err).NotTo(HaveOccurred())
	// The operator identity (ADR 0008). Token auth has no mount; stamp one
	// explicitly so identity comparisons behave like a real k8s-auth login.
	vc.SetAuthMount("kubernetes")

	cache := vault.NewClientCache()
	cache.Set(mmConnName, vc)

	h := policyctrl.NewHandler(env.K8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	return h, vc
}

// newTestPolicy returns a minimal VaultPolicy CR for these specs.
func newTestPolicy(name string) *vaultv1alpha1.VaultPolicy {
	return &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: mmConnName,
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
		handler *policyctrl.Handler
		opVC    *vault.Client // the operator's client (identity: kubernetes)
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
		handler, opVC = setupPolicyHandler(ctx, testEnv)
	})

	// syncAndPhase runs a sync through the handler and returns the CR's
	// resulting phase (the workflow persists status even on conflict).
	syncAndPhase := func(policy *vaultv1alpha1.VaultPolicy) vaultv1alpha1.Phase {
		GinkgoHelper()
		adapter := domain.NewVaultPolicyAdapter(policy)
		_ = handler.SyncPolicy(ctx, adapter) // classified errors also land in status
		fetched := &vaultv1alpha1.VaultPolicy{}
		Expect(testEnv.K8sClient.Get(ctx,
			types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, fetched)).To(Succeed())
		return fetched.Status.Phase
	}

	cleanupCR := func(policy *vaultv1alpha1.VaultPolicy) {
		GinkgoHelper()
		fetched := &vaultv1alpha1.VaultPolicy{}
		Expect(testEnv.K8sClient.Get(ctx,
			types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, fetched)).To(Succeed())
		Expect(handler.CleanupPolicy(ctx, domain.NewVaultPolicyAdapter(fetched))).To(Succeed())
		Expect(testEnv.K8sClient.Delete(ctx, fetched)).To(Succeed())
	}

	Context("INT-MM: Flag-on in-band ownership", func() {
		Describe("INT-MM01: Ownership header travels inside the policy document", func() {
			It("stamps the header on write and creates NO marker subtree", func() {
				By("Creating and syncing a VaultPolicy")
				policy := newTestPolicy("int-mm01-policy")
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				Expect(syncAndPhase(policy)).To(Equal(vaultv1alpha1.PhaseActive))

				By("Verifying the written policy carries the in-band ownership header")
				own, err := opVC.GetPolicyOwnership(ctx, "default-int-mm01-policy")
				Expect(err).NotTo(HaveOccurred())
				Expect(own).NotTo(BeNil())
				Expect(own.ManagedBy).To(Equal(vault.KVManagedByValue))
				Expect(own.AuthMount).To(Equal("kubernetes"))
				Expect(own.K8sResource).To(Equal("default/int-mm01-policy"))
				Expect(own.K8sKind).To(Equal("VaultPolicy"))

				By("Verifying the dedicated marker subtree is never created (ADR 0008)")
				list, err := opVC.Logical().ListWithContext(ctx, "secret/metadata/vault-access-operator")
				Expect(err).NotTo(HaveOccurred())
				Expect(list).To(BeNil(), "secret/metadata/vault-access-operator/ must not exist")

				By("Cleaning up: the ownership record dies with the policy")
				cleanupCR(policy)
				hcl, err := opVC.ReadPolicy(ctx, "default-int-mm01-policy")
				Expect(err).NotTo(HaveOccurred())
				Expect(hcl).To(BeEmpty())
			})
		})

		Describe("INT-MM02: Foreign-operator policy cannot be adopted", func() {
			It("conflicts even with the adopt annotation, and cleanup refuses to delete it", func() {
				By("Pre-writing a policy owned by another operator instance (different auth-mount identity)")
				foreign := vault.OwnershipHeader(vault.Ownership{
					ManagedBy:   vault.KVManagedByValue,
					AuthMount:   "k8s-other-cluster",
					K8sResource: "default/int-mm02-policy", // same CR coords — the collision case
					K8sKind:     "VaultPolicy",
				}) + "\npath \"secret/*\" { capabilities = [\"read\"] }"
				Expect(opVC.WritePolicy(ctx, "default-int-mm02-policy", foreign)).To(Succeed())

				By("Syncing a CR with the adopt annotation → adoption must be blocked")
				policy := newTestPolicy("int-mm02-policy")
				policy.Annotations = map[string]string{
					vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue,
				}
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				Expect(syncAndPhase(policy)).To(Equal(vaultv1alpha1.PhaseConflict))

				By("Verifying the foreign policy was not overwritten")
				hcl, err := opVC.ReadPolicy(ctx, "default-int-mm02-policy")
				Expect(err).NotTo(HaveOccurred())
				own, ok := vault.ParseOwnership(hcl)
				Expect(ok).To(BeTrue())
				Expect(own.AuthMount).To(Equal("k8s-other-cluster"))

				By("Verifying cleanup refuses to delete the foreign-owned policy")
				cleanupCR(policy)
				hcl, err = opVC.ReadPolicy(ctx, "default-int-mm02-policy")
				Expect(err).NotTo(HaveOccurred())
				Expect(hcl).NotTo(BeEmpty(), "foreign policy must survive our CR's cleanup")
				Expect(opVC.DeletePolicy(ctx, "default-int-mm02-policy")).To(Succeed())
			})
		})

		Describe("INT-MM05: Unmanaged-policy conflict and adoption", func() {
			It("fails on an unmanaged existing policy, then adopts with the adopt annotation", func() {
				By("Pre-writing an unmanaged policy (no ownership header)")
				Expect(opVC.WritePolicy(ctx, "default-int-mm05-policy",
					`path "secret/*" { capabilities = ["read"] }`)).To(Succeed())

				By("Syncing a colliding CR → expect Conflict")
				policy := newTestPolicy("int-mm05-policy")
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				Expect(syncAndPhase(policy)).To(Equal(vaultv1alpha1.PhaseConflict))

				By("Adding the adopt annotation → the operator adopts and reaches Active")
				fetched := &vaultv1alpha1.VaultPolicy{}
				Expect(testEnv.K8sClient.Get(ctx,
					types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, fetched)).To(Succeed())
				fetched.Annotations = map[string]string{
					vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue,
				}
				Expect(testEnv.K8sClient.Update(ctx, fetched)).To(Succeed())
				Expect(syncAndPhase(fetched)).To(Equal(vaultv1alpha1.PhaseActive))

				By("Verifying adoption rewrote the policy with our ownership header")
				own, err := opVC.GetPolicyOwnership(ctx, "default-int-mm05-policy")
				Expect(err).NotTo(HaveOccurred())
				Expect(own).NotTo(BeNil())
				Expect(own.K8sResource).To(Equal("default/int-mm05-policy"))

				By("Cleaning up")
				cleanupCR(policy)
			})
		})

		Describe("INT-MM06: Manual full replacement wipes the header but not ownership", func() {
			It("treats a headerless policy as ours when the CR previously synced, and flags the drift", func() {
				By("Creating and syncing a VaultPolicy")
				policy := newTestPolicy("int-mm06-policy")
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				Expect(syncAndPhase(policy)).To(Equal(vaultv1alpha1.PhaseActive))

				By("Manually replacing the policy in Vault (wipes the in-band header)")
				Expect(opVC.WritePolicy(ctx, "default-int-mm06-policy",
					`path "hijacked/*" { capabilities = ["delete"] }`)).To(Succeed())

				By("Re-syncing → NOT a conflict (CR status is the ownership memory)")
				fetched := &vaultv1alpha1.VaultPolicy{}
				Expect(testEnv.K8sClient.Get(ctx,
					types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, fetched)).To(Succeed())
				Expect(syncAndPhase(fetched)).To(Equal(vaultv1alpha1.PhaseActive))

				By("Verifying the divergence surfaced as drift (default mode detects, never overwrites)")
				Expect(testEnv.K8sClient.Get(ctx,
					types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, fetched)).To(Succeed())
				Expect(fetched.Status.DriftDetected).To(BeTrue())

				By("Cleaning up")
				cleanupCR(policy)
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
				foreign := vault.OwnershipHeader(vault.Ownership{
					ManagedBy:   vault.KVManagedByValue,
					AuthMount:   "k8s-other-cluster",
					K8sResource: "other-ns/foreign",
					K8sKind:     "VaultPolicy",
				}) + "\npath \"secret/*\" { capabilities = [\"read\"] }"
				Expect(opVC.WritePolicy(ctx, "default-int-mm04-policy", foreign)).To(Succeed())

				By("Syncing the CR → with markers OFF it reaches Active (no conflict check)")
				policy := newTestPolicy("int-mm04-policy")
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				Expect(syncAndPhase(policy)).To(Equal(vaultv1alpha1.PhaseActive))

				By("Cleaning up")
				cleanupCR(policy)
			})
		})
	})
})
