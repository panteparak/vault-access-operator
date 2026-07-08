//go:build integration

/*
Package orphan provides integration tests for orphan detection against a real
Vault (Testcontainers) and a real API server (envtest). The policy handler and
the orphan controller are driven directly — the integration harness does not
run a controller manager.

Tests use the naming convention: INT-ORP{NN}_{Description}
*/

package orphan

import (
	"context"

	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	policyctrl "github.com/panteparak/vault-access-operator/features/policy/controller"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/orphan"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
	"github.com/panteparak/vault-access-operator/shared/naming"
	"github.com/panteparak/vault-access-operator/test/integration"
)

const orpConnName = "default-connection"

// orpVaultName derives the ADR 0010 Vault-side name this suite's handler
// binds: identity is the client's stamped "kubernetes" auth mount (no
// --cluster-name in tests), namespace is always "default" here.
func orpVaultName(name string) string {
	return naming.VaultName(naming.Identity("", "kubernetes"), "default", name)
}

// setupHarness builds the policy handler + orphan controller wired to the
// suite's envtest API server and Vault container. The operator's identity is
// the "kubernetes" auth mount (stamped explicitly — token auth has none).
func setupHarness(ctx context.Context, env *integration.TestEnvironment) (
	*policyctrl.Handler, *orphan.Controller, *vault.Client,
) {
	GinkgoHelper()

	conn := &vaultv1alpha1.VaultConnection{}
	if err := env.K8sClient.Get(ctx, types.NamespacedName{Name: orpConnName}, conn); err != nil {
		conn = &vaultv1alpha1.VaultConnection{
			ObjectMeta: metav1.ObjectMeta{Name: orpConnName},
			Spec: vaultv1alpha1.VaultConnectionSpec{
				Address: env.VaultAddress(),
				Auth: vaultv1alpha1.AuthConfig{
					Token: &vaultv1alpha1.TokenAuth{
						SecretRef: vaultv1alpha1.SecretKeySelector{Name: "vault-token", Key: "token"},
					},
				},
				// Token login has no mount — declare the role mount so role
				// CRs referencing this connection resolve to "kubernetes"
				// (matches vc.SetAuthMount below).
				Defaults: &vaultv1alpha1.ConnectionDefaults{AuthPath: "kubernetes"},
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
	vc.SetAuthMount("kubernetes")

	cache := vault.NewClientCache()
	cache.Set(orpConnName, vc)

	handler := policyctrl.NewHandler(env.K8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	ctrl := orphan.NewController(orphan.ControllerConfig{
		K8sClient:   env.K8sClient,
		ClientCache: cache,
		Log:         logr.Discard(),
	})
	return handler, ctrl, vc
}

func newOrpPolicy(name string) *vaultv1alpha1.VaultPolicy {
	return &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: orpConnName,
			Rules: []vaultv1alpha1.PolicyRule{
				{Path: "secret/data/{{namespace}}/*", Capabilities: []vaultv1alpha1.Capability{"read"}},
			},
		},
	}
}

var _ = Describe("Orphan Detection Integration Tests", func() {
	var (
		ctx     context.Context
		testEnv *integration.TestEnvironment
		handler *policyctrl.Handler
		ctrl    *orphan.Controller
		opVC    *vault.Client
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
		handler, ctrl, opVC = setupHarness(ctx, testEnv)
	})

	syncPolicy := func(policy *vaultv1alpha1.VaultPolicy) {
		GinkgoHelper()
		Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
		Expect(handler.SyncPolicy(ctx, domain.NewVaultPolicyAdapter(policy))).To(Succeed())
	}

	orphanNames := func(infos []orphan.OrphanInfo) []string {
		names := make([]string, 0, len(infos))
		for _, o := range infos {
			names = append(names, o.VaultName)
		}
		return names
	}

	Context("INT-ORP: Policy Orphan Detection", func() {
		Describe("INT-ORP01: Detect orphaned policy when K8s resource is deleted", func() {
			It("flags a policy whose in-band header names a vanished CR", func() {
				By("Syncing a VaultPolicy so Vault carries our ownership header")
				policy := newOrpPolicy("int-orp01-test-policy")
				syncPolicy(policy)

				By("Deleting the CR WITHOUT cleanup (simulates a missed finalizer)")
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())

				By("Running policy orphan detection")
				orphans := ctrl.DetectOrphanedPolicies(ctx, opVC, orpConnName)
				Expect(orphanNames(orphans)).To(ContainElement(orpVaultName("int-orp01-test-policy")))

				By("Cleaning up the leaked Vault policy")
				Expect(opVC.DeletePolicy(ctx, orpVaultName("int-orp01-test-policy"))).To(Succeed())
			})
		})

		Describe("INT-ORP02: No orphan when K8s resource exists", func() {
			It("does not flag a policy whose owning CR is alive", func() {
				By("Syncing a VaultPolicy")
				policy := newOrpPolicy("int-orp02-active-policy")
				syncPolicy(policy)

				By("Verifying the ownership header names the owning K8s resource")
				own, err := opVC.GetPolicyOwnership(ctx, orpVaultName("int-orp02-active-policy"))
				Expect(err).NotTo(HaveOccurred())
				Expect(own).NotTo(BeNil())
				Expect(own.K8sResource).To(Equal("default/int-orp02-active-policy"))

				By("Running policy orphan detection — nothing flagged")
				orphans := ctrl.DetectOrphanedPolicies(ctx, opVC, orpConnName)
				Expect(orphanNames(orphans)).NotTo(ContainElement(orpVaultName("int-orp02-active-policy")))

				By("Cleaning up")
				Expect(handler.CleanupPolicy(ctx, domain.NewVaultPolicyAdapter(policy))).To(Succeed())
				Expect(testEnv.K8sClient.Delete(ctx, policy)).To(Succeed())
			})
		})

		Describe("INT-ORP04: Foreign and unmanaged policies are never flagged", func() {
			It("ignores policies without our identity", func() {
				By("Writing an unmanaged policy and a foreign-operator policy directly to Vault")
				Expect(opVC.WritePolicy(ctx, "int-orp04-unmanaged",
					`path "x/*" { capabilities = ["read"] }`)).To(Succeed())
				foreign := vault.OwnershipHeader(vault.Ownership{
					ManagedBy:   vault.KVManagedByValue,
					AuthMount:   "k8s-other-cluster",
					K8sResource: "gone/foreign",
					K8sKind:     "VaultPolicy",
				}) + "\npath \"y/*\" { capabilities = [\"read\"] }"
				Expect(opVC.WritePolicy(ctx, "int-orp04-foreign", foreign)).To(Succeed())

				By("Running policy orphan detection — neither is ours to flag")
				orphans := ctrl.DetectOrphanedPolicies(ctx, opVC, orpConnName)
				Expect(orphanNames(orphans)).NotTo(ContainElement("int-orp04-unmanaged"))
				Expect(orphanNames(orphans)).NotTo(ContainElement("int-orp04-foreign"))

				By("Cleaning up")
				Expect(opVC.DeletePolicy(ctx, "int-orp04-unmanaged")).To(Succeed())
				Expect(opVC.DeletePolicy(ctx, "int-orp04-foreign")).To(Succeed())
			})
		})
	})

	Context("INT-ORP: Role Orphan Detection", func() {
		Describe("INT-ORP03: Detect orphaned role on the operator's own mount", func() {
			It("flags only vao.-shaped roles with no CR; hand-created and recorded roles survive", func() {
				By("Enabling the kubernetes auth mount")
				err := opVC.Sys().EnableAuthWithOptionsWithContext(ctx, "kubernetes",
					&vaultapi.EnableAuthOptions{Type: "kubernetes"})
				if err != nil {
					// Already enabled from a previous spec — fine.
					Expect(err.Error()).To(ContainSubstring("already in use"))
				}

				roleData := map[string]interface{}{
					"bound_service_account_names":      []string{"default"},
					"bound_service_account_namespaces": []string{"default"},
				}

				By("Writing a vao.-shaped role on OUR mount with no corresponding CR → orphan")
				staleName := orpVaultName("int-orp03-stale-role")
				Expect(opVC.WriteKubernetesAuthRole(ctx, "kubernetes", staleName, roleData)).To(Succeed())

				By("Writing a HAND-CREATED role (no vao. prefix) on our mount → never an orphan candidate")
				Expect(opVC.WriteKubernetesAuthRole(ctx, "kubernetes", "int-orp03-hand-role", roleData)).To(Succeed())

				By("Creating a VaultRole CR with its synced name RECORDED in status (not an orphan)")
				role := &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{Name: "live-role", Namespace: "default"},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   orpConnName,
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{Kind: "VaultPolicy", Name: "some-policy"},
						},
					},
				}
				Expect(testEnv.K8sClient.Create(ctx, role)).To(Succeed())
				liveName := orpVaultName("live-role")
				// The scan matches by RECORDED status names (ADR 0010) —
				// simulate a synced CR by recording the name it wrote.
				role.Status.VaultRoleName = liveName
				Expect(testEnv.K8sClient.Status().Update(ctx, role)).To(Succeed())
				Expect(opVC.WriteKubernetesAuthRole(ctx, "kubernetes", liveName, roleData)).To(Succeed())

				By("Running role orphan detection")
				orphans := ctrl.DetectOrphanedRoles(ctx, opVC, orpConnName)
				names := orphanNames(orphans)
				Expect(names).To(ContainElement(staleName),
					"vao.-shaped role with no CR must be flagged")
				Expect(names).NotTo(ContainElement("int-orp03-hand-role"),
					"hand-created (non-vao.) role must never be flagged")
				Expect(names).NotTo(ContainElement(liveName),
					"role recorded in a live CR's status must not be flagged")

				By("Cleaning up")
				Expect(opVC.DeleteKubernetesAuthRole(ctx, "kubernetes", staleName)).To(Succeed())
				Expect(opVC.DeleteKubernetesAuthRole(ctx, "kubernetes", "int-orp03-hand-role")).To(Succeed())
				Expect(opVC.DeleteKubernetesAuthRole(ctx, "kubernetes", liveName)).To(Succeed())
				Expect(testEnv.K8sClient.Delete(ctx, role)).To(Succeed())
			})
		})
	})
})
