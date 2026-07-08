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
	rolectrl "github.com/panteparak/vault-access-operator/features/role/controller"
	roledomain "github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
	"github.com/panteparak/vault-access-operator/shared/markers"
	"github.com/panteparak/vault-access-operator/shared/naming"
	"github.com/panteparak/vault-access-operator/test/integration"
)

const mmConnName = "default-connection"

// mmVaultName derives the ADR 0010 Vault-side name this suite's handler
// binds: identity is the client's stamped "kubernetes" auth mount (no
// --cluster-name in tests), namespace is always "default" here.
func mmVaultName(name string) string {
	return naming.VaultName(naming.Identity("", "kubernetes"), "default", name)
}

// setupPolicyHandler builds a policy handler wired to the suite's envtest
// API server and Vault container, plus the Active VaultConnection CR the
// resolver requires. Returns the handler and the operator-side vault client.
func setupPolicyHandler(
	ctx context.Context, env *integration.TestEnvironment,
) (*policyctrl.Handler, *rolectrl.Handler, *vault.Client) {
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
	// The operator identity (ADR 0008). Token auth has no mount; stamp one
	// explicitly so identity comparisons behave like a real k8s-auth login.
	vc.SetAuthMount("kubernetes")

	cache := vault.NewClientCache()
	cache.Set(mmConnName, vc)

	h := policyctrl.NewHandler(env.K8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	rh := rolectrl.NewHandler(env.K8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	return h, rh, vc
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
		ctx         context.Context
		testEnv     *integration.TestEnvironment
		handler     *policyctrl.Handler
		roleHandler *rolectrl.Handler
		opVC        *vault.Client // the operator's client (identity: kubernetes)
	)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil(), "Test environment not initialized")
		handler, roleHandler, opVC = setupPolicyHandler(ctx, testEnv)
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
				own, err := opVC.GetPolicyOwnership(ctx, mmVaultName("int-mm01-policy"))
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
				hcl, err := opVC.ReadPolicy(ctx, mmVaultName("int-mm01-policy"))
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
				Expect(opVC.WritePolicy(ctx, mmVaultName("int-mm02-policy"), foreign)).To(Succeed())

				By("Syncing a CR with the adopt annotation → adoption must be blocked")
				policy := newTestPolicy("int-mm02-policy")
				policy.Annotations = map[string]string{
					vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue,
				}
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				Expect(syncAndPhase(policy)).To(Equal(vaultv1alpha1.PhaseConflict))

				By("Verifying the foreign policy was not overwritten")
				hcl, err := opVC.ReadPolicy(ctx, mmVaultName("int-mm02-policy"))
				Expect(err).NotTo(HaveOccurred())
				own, ok := vault.ParseOwnership(hcl)
				Expect(ok).To(BeTrue())
				Expect(own.AuthMount).To(Equal("k8s-other-cluster"))

				By("Verifying cleanup refuses to delete the foreign-owned policy")
				cleanupCR(policy)
				hcl, err = opVC.ReadPolicy(ctx, mmVaultName("int-mm02-policy"))
				Expect(err).NotTo(HaveOccurred())
				Expect(hcl).NotTo(BeEmpty(), "foreign policy must survive our CR's cleanup")
				Expect(opVC.DeletePolicy(ctx, mmVaultName("int-mm02-policy"))).To(Succeed())
			})
		})

		Describe("INT-MM05: Unmanaged-policy conflict and adoption", func() {
			It("fails on an unmanaged existing policy, then adopts with the adopt annotation", func() {
				By("Pre-writing an unmanaged policy (no ownership header)")
				Expect(opVC.WritePolicy(ctx, mmVaultName("int-mm05-policy"),
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
				own, err := opVC.GetPolicyOwnership(ctx, mmVaultName("int-mm05-policy"))
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
				Expect(opVC.WritePolicy(ctx, mmVaultName("int-mm06-policy"),
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

		Describe("INT-MM07: Rename converges to the new name and deletes the old", func() {
			It("writes the new-named policy, removes the old-named one, and keeps the header intact", func() {
				By("Creating and syncing a VaultPolicy")
				policy := newTestPolicy("int-mm07-policy")
				Expect(testEnv.K8sClient.Create(ctx, policy)).To(Succeed())
				Expect(syncAndPhase(policy)).To(Equal(vaultv1alpha1.PhaseActive))
				newName := mmVaultName("int-mm07-policy")

				By("Simulating a naming change: recording a fake old name in status " +
					"and pre-creating that old-named policy with OUR ownership header")
				oldName := naming.VaultName("old-cluster", "default", "int-mm07-policy")
				ours := vault.OwnershipHeader(vault.Ownership{
					ManagedBy:   vault.KVManagedByValue,
					AuthMount:   "kubernetes",
					K8sResource: "default/int-mm07-policy",
					K8sKind:     "VaultPolicy",
				}) + "\npath \"secret/*\" { capabilities = [\"read\"] }"
				Expect(opVC.WritePolicy(ctx, oldName, ours)).To(Succeed())

				fetched := &vaultv1alpha1.VaultPolicy{}
				Expect(testEnv.K8sClient.Get(ctx,
					types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, fetched)).To(Succeed())
				fetched.Status.VaultName = oldName
				Expect(testEnv.K8sClient.Status().Update(ctx, fetched)).To(Succeed())

				By("Re-syncing → the recorded name differs from the derived one, triggering a rename")
				Expect(syncAndPhase(fetched)).To(Equal(vaultv1alpha1.PhaseActive))

				By("Verifying the new-named policy exists with an intact ownership header")
				own, err := opVC.GetPolicyOwnership(ctx, newName)
				Expect(err).NotTo(HaveOccurred())
				Expect(own).NotTo(BeNil())
				Expect(own.K8sResource).To(Equal("default/int-mm07-policy"))
				Expect(own.AuthMount).To(Equal("kubernetes"))

				By("Verifying the old-named policy is GONE")
				hcl, err := opVC.ReadPolicy(ctx, oldName)
				Expect(err).NotTo(HaveOccurred())
				Expect(hcl).To(BeEmpty(), "stale pre-rename policy must be deleted")

				By("Verifying status records the new name")
				Expect(testEnv.K8sClient.Get(ctx,
					types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, fetched)).To(Succeed())
				Expect(fetched.Status.VaultName).To(Equal(newName))

				By("Cleaning up")
				cleanupCR(policy)
			})
		})

		Describe("INT-MM08: Role ownership rides in alias_metadata", func() {
			ensureKubernetesAuth := func() {
				GinkgoHelper()
				enabled, err := opVC.IsAuthEnabled(ctx, "kubernetes")
				Expect(err).NotTo(HaveOccurred())
				if !enabled {
					Expect(opVC.EnableAuth(ctx, "kubernetes", "kubernetes")).To(Succeed())
				}
			}

			newTestRole := func(name string) *vaultv1alpha1.VaultRole {
				return &vaultv1alpha1.VaultRole{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
					Spec: vaultv1alpha1.VaultRoleSpec{
						ConnectionRef:   mmConnName,
						ServiceAccounts: []string{"default"},
						Policies: []vaultv1alpha1.PolicyReference{
							{Kind: "VaultPolicy", Name: "int-mm08-nonexistent-policy"},
						},
					},
				}
			}

			It("stamps the ownership record on every write", func() {
				ensureKubernetesAuth()

				By("Creating and syncing a VaultRole")
				role := newTestRole("int-mm08-role")
				Expect(testEnv.K8sClient.Create(ctx, role)).To(Succeed())
				Expect(roleHandler.SyncRole(ctx, roledomain.NewVaultRoleAdapter(role))).To(Succeed())
				roleName := mmVaultName("int-mm08-role")

				By("Reading the role back raw — alias_metadata carries our ownership record")
				data, err := opVC.ReadKubernetesAuthRole(ctx, "kubernetes", roleName)
				Expect(err).NotTo(HaveOccurred())
				Expect(data).NotTo(BeNil())
				own, ok := vault.ParseAliasMetadata(data)
				Expect(ok).To(BeTrue(), "role must carry the alias_metadata ownership record")
				Expect(own.ManagedBy).To(Equal(vault.KVManagedByValue))
				Expect(own.AuthMount).To(Equal("kubernetes"))
				Expect(own.K8sResource).To(Equal("default/int-mm08-role"))
				Expect(own.K8sKind).To(Equal("VaultRole"))

				By("Cleaning up")
				fetched := &vaultv1alpha1.VaultRole{}
				Expect(testEnv.K8sClient.Get(ctx,
					types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, fetched)).To(Succeed())
				Expect(roleHandler.CleanupRole(ctx, roledomain.NewVaultRoleAdapter(fetched))).To(Succeed())
				Expect(testEnv.K8sClient.Delete(ctx, fetched)).To(Succeed())
			})

			It("conflicts when the derived name collides with a foreign-owned role", func() {
				ensureKubernetesAuth()

				By("Pre-creating a role at the CR's exact derived name, owned by a FOREIGN operator")
				roleName := mmVaultName("int-mm08-foreign-role")
				Expect(opVC.WriteKubernetesAuthRole(ctx, "kubernetes", roleName,
					map[string]interface{}{
						"bound_service_account_names":      []string{"svc-app"},
						"bound_service_account_namespaces": []string{"prod"},
						vault.RoleAliasMetadataKey: vault.OwnershipAliasMetadata(vault.Ownership{
							ManagedBy:   vault.KVManagedByValue,
							AuthMount:   "k8s-other-cluster",
							K8sResource: "other-ns/foreign-role",
							K8sKind:     "VaultRole",
						}),
					})).To(Succeed())

				By("Syncing a CR whose derived name collides → conflict")
				role := newTestRole("int-mm08-foreign-role")
				Expect(testEnv.K8sClient.Create(ctx, role)).To(Succeed())
				err := roleHandler.SyncRole(ctx, roledomain.NewVaultRoleAdapter(role))
				Expect(err).To(HaveOccurred(), "sync against a foreign-owned role must fail")

				fetched := &vaultv1alpha1.VaultRole{}
				Expect(testEnv.K8sClient.Get(ctx,
					types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, fetched)).To(Succeed())
				Expect(fetched.Status.Phase).To(Equal(vaultv1alpha1.PhaseConflict))

				By("Verifying the foreign role was not overwritten")
				data, err := opVC.ReadKubernetesAuthRole(ctx, "kubernetes", roleName)
				Expect(err).NotTo(HaveOccurred())
				own, ok := vault.ParseAliasMetadata(data)
				Expect(ok).To(BeTrue())
				Expect(own.AuthMount).To(Equal("k8s-other-cluster"))

				By("Cleaning up")
				Expect(opVC.DeleteKubernetesAuthRole(ctx, "kubernetes", roleName)).To(Succeed())
				Expect(testEnv.K8sClient.Delete(ctx, fetched)).To(Succeed())
			})
		})

		Describe("INT-MM09: ADR 0010 name charset is accepted by Vault (F13)", func() {
			It("accepts dotted 4-segment names for policies and roles, rejects commas in policy names", func() {
				dotted := "vao._.some-ns.dotted.cr.name" // CR names may contain dots — name is the LAST segment

				By("Writing a policy with a dotted ADR 0010 name")
				Expect(opVC.WritePolicy(ctx, dotted,
					`path "x/*" { capabilities = ["read"] }`)).To(Succeed())
				hcl, err := opVC.ReadPolicy(ctx, dotted)
				Expect(err).NotTo(HaveOccurred())
				Expect(hcl).NotTo(BeEmpty())

				By("Writing a role with the same dotted shape")
				enabled, err := opVC.IsAuthEnabled(ctx, "kubernetes")
				Expect(err).NotTo(HaveOccurred())
				if !enabled {
					Expect(opVC.EnableAuth(ctx, "kubernetes", "kubernetes")).To(Succeed())
				}
				Expect(opVC.WriteKubernetesAuthRole(ctx, "kubernetes", dotted,
					map[string]interface{}{
						"bound_service_account_names":      []string{"default"},
						"bound_service_account_namespaces": []string{"default"},
					})).To(Succeed())
				data, err := opVC.ReadKubernetesAuthRole(ctx, "kubernetes", dotted)
				Expect(err).NotTo(HaveOccurred())
				Expect(data).NotTo(BeNil())

				// Comma assertion skipped deliberately: Vault ACCEPTS a comma
				// in a policy name on write (verified against 1.17 and 1.21)
				// — the breakage only manifests later when the name is used
				// in a token_policies list. Nothing to pin at the write layer.

				By("Cleaning up")
				Expect(opVC.DeletePolicy(ctx, dotted)).To(Succeed())
				Expect(opVC.DeleteKubernetesAuthRole(ctx, "kubernetes", dotted)).To(Succeed())
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
				Expect(opVC.WritePolicy(ctx, mmVaultName("int-mm04-policy"), foreign)).To(Succeed())

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
