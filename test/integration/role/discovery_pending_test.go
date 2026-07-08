//go:build integration

/*
Integration tests for the discovery-pending annotation guard on RoleOps
(IMPROVEMENTS.md §4). These tests exercise the skip against a real Vault
container (via testcontainers) to validate the vault-api-go SDK behavior
end-to-end, not just the HTTP-layer contract covered by unit tests.

Scenario — the regression we're guarding against:
  1. A Vault operator has manually created an auth role with real
     service-account bindings, e.g. ["svc-app"].
  2. Discovery scans Vault and auto-creates a VaultRole CR for adoption.
     The auto-create sets `discovery-pending=true` plus placeholder SAs
     and Policies required to satisfy MinItems=1 schema validation.
  3. Without the skip guard, the FIRST reconcile would call
     `WriteKubernetesAuthRole` with the placeholder spec, silently
     overwriting the real SAs and breaking every pod relying on the role.

INT-DISC-PEND01 pins the happy path (skip active).
INT-DISC-PEND02 pins the counter-case (annotation cleared → write proceeds).
*/

package role

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	rolectrl "github.com/panteparak/vault-access-operator/features/role/controller"
	roledomain "github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/naming"
	"github.com/panteparak/vault-access-operator/test/integration"
)

var _ = Describe("INT-DISC-PEND: Discovery-pending role adoption safety (IMPROVEMENTS §4)", func() {
	var (
		ctx         context.Context
		testEnv     *integration.TestEnvironment
		vaultClient *vault.Client
	)

	const (
		realNamespace = "int-disc-pend"
		realName      = "real-role"
		authPath      = "auth/kubernetes"
	)
	// ADR 0010 name: the suite's vault client is token-auth (no auth mount)
	// and no --cluster-name is set, so the identity segment is the
	// placeholder. Pre-populate Vault with this exact name so the CR we
	// construct below targets the same role.
	realRoleName := naming.VaultName(naming.Placeholder, realNamespace, realName)

	BeforeEach(func() {
		ctx = integration.GetContext()
		testEnv = integration.GetTestEnv()
		Expect(testEnv).NotTo(BeNil())
		Expect(testEnv.VaultClient).NotTo(BeNil(), "vault container required")
		vaultClient = testEnv.VaultClient

		By("ensuring kubernetes auth mount is enabled")
		enabled, err := vaultClient.IsAuthEnabled(ctx, "kubernetes")
		Expect(err).NotTo(HaveOccurred())
		if !enabled {
			Expect(vaultClient.EnableAuth(ctx, "kubernetes", "kubernetes")).To(Succeed())
		}

		By("pre-populating Vault with a real auth role bound to real SAs")
		realData := map[string]interface{}{
			"policies":                         []string{"real-policy"},
			"bound_service_account_names":      []string{"svc-app"},
			"bound_service_account_namespaces": []string{"prod"},
		}
		Expect(vaultClient.WriteKubernetesAuthRole(ctx, authPath, realRoleName, realData)).To(Succeed())
	})

	AfterEach(func() {
		_ = vaultClient.DeleteKubernetesAuthRole(ctx, authPath, realRoleName)
	})

	Describe("INT-DISC-PEND01: WriteToVault skips when discovery-pending=true", func() {
		It("preserves real service-account bindings on the adopted Vault role", func() {
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      realName,
					Namespace: realNamespace,
					Annotations: map[string]string{
						vaultv1alpha1.AnnotationAdopt:            vaultv1alpha1.AnnotationValueTrue,
						vaultv1alpha1.AnnotationDiscoveryPending: vaultv1alpha1.AnnotationValueTrue,
					},
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef: "default-connection",
					// Placeholder values that MUST NOT reach Vault.
					ServiceAccounts: []string{"discovery-placeholder-replace-me"},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "discovery-placeholder-replace-me"},
					},
				},
			}
			adapter := roledomain.NewVaultRoleAdapter(role)

			ops := rolectrl.NewRoleOpsForTest(adapter, authPath,
				map[string]interface{}{
					"policies":                         []string{"discovery-placeholder-replace-me"},
					"bound_service_account_names":      []string{"discovery-placeholder-replace-me"},
					"bound_service_account_namespaces": []string{realNamespace},
				})
			Expect(ops.BindVaultName(vaultClient)).To(Equal(realRoleName),
				"test setup: derived name must match pre-populated Vault role")

			By("invoking WriteToVault while discovery-pending is set")
			Expect(ops.WriteToVault(ctx, vaultClient)).To(Succeed())

			By("reading the role back — placeholder MUST NOT have been written")
			data, err := vaultClient.ReadKubernetesAuthRole(ctx, authPath, realRoleName)
			Expect(err).NotTo(HaveOccurred())
			Expect(data).NotTo(BeNil())
			Expect(data["bound_service_account_names"]).To(ContainElement("svc-app"),
				"real SA was unbound — §4 regression")
			Expect(data["bound_service_account_names"]).NotTo(ContainElement("discovery-placeholder-replace-me"),
				"placeholder leaked into Vault — §4 regression")

			By("invoking ReadbackVerify — must not return TransientError")
			// Even though Vault content differs from the placeholder roleData,
			// the skip guard short-circuits ReadbackVerify too. Without the
			// guard this would loop the reconciler forever with a
			// "role content mismatch after write" TransientError.
			Expect(ops.ReadbackVerify(ctx, vaultClient)).To(Succeed())
		})
	})

	Describe("INT-DISC-PEND02: WriteToVault proceeds when annotation is cleared", func() {
		It("writes user-directed data when discovery-pending is absent", func() {
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:       realName,
					Namespace:  realNamespace,
					Generation: 1,
					// NO discovery-pending annotation.
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   "default-connection",
					ServiceAccounts: []string{"svc-newapp"},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultClusterPolicy", Name: "newapp-policy"},
					},
				},
			}
			adapter := roledomain.NewVaultRoleAdapter(role)

			ops := rolectrl.NewRoleOpsForTest(adapter, authPath,
				map[string]interface{}{
					"policies":                         []string{"newapp-policy"},
					"bound_service_account_names":      []string{"svc-newapp"},
					"bound_service_account_namespaces": []string{realNamespace},
				})
			Expect(ops.BindVaultName(vaultClient)).To(Equal(realRoleName))

			By("invoking WriteToVault — should proceed")
			Expect(ops.WriteToVault(ctx, vaultClient)).To(Succeed())

			By("reading the role back — user-directed data should have replaced the original")
			data, err := vaultClient.ReadKubernetesAuthRole(ctx, authPath, realRoleName)
			Expect(err).NotTo(HaveOccurred())
			Expect(data["bound_service_account_names"]).To(ContainElement("svc-newapp"))
			Expect(data["bound_service_account_names"]).NotTo(ContainElement("svc-app"),
				"user-directed write must replace the existing bindings")
		})
	})
})
