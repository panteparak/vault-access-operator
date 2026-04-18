/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// TC-DISC05-ROLE-ADOPTION pins the §4 fix end-to-end against the live k3s +
// Vault + operator stack. The test's success criterion is that the Vault role's
// ServiceAccount bindings survive the reconcile loop after discovery auto-creates
// a VaultRole CR. Before §4, the first reconcile would write the placeholder
// ServiceAccounts=[discovery-placeholder-replace-me] and silently unbind every
// real workload.

var _ = Describe("Discovery Auto-Create Tests", Ordered, Label("discovery", "auto-create"), func() {
	ctx := context.Background()

	const (
		autoCreateConnectionName = "e2e-discovery-autocreate"
		autoCreateTokenSecret    = "vault-token-autocreate"
		targetNamespace          = "vault-resources"
	)

	refreshAutoCreateToken := func() {
		By("ensuring a fresh token secret for auto-create discovery connection")
		vc, err := utils.GetTestVaultClient()
		Expect(err).NotTo(HaveOccurred())

		operatorToken, err := vc.CreateToken(ctx, []string{operatorPolicyName}, "1h")
		Expect(err).NotTo(HaveOccurred())

		_ = utils.DeleteSecret(ctx, testNamespace, autoCreateTokenSecret)
		err = utils.CreateSecret(ctx, testNamespace, autoCreateTokenSecret,
			map[string][]byte{"token": []byte(operatorToken)})
		Expect(err).NotTo(HaveOccurred())
	}

	BeforeAll(func() {
		By("ensuring target namespace for auto-created CRs exists")
		_ = utils.CreateNamespace(ctx, targetNamespace)
		refreshAutoCreateToken()
	})

	AfterAll(func() {
		By("cleaning up auto-create connection")
		_ = utils.DeleteVaultConnectionCR(ctx, autoCreateConnectionName)
		_ = utils.DeleteSecret(ctx, testNamespace, autoCreateTokenSecret)
	})

	Context("TC-DISC-AUTOCREATE: Discovery auto-creates adoption CRs safely", func() {
		It("TC-DISC05-ROLE-ADOPTION: Auto-created VaultRole must not overwrite real Vault role (§4)", func() {
			refreshAutoCreateToken()

			const (
				realRoleName   = "tc-disc05-real-role"
				realSAName     = "tc-disc05-real-sa"
				realSANamespce = "prod"
				realPolicyName = "tc-disc05-real-policy"
			)

			By("pre-populating Vault with a real auth role bound to a real SA")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			// Real role state — what a human operator set up pre-adoption.
			roleData := map[string]interface{}{
				"bound_service_account_names":      []string{realSAName},
				"bound_service_account_namespaces": []string{realSANamespce},
				"policies":                         []string{realPolicyName},
				"ttl":                              "5m",
			}
			Expect(vaultClient.WriteAuthRole(ctx, "kubernetes", realRoleName, roleData)).To(Succeed())
			DeferCleanup(func() { _ = vaultClient.DeleteAuthRole(ctx, "kubernetes", realRoleName) })

			By("creating VaultConnection with discovery + auto-create enabled")
			boolTrue := true
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{Name: autoCreateConnectionName},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: vaultK8sAddr,
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name:      autoCreateTokenSecret,
								Namespace: testNamespace,
								Key:       "token",
							},
						},
					},
					Discovery: &vaultv1alpha1.DiscoveryConfig{
						Enabled:               true,
						Interval:              "30s",
						RolePatterns:          []string{"tc-disc05-*"},
						ExcludeSystemPolicies: &boolTrue,
						AutoCreateCRs:         true,
						TargetNamespace:       targetNamespace,
					},
				},
			}
			Expect(utils.CreateVaultConnectionCR(ctx, conn)).To(Succeed())

			By("waiting for VaultConnection to become Active and complete a scan")
			Eventually(func(g Gomega) {
				vc, err := utils.GetVaultConnection(ctx, autoCreateConnectionName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(vc.Status.Phase).To(Equal(vaultv1alpha1.PhaseActive))
				g.Expect(vc.Status.DiscoveryStatus).NotTo(BeNil())
				g.Expect(vc.Status.DiscoveryStatus.UnmanagedRoles).To(BeNumerically(">=", 1))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for the auto-created VaultRole CR to appear")
			var autoCreated *vaultv1alpha1.VaultRole
			Eventually(func(g Gomega) {
				r, err := utils.GetVaultRole(ctx, realRoleName, targetNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(r).NotTo(BeNil())
				autoCreated = r
			}, 90*time.Second, 5*time.Second).Should(Succeed())
			DeferCleanup(func() { _ = utils.DeleteVaultRoleCR(ctx, realRoleName, targetNamespace) })

			By("verifying the auto-created CR has the annotations and placeholders §4 requires")
			Expect(autoCreated.Annotations[vaultv1alpha1.AnnotationAdopt]).To(Equal(vaultv1alpha1.AnnotationValueTrue))
			Expect(autoCreated.Annotations[vaultv1alpha1.AnnotationDiscoveryPending]).To(
				Equal(vaultv1alpha1.AnnotationValueTrue),
				"§4 regression: VaultRole must carry discovery-pending=true")
			Expect(autoCreated.Spec.ServiceAccounts).To(
				ContainElement("discovery-placeholder-replace-me"),
				"§4 regression: VaultRole must have placeholder SAs to satisfy MinItems=1")
			Expect(autoCreated.Spec.Policies).To(HaveLen(1))

			By("letting the reconciler run a few cycles over the auto-created CR")
			// Two+ reconcile intervals (default 30s success, 30s error).
			time.Sleep(90 * time.Second)

			By("verifying the real Vault role STILL has its original service-account binding")
			data, err := vaultClient.ReadAuthRole(ctx, "kubernetes", realRoleName)
			Expect(err).NotTo(HaveOccurred())
			Expect(data).NotTo(BeNil())
			Expect(data["bound_service_account_names"]).To(ContainElement(realSAName),
				"§4 regression: adopted role's real SA was unbound — the placeholder leaked into Vault")
			Expect(data["bound_service_account_names"]).NotTo(
				ContainElement("discovery-placeholder-replace-me"),
				"§4 regression: placeholder SA appeared in Vault")

			By("clearing the discovery-pending annotation and supplying real spec")
			Expect(utils.UpdateVaultRoleCR(ctx, realRoleName, targetNamespace, func(r *vaultv1alpha1.VaultRole) {
				delete(r.Annotations, vaultv1alpha1.AnnotationDiscoveryPending)
				r.Spec.ServiceAccounts = []string{realSAName}
				r.Spec.Policies = []vaultv1alpha1.PolicyReference{
					{Kind: "VaultClusterPolicy", Name: realPolicyName},
				}
			})).To(Succeed())

			By("verifying the operator now reconciles the CR to Active")
			Eventually(func(g Gomega) {
				r, err := utils.GetVaultRole(ctx, realRoleName, targetNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(r.Status.Phase).To(Equal(vaultv1alpha1.PhaseActive))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up auto-create connection for subsequent tests")
			_ = utils.DeleteVaultConnectionCR(ctx, autoCreateConnectionName)
			Eventually(func(g Gomega) {
				_, err := utils.GetVaultConnection(ctx, autoCreateConnectionName, "")
				g.Expect(err).To(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})
	})
})
