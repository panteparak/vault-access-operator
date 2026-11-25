/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// In-band ownership tests (ADR 0008). Since #18 the ownership checks run on
// every stack; --managed-markers only gates the discovery and orphan
// controllers. TC-MM01 checks no marker subtree is ever created, TC-MM04 that
// the adopt annotation takes over an unrecorded policy, and TC-MM10/TC-MM13 the in-band record
// and the foreign-owner block, on the default stack and on the
// --managed-markers stack (`make e2e-local-test-markers`) alike.
var _ = Describe("Managed Markers", Ordered, Label("managed-markers"), func() {
	const (
		mmOptOutPolicy = "tc-mm-optout-policy"
		mmAdoptPolicy  = "tc-mm-adopt-policy"
		mmOnPolicy     = "tc-mm-on-policy"
		mmConflictPol  = "tc-mm-conflict-policy"
	)

	ctx := context.Background()

	BeforeAll(func() {
		RefreshSharedVaultToken(ctx)
	})

	AfterAll(func() {
		By("cleaning up managed-marker test resources")
		_ = utils.DeleteVaultPolicyCR(ctx, mmOptOutPolicy, testNamespace)
		_ = utils.DeleteVaultPolicyCR(ctx, mmAdoptPolicy, testNamespace)
		_ = utils.DeleteVaultPolicyCR(ctx, mmOnPolicy, testNamespace)
		_ = utils.DeleteVaultPolicyCR(ctx, mmConflictPol, testNamespace)
	})

	Context("TC-MM: in-band ownership (any stack)", func() {
		It("TC-MM01: the resource reaches Active and no marker subtree is created", func() {

			By("creating a VaultPolicy")
			Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(mmOptOutPolicy))).To(Succeed())

			By("waiting for it to become Active")
			ExpectPolicyActive(ctx, mmOptOutPolicy)

			By("verifying NO marker subtree exists in Vault (ADR 0008: ownership is in-band)")
			vc, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			Consistently(func(g Gomega) {
				secret, listErr := vc.Client().Logical().ListWithContext(ctx, "secret/metadata/vault-access-operator")
				g.Expect(listErr).NotTo(HaveOccurred())
				g.Expect(secret).To(BeNil(), "no marker subtree should ever be created")
			}, 10*time.Second, 2*time.Second).Should(Succeed())
		})

		// #18 AC7 (changed from v0.12.0, which rejected or ignored adopt-intent
		// with markers off): ownership checks always run, so the adopt
		// annotation takes over an unrecorded policy with or without
		// --managed-markers. (TC-ID07 covers spec.conflictPolicy: Adopt.)
		It("TC-MM04: the adopt annotation takes over an unrecorded policy, with or without --managed-markers", func() {
			vaultPolicyName := nsVaultName(mmAdoptPolicy)
			vc, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = vc.DeletePolicy(ctx, vaultPolicyName) })

			By("placing an unrecorded policy at the CR's Vault name")
			Expect(vc.WritePolicy(ctx, vaultPolicyName,
				`path "secret/data/unrecorded-mm04/*" { capabilities = ["read"] }`)).To(Succeed())

			By("creating a VaultPolicy that requests adoption via annotation")
			p := BuildTestPolicy(mmAdoptPolicy)
			p.Annotations = map[string]string{vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue}
			Expect(utils.CreateVaultPolicyCR(ctx, p)).To(Succeed())
			ExpectPolicyActive(ctx, mmAdoptPolicy)

			By("verifying the policy now carries this CR's ownership header")
			hcl, err := vc.ReadPolicy(ctx, vaultPolicyName)
			Expect(err).NotTo(HaveOccurred())
			own, ok := vault.ParseOwnership(hcl)
			Expect(ok).To(BeTrue(), "expected an ownership header after adoption, got:\n%s", hcl)
			Expect(own.K8sResource).To(Equal(testNamespace + "/" + mmAdoptPolicy))
			Expect(hcl).NotTo(ContainSubstring("unrecorded-mm04"), "adoption must replace the unrecorded rules")
		})

		It("TC-MM10: the ownership header travels inside the policy document", func() {
			By("creating a VaultPolicy")
			Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(mmOnPolicy))).To(Succeed())

			By("waiting for it to become Active")
			ExpectPolicyActive(ctx, mmOnPolicy)

			By("verifying the written policy carries the structured ownership header")
			vc, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				hcl, readErr := vc.ReadPolicy(ctx, nsVaultName(mmOnPolicy))
				g.Expect(readErr).NotTo(HaveOccurred())
				own, ok := vault.ParseOwnership(hcl)
				g.Expect(ok).To(BeTrue(), "expected in-band ownership header, got:\n%s", hcl)
				g.Expect(own.ManagedBy).To(Equal(vault.KVManagedByValue))
				g.Expect(own.K8sResource).To(Equal(testNamespace + "/" + mmOnPolicy))
				g.Expect(own.K8sKind).To(Equal("VaultPolicy"))
				// The e2e stack's operator connection authenticates with a
				// static token → no auth mount, no identity line (ADR 0008).
				// The OwnershipIdentityUnavailable warning event covers that
				// path; the header simply omits auth-mount here.
				g.Expect(own.AuthMount).To(BeEmpty())
			}, 60*time.Second, 5*time.Second).Should(Succeed())

			By("verifying no dedicated marker subtree was created")
			secret, listErr := vc.Client().Logical().ListWithContext(ctx, "secret/metadata/vault-access-operator")
			Expect(listErr).NotTo(HaveOccurred())
			Expect(secret).To(BeNil())
		})

		It("TC-MM13: a foreign ownership header blocks (Conflict), and adopt does not override it", func() {
			By("pre-writing a policy owned by another operator instance (foreign auth-mount identity)")
			vc, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			foreign := vault.OwnershipHeader(vault.Ownership{
				ManagedBy:   vault.KVManagedByValue,
				AuthMount:   "k8s-other-cluster",
				K8sResource: "other-ns/foreign-owner",
				K8sKind:     "VaultPolicy",
			}) + "\npath \"secret/*\" { capabilities = [\"read\"] }"
			Expect(vc.WritePolicy(ctx, nsVaultName(mmConflictPol), foreign)).To(Succeed())

			By("creating the CR → expect a non-Active (Conflict) phase")
			Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(mmConflictPol))).To(Succeed())
			Eventually(func(g Gomega) {
				status, statusErr := utils.GetVaultPolicyStatus(ctx, mmConflictPol, testNamespace)
				g.Expect(statusErr).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Conflict"))
			}, 90*time.Second, 5*time.Second).Should(Succeed())

			By("adding the adopt annotation → still blocked: adopt never steals a resource another owner holds")
			Expect(utils.UpdateVaultPolicyCR(ctx, mmConflictPol, testNamespace, func(p *vaultv1alpha1.VaultPolicy) {
				if p.Annotations == nil {
					p.Annotations = map[string]string{}
				}
				p.Annotations[vaultv1alpha1.AnnotationAdopt] = vaultv1alpha1.AnnotationValueTrue
			})).To(Succeed())
			Consistently(func(g Gomega) {
				status, statusErr := utils.GetVaultPolicyStatus(ctx, mmConflictPol, testNamespace)
				g.Expect(statusErr).NotTo(HaveOccurred())
				g.Expect(status).NotTo(Equal("Active"))
			}, 20*time.Second, 5*time.Second).Should(Succeed())

			By("verifying the foreign policy content was never overwritten")
			hcl, readErr := vc.ReadPolicy(ctx, nsVaultName(mmConflictPol))
			Expect(readErr).NotTo(HaveOccurred())
			own, ok := vault.ParseOwnership(hcl)
			Expect(ok).To(BeTrue())
			Expect(own.AuthMount).To(Equal("k8s-other-cluster"))
		})
	})
})
