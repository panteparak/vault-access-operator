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
	"os"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// In-band ownership tests (ADR 0008). Ownership tracking is opt-in
// (--managed-markers), OFF on the default E2E stack. Opt-out cases (TC-MM01,
// TC-MM04) verify the disabled behavior on the default stack. Opt-in cases
// (TC-MM10, TC-MM13) require the operator deployed WITH --managed-markers and
// are gated on E2E_MANAGED_MARKERS (set by `make e2e-local-test-markers`);
// they Skip otherwise.
var _ = Describe("Managed Markers", Ordered, Label("managed-markers"), func() {
	const (
		mmOptOutPolicy = "tc-mm-optout-policy"
		mmAdoptPolicy  = "tc-mm-adopt-policy"
		mmOnPolicy     = "tc-mm-on-policy"
		mmConflictPol  = "tc-mm-conflict-policy"
	)

	ctx := context.Background()
	markersEnabled := false

	BeforeAll(func() {
		markersEnabled = os.Getenv("E2E_MANAGED_MARKERS") != ""
		RefreshSharedVaultToken(ctx)
	})

	AfterAll(func() {
		By("cleaning up managed-marker test resources")
		_ = utils.DeleteVaultPolicyCR(ctx, mmOptOutPolicy, testNamespace)
		_ = utils.DeleteVaultPolicyCR(ctx, mmAdoptPolicy, testNamespace)
		_ = utils.DeleteVaultPolicyCR(ctx, mmOnPolicy, testNamespace)
		_ = utils.DeleteVaultPolicyCR(ctx, mmConflictPol, testNamespace)
	})

	Context("TC-MM: markers disabled (default stack, opt-out)", func() {
		It("TC-MM01: the resource reaches Active and no marker subtree is created", func() {
			if markersEnabled {
				Skip("E2E_MANAGED_MARKERS set: this opt-out case asserts the DISABLED behavior")
			}

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

		It("TC-MM04: adopt-intent emits a ManagedMarkersDisabled Warning event", func() {
			if markersEnabled {
				Skip("E2E_MANAGED_MARKERS set: the disabled-warning only fires when markers are OFF")
			}

			By("creating a VaultPolicy that requests adoption via annotation")
			p := BuildTestPolicy(mmAdoptPolicy)
			p.Annotations = map[string]string{vaultv1alpha1.AnnotationAdopt: vaultv1alpha1.AnnotationValueTrue}
			// NOTE: with the admission webhook enabled this create is REJECTED
			// (adopt-intent needs markers). The default stack runs without the
			// validating webhook, so the create succeeds and the runtime warning
			// path is what we exercise here.
			Expect(utils.CreateVaultPolicyCR(ctx, p)).To(Succeed())

			By("verifying a Warning event with reason ManagedMarkersDisabled is emitted")
			Eventually(func(g Gomega) {
				out, err := utils.Run(exec.Command( //nolint:gosec // fixed args
					"kubectl", "get", "events", "-n", testNamespace,
					"--field-selector", "reason=ManagedMarkersDisabled",
					"-o", "jsonpath={.items[*].involvedObject.name}"))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(ContainSubstring(mmAdoptPolicy))
			}, 90*time.Second, 5*time.Second).Should(Succeed())
		})
	})

	Context("TC-MM: markers enabled (opt-in stack)", func() {
		BeforeEach(func() {
			if !markersEnabled {
				Skip("E2E_MANAGED_MARKERS not set: operator is not deployed with --managed-markers. " +
					"Run `make e2e-local-up-with-markers e2e-local-test-markers`.")
			}
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
