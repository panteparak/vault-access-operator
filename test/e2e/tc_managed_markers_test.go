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
	"fmt"
	"os"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// Managed-marker tests. Marker tracking is opt-in (--managed-markers), OFF on
// the default E2E stack. Opt-out cases (TC-MM01, TC-MM04) verify the disabled
// behavior on the default stack. Opt-in cases (TC-MM10, TC-MM13) require the
// operator deployed WITH --managed-markers and are gated on E2E_MANAGED_MARKERS
// (set by `make e2e-local-test-markers`); they Skip otherwise.
var _ = Describe("Managed Markers", Ordered, Label("managed-markers"), func() {
	const (
		mmOptOutPolicy = "tc-mm-optout-policy"
		mmAdoptPolicy  = "tc-mm-adopt-policy"
		mmOnPolicy     = "tc-mm-on-policy"
		mmConflictPol  = "tc-mm-conflict-policy"
	)

	ctx := context.Background()
	markersEnabled := false

	// markerMetadataPath returns the KV v2 metadata path a namespaced policy
	// marker lands at on the default (no cluster prefix) stack.
	markerMetadataPath := func(name string) string {
		return fmt.Sprintf("secret/metadata/vault-access-operator/managed/policies/%s/%s", testNamespace, name)
	}

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
		It("TC-MM01: no marker is written and the resource reaches Active", func() {
			if markersEnabled {
				Skip("E2E_MANAGED_MARKERS set: this opt-out case asserts the DISABLED behavior")
			}

			By("creating a VaultPolicy")
			Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(mmOptOutPolicy))).To(Succeed())

			By("waiting for it to become Active")
			ExpectPolicyActive(ctx, mmOptOutPolicy)

			By("verifying NO managed marker was written to Vault")
			vc, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			// The metadata read returns nil data for an absent path.
			Consistently(func(g Gomega) {
				secret, readErr := vc.Read(ctx, markerMetadataPath(mmOptOutPolicy))
				g.Expect(readErr).NotTo(HaveOccurred())
				g.Expect(secret).To(BeNil(), "no marker should exist with markers disabled")
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

		It("TC-MM10: a hierarchical marker (custom_metadata) is written for an Active policy", func() {
			By("creating a VaultPolicy")
			Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(mmOnPolicy))).To(Succeed())

			By("waiting for it to become Active")
			ExpectPolicyActive(ctx, mmOnPolicy)

			By("verifying the marker exists as custom_metadata at the hierarchical path")
			vc, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				secret, readErr := vc.Read(ctx, markerMetadataPath(mmOnPolicy))
				g.Expect(readErr).NotTo(HaveOccurred())
				g.Expect(secret).NotTo(BeNil())
				cm, ok := secret.Data["custom_metadata"].(map[string]interface{})
				g.Expect(ok).To(BeTrue(), "expected custom_metadata block")
				g.Expect(cm["managed-by"]).To(Equal("vault-access-operator"))
				g.Expect(cm["k8s-resource"]).To(Equal(testNamespace + "/" + mmOnPolicy))
			}, 60*time.Second, 5*time.Second).Should(Succeed())
		})

		It("TC-MM13: a foreign marker blocks (Conflict), and adopt does not override it", func() {
			By("pre-seeding a foreign ownership marker at the policy's marker path")
			vc, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			_, err = vc.Write(ctx, markerMetadataPath(mmConflictPol), map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"managed-by":   "vault-access-operator",
					"k8s-resource": "other-ns/foreign-owner",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("also writing the policy so the existence check trips")
			Expect(vc.WritePolicy(ctx, testNamespace+"-"+mmConflictPol,
				`path "secret/*" { capabilities = ["read"] }`)).To(Succeed())

			By("creating the CR → expect a non-Active (Conflict) phase")
			Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(mmConflictPol))).To(Succeed())
			Eventually(func(g Gomega) {
				status, statusErr := utils.GetVaultPolicyStatus(ctx, mmConflictPol, testNamespace)
				g.Expect(statusErr).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Conflict"))
			}, 90*time.Second, 5*time.Second).Should(Succeed())

			By("adding the adopt annotation → still blocked: adopt never steals a resource a different marker owns")
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
		})
	})
})
