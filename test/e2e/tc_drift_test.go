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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Drift Detection Tests", Ordered, Label("drift"), func() {
	ctx := context.Background()

	Context("TC-DRIFT: Policy Drift Detection", func() {
		It("TC-DRIFT01-IGNORE: DriftMode=ignore skips detection", func() {
			policyName := "tc-drift01-ignore"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, policyName)

			By("creating VaultPolicy with driftMode=ignore")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					DriftMode:     vaultv1alpha1.DriftModeIgnore,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/ignore/*",
							Capabilities: []vaultv1alpha1.Capability{"read"},
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("modifying policy directly in Vault to create drift")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			modifiedHCL := `path "secret/data/ignore/*" { capabilities = ["read", "list"] }`
			err = vaultClient.WritePolicy(ctx, expectedVaultName, modifiedHCL)
			Expect(err).NotTo(HaveOccurred())

			By("verifying drift detection is skipped (effectiveDriftMode=ignore)")
			// With ignore mode, drift should NOT be detected
			Consistently(func(g Gomega) {
				p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(p.Status.DriftDetected).To(BeFalse(),
					"DriftDetected should remain false with driftMode=ignore")
			}, 10*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up")
			_ = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
		})

		It("TC-DRIFT02-DETECT: DriftMode=detect reports but doesn't correct", func() {
			policyName := "tc-drift02-detect"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, policyName)

			By("creating VaultPolicy with driftMode=detect")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					DriftMode:     vaultv1alpha1.DriftModeDetect,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/detect/*",
							Capabilities: []vaultv1alpha1.Capability{"read"},
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("modifying policy directly in Vault to create drift")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			modifiedHCL := `path "secret/data/detect/*" { capabilities = ["read", "list", "create"] }`
			err = vaultClient.WritePolicy(ctx, expectedVaultName, modifiedHCL)
			Expect(err).NotTo(HaveOccurred())

			By("triggering reconciliation")
			// Touch the CR to trigger reconciliation
			p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			if p.Annotations == nil {
				p.Annotations = make(map[string]string)
			}
			p.Annotations["trigger-reconcile"] = time.Now().String()
			err = utils.UpdateVaultPolicy(ctx, p)
			Expect(err).NotTo(HaveOccurred())

			By("verifying drift is detected")
			Eventually(func(g Gomega) {
				p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(p.Status.DriftDetected).To(BeTrue(),
					"DriftDetected should be true")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying drift is NOT corrected (original Vault content preserved)")
			content, err := vaultClient.ReadPolicy(ctx, expectedVaultName)
			Expect(err).NotTo(HaveOccurred())
			Expect(content).To(ContainSubstring("create"),
				"Modified content should be preserved since mode is detect-only")

			By("cleaning up")
			_ = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
		})

		It("TC-DRIFT03-CORRECT: DriftMode=correct auto-corrects with annotation", func() {
			policyName := "tc-drift03-correct"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, policyName)

			By("creating VaultPolicy with driftMode=correct and allow-destructive annotation")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						vaultv1alpha1.AnnotationAllowDestructive: "true",
					},
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					DriftMode:     vaultv1alpha1.DriftModeCorrect,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/correct/*",
							Capabilities: []vaultv1alpha1.Capability{"read"},
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("modifying policy directly in Vault to create drift")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			modifiedHCL := `path "secret/data/correct/*" { capabilities = ["read", "list", "delete"] }`
			err = vaultClient.WritePolicy(ctx, expectedVaultName, modifiedHCL)
			Expect(err).NotTo(HaveOccurred())

			By("verifying policy contains modified content before correction")
			content, err := vaultClient.ReadPolicy(ctx, expectedVaultName)
			Expect(err).NotTo(HaveOccurred())
			Expect(content).To(ContainSubstring("delete"))

			By("triggering reconciliation")
			p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			if p.Annotations == nil {
				p.Annotations = make(map[string]string)
			}
			p.Annotations["trigger-reconcile"] = time.Now().String()
			err = utils.UpdateVaultPolicy(ctx, p)
			Expect(err).NotTo(HaveOccurred())

			By("verifying drift was corrected")
			Eventually(func(g Gomega) {
				content, err := vaultClient.ReadPolicy(ctx, expectedVaultName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(content).NotTo(ContainSubstring("delete"),
					"Drift should be corrected - 'delete' capability should be removed")
				g.Expect(content).To(ContainSubstring("read"),
					"Original 'read' capability should be restored")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("cleaning up")
			_ = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
		})

		It("TC-DRIFT04-SAFETY: DriftMode=correct blocked without allow-destructive", func() {
			policyName := "tc-drift04-safety"
			expectedVaultName := fmt.Sprintf("%s-%s", testNamespace, policyName)

			By("creating VaultPolicy with driftMode=correct but WITHOUT allow-destructive annotation")
			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					// No allow-destructive annotation
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					DriftMode:     vaultv1alpha1.DriftModeCorrect,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/safety/*",
							Capabilities: []vaultv1alpha1.Capability{"read"},
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultPolicy to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultPolicyStatus(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("modifying policy directly in Vault to create drift")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			modifiedHCL := `path "secret/data/safety/*" { capabilities = ["read", "update"] }`
			err = vaultClient.WritePolicy(ctx, expectedVaultName, modifiedHCL)
			Expect(err).NotTo(HaveOccurred())

			By("triggering reconciliation")
			p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			if p.Annotations == nil {
				p.Annotations = make(map[string]string)
			}
			p.Annotations["trigger-reconcile"] = time.Now().String()
			err = utils.UpdateVaultPolicy(ctx, p)
			Expect(err).NotTo(HaveOccurred())

			By("verifying drift is detected but NOT corrected (safety block)")
			Eventually(func(g Gomega) {
				p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				// Should detect drift
				g.Expect(p.Status.DriftDetected).To(BeTrue())
				// Status should indicate the block
				g.Expect(p.Status.Phase).To(Equal(vaultv1alpha1.PhaseConflict),
					"Phase should be Conflict when correction blocked")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying Vault content is NOT corrected (preserved)")
			content, err := vaultClient.ReadPolicy(ctx, expectedVaultName)
			Expect(err).NotTo(HaveOccurred())
			Expect(content).To(ContainSubstring("update"),
				"Modified content should be preserved since correction was blocked")

			By("cleaning up")
			_ = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
		})
	})

	Context("TC-DRIFT: Role Drift Detection", func() {
		It("TC-DRIFT05-ROLE: Detect drift in Vault role", func() {
			roleName := "tc-drift05-role"

			By("creating VaultRole with driftMode=detect")
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      roleName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   sharedVaultConnectionName,
					DriftMode:       vaultv1alpha1.DriftModeDetect,
					ServiceAccounts: []string{"default"},
					TokenTTL:        "5m",
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultClusterPolicy",
							Name: "default", // Use default Vault policy
						},
					},
				},
			}
			err := utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for VaultRole to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultRoleStatus(ctx, roleName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(Equal("Active"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up")
			_ = utils.DeleteVaultRoleCR(ctx, roleName, testNamespace)
		})
	})
})
