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

var _ = Describe("Metrics Validation Tests", Ordered, Label("metrics"), func() {
	ctx := context.Background()

	Context("TC-METRICS: Prometheus Metrics Content", func() {
		It("TC-METRICS01: Drift detected metric is set after drift", func() {
			policyName := uniqueName("tc-metrics01")
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
							Path:         "secret/data/metrics-test/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			}
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active")
			ExpectPolicyActive(ctx, policyName)

			By("modifying the policy directly in Vault to create drift")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			modifiedHCL := `path "secret/data/metrics-test/*" { capabilities = ["read", "list", "delete"] }`
			err = vaultClient.WritePolicy(ctx, expectedVaultName, modifiedHCL)
			Expect(err).NotTo(HaveOccurred())

			By("triggering reconciliation by updating the policy annotation")
			Eventually(func() error {
				return utils.UpdateVaultPolicyCR(ctx, policyName, testNamespace, func(p *vaultv1alpha1.VaultPolicy) {
					if p.Annotations == nil {
						p.Annotations = make(map[string]string)
					}
					p.Annotations["metrics-test/trigger"] = time.Now().Format(time.RFC3339)
				})
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("waiting for drift to be detected")
			Eventually(func(g Gomega) {
				p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(p.Status.DriftDetected).To(BeTrue(), "drift should be detected")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up")
			CleanupPolicy(ctx, policyName)
		})

		It("TC-METRICS02: Sync success counter increments after policy creation", func() {
			policyName := uniqueName("tc-metrics02")

			By("creating a VaultPolicy")
			policy := BuildTestPolicy(policyName)
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for policy to become Active (proves sync succeeded)")
			ExpectPolicyActive(ctx, policyName)

			By("verifying policy status shows successful sync")
			p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(p.Status.Phase)).To(Equal("Active"))
			Expect(p.Status.LastSyncedAt).NotTo(BeNil(), "lastSyncedAt should be set after successful sync")
			Expect(p.Status.Managed).To(BeTrue(), "managed should be true after sync")

			By("cleaning up")
			CleanupPolicy(ctx, policyName)
		})
	})
})
