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
	"encoding/json"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// TC-PB: role→policy binding resolves via the referenced policy CR's
// RECORDED status.vaultName (ADR 0010). A role that references a policy CR
// which doesn't exist yet must surface the pending dependency
// (PoliciesResolved=False → Ready=False, policyBindings[].resolved=false),
// sync with the resolved subset, and converge via watch once the policy
// lands — no manual nudge.
var _ = Describe("Pending Policy Binding Tests", Ordered, Label("module"), func() {
	const (
		pbRoleName   = "tc-pb01-role"
		pbPolicyName = "tc-pb01-policy"
		pbSAName     = "tc-pb01-sa"
	)

	ctx := context.Background()

	BeforeAll(func() {
		RefreshSharedVaultToken(ctx)

		By("creating test service account for pending-binding tests")
		_ = utils.CreateServiceAccount(ctx, testNamespace, pbSAName)
	})

	AfterAll(func() {
		By("cleaning up pending-binding test resources")
		_ = utils.DeleteVaultRoleCR(ctx, pbRoleName, testNamespace)
		_ = utils.DeleteVaultPolicyCR(ctx, pbPolicyName, testNamespace)
		_ = utils.DeleteServiceAccount(ctx, testNamespace, pbSAName)
	})

	Context("TC-PB: role referencing a not-yet-existing policy", func() {
		It("TC-PB01: role reports the pending binding, then converges when the policy lands", func() {
			By("creating a VaultRole referencing a policy that does NOT exist yet")
			Expect(utils.CreateVaultRoleCR(ctx,
				BuildTestRole(pbRoleName, pbSAName, pbPolicyName))).To(Succeed())

			By("waiting for the role to surface the unresolved dependency")
			Eventually(func(g Gomega) {
				r, err := utils.GetVaultRole(ctx, pbRoleName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())

				expectCondition(g, r.Status.Conditions,
					vaultv1alpha1.ConditionTypePoliciesResolved, metav1.ConditionFalse)
				expectCondition(g, r.Status.Conditions,
					vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse)

				b := findPolicyBinding(r.Status.PolicyBindings, pbPolicyName)
				g.Expect(b).NotTo(BeNil(),
					"status.policyBindings should have an entry for %q; got %+v",
					pbPolicyName, r.Status.PolicyBindings)
				g.Expect(b.Resolved).To(BeFalse(),
					"binding for the missing policy must report resolved=false")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("creating the referenced policy")
			Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(pbPolicyName))).To(Succeed())
			ExpectPolicyActive(ctx, pbPolicyName)

			By("reading the policy's recorded Vault name")
			p, err := utils.GetVaultPolicy(ctx, pbPolicyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Status.VaultName).NotTo(BeEmpty())
			policyVaultName := p.Status.VaultName

			By("waiting for the role to converge via the policy watch")
			Eventually(func(g Gomega) {
				r, err := utils.GetVaultRole(ctx, pbRoleName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())

				expectCondition(g, r.Status.Conditions,
					vaultv1alpha1.ConditionTypePoliciesResolved, metav1.ConditionTrue)
				expectCondition(g, r.Status.Conditions,
					vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue)

				b := findPolicyBinding(r.Status.PolicyBindings, pbPolicyName)
				g.Expect(b).NotTo(BeNil())
				g.Expect(b.Resolved).To(BeTrue(),
					"binding must flip to resolved=true once the policy syncs")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying Vault's token_policies contains the policy's recorded name")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				roleData, readErr := vaultClient.ReadAuthRole(
					ctx, "kubernetes", nsVaultName(pbRoleName))
				g.Expect(readErr).NotTo(HaveOccurred())

				dataJSON, marshalErr := json.Marshal(roleData)
				g.Expect(marshalErr).NotTo(HaveOccurred())
				var roleConfig struct {
					Policies []string `json:"token_policies"`
				}
				g.Expect(json.Unmarshal(dataJSON, &roleConfig)).To(Succeed())
				g.Expect(roleConfig.Policies).To(ContainElement(policyVaultName),
					"token_policies must carry the policy's status.vaultName")
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})
	})
})

// expectCondition asserts that the condition of the given type exists and has
// the expected status.
func expectCondition(
	g Gomega,
	conds []vaultv1alpha1.Condition,
	condType string,
	expected metav1.ConditionStatus,
) {
	for _, c := range conds {
		if c.Type == condType {
			g.Expect(c.Status).To(Equal(expected),
				"condition %s should be %s (reason=%q message=%q)",
				condType, expected, c.Reason, c.Message)
			return
		}
	}
	g.Expect(false).To(BeTrue(), "condition %s not found in %+v", condType, conds)
}

// findPolicyBinding returns the status.policyBindings entry whose K8sRef
// names the given policy, or nil.
func findPolicyBinding(
	bindings []vaultv1alpha1.PolicyBinding, policyName string,
) *vaultv1alpha1.PolicyBinding {
	for i := range bindings {
		if strings.Contains(bindings[i].K8sRef, policyName) {
			return &bindings[i]
		}
	}
	return nil
}
