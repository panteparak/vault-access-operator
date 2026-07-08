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
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Pre-ADR-0010, this file asserted webhook DENIAL of "{namespace}-{name}"
// dash-join collisions. The fixed 4-segment name shape
// vao.{identity}.{namespace}.{name} is injective, so those collisions are
// structurally impossible — the checks were deleted, and this TC now proves
// the OPPOSITE contract: formerly-colliding CR pairs are admitted and
// coexist in Vault under distinct names.
var _ = Describe("Naming Injectivity Tests", Ordered, Label("collision"), func() {
	ctx := context.Background()

	It("TC-COLLISION01: formerly-colliding VaultPolicy and VaultClusterPolicy coexist", func() {
		policyName := uniqueName("tc-col01")
		// The exact cluster-policy name that collided under the old scheme:
		// "{namespace}-{name}" of the namespaced policy.
		clusterPolicyName := testNamespace + "-" + policyName

		By("creating the namespaced VaultPolicy")
		policy := BuildTestPolicy(policyName)
		Expect(utils.CreateVaultPolicyCR(ctx, policy)).To(Succeed())
		DeferCleanup(func() { CleanupPolicy(ctx, policyName) })
		ExpectPolicyActive(ctx, policyName)

		By("creating the VaultClusterPolicy that used to collide — must be ADMITTED")
		clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: clusterPolicyName},
			Spec: vaultv1alpha1.VaultClusterPolicySpec{
				ConnectionRef: sharedVaultConnectionName,
				Rules: []vaultv1alpha1.PolicyRule{
					{
						Path:         "secret/data/tc-col01/*",
						Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
					},
				},
			},
		}
		Expect(utils.CreateVaultClusterPolicyCR(ctx, clusterPolicy)).To(Succeed(),
			"ADR 0010: formerly-colliding pair must be admitted")
		DeferCleanup(func() { _ = utils.DeleteVaultClusterPolicyCR(ctx, clusterPolicyName) })

		By("waiting for the VaultClusterPolicy to become Active")
		Eventually(func(g Gomega) {
			status, err := utils.GetVaultClusterPolicyStatus(ctx, clusterPolicyName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(status).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying both objects exist in Vault under DISTINCT names")
		nsVault := nsVaultName(policyName)
		clusterVault := clusterVaultName(clusterPolicyName)
		Expect(nsVault).NotTo(Equal(clusterVault),
			"the two derived names must differ — that is the injectivity contract")
		ExpectPolicyInVault(ctx, nsVault)
		ExpectPolicyInVault(ctx, clusterVault)
	})
})
