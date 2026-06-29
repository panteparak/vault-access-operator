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
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/test/utils"
)

// Cluster-name prefix tests (ADR 0006). These exercise the operator's
// `--cluster-name` flag, which prefixes every derived Vault resource name so
// multiple operators can share one Vault CE server without collisions.
//
// They require the operator to be deployed WITH `--cluster-name` set, which the
// default E2E stack is NOT. The expected prefix is read from E2E_CLUSTER_NAME,
// set by the `e2e-local-test-cluster-name` target to the SAME value passed to
// the operator's flag (`make e2e-local-up-with-cluster-name`). When
// E2E_CLUSTER_NAME is empty (any normal run), the whole container skips — so
// these prefixed-name assertions never run against an operator that isn't
// prefixing, and the default suite is unaffected.
var _ = Describe("Cluster Name Prefix", Ordered, Label("cluster-name"), func() {
	const (
		cnPolicyName = "tc-cn-policy"
		cnRoleName   = "tc-cn-role"
		cnSAName     = "tc-cn-sa"
	)

	ctx := context.Background()
	var clusterPrefix string

	BeforeAll(func() {
		clusterPrefix = os.Getenv("E2E_CLUSTER_NAME")
		if clusterPrefix == "" {
			Skip("E2E_CLUSTER_NAME not set: the operator is not deployed with --cluster-name. " +
				"Run `make e2e-local-up-with-cluster-name e2e-local-test-cluster-name`.")
		}
		RefreshSharedVaultToken(ctx)

		By("creating a service account for the cluster-name role test")
		_ = utils.CreateServiceAccount(ctx, testNamespace, cnSAName)
	})

	AfterAll(func() {
		if clusterPrefix == "" {
			return // container was skipped — nothing was created
		}
		By("cleaning up cluster-name test resources")
		_ = utils.DeleteVaultRoleCR(ctx, cnRoleName, testNamespace)
		_ = utils.DeleteVaultPolicyCR(ctx, cnPolicyName, testNamespace)
		_ = utils.DeleteServiceAccount(ctx, testNamespace, cnSAName)
	})

	Context("TC-CN: cluster-name prefix on Vault resource names", func() {
		It("TC-CN01: VaultPolicy is created in Vault under the cluster-prefixed name", func() {
			prefixedName := fmt.Sprintf("%s-%s-%s", clusterPrefix, testNamespace, cnPolicyName)
			unprefixedName := fmt.Sprintf("%s-%s", testNamespace, cnPolicyName)

			By("creating a VaultPolicy")
			Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(cnPolicyName))).To(Succeed())

			By("waiting for the VaultPolicy to become Active")
			ExpectPolicyActive(ctx, cnPolicyName)

			By("verifying status.vaultName carries the cluster prefix")
			p, err := utils.GetVaultPolicy(ctx, cnPolicyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Status.VaultName).To(Equal(prefixedName),
				"status.vaultName should be {cluster}-{namespace}-{name}")

			By("verifying the prefixed policy exists in Vault")
			ExpectPolicyInVault(ctx, prefixedName)

			By("verifying the UNprefixed name does NOT exist in Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			exists, err := vaultClient.PolicyExists(ctx, unprefixedName)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeFalse(),
				"unprefixed policy %q must not exist — the cluster prefix did not take effect", unprefixedName)
		})

		It("TC-CN02: VaultRole binds the cluster-prefixed policy name (token_policies)", func() {
			prefixedRoleName := fmt.Sprintf("%s-%s-%s", clusterPrefix, testNamespace, cnRoleName)
			prefixedPolicyName := fmt.Sprintf("%s-%s-%s", clusterPrefix, testNamespace, cnPolicyName)

			By("creating a VaultRole referencing the policy from TC-CN01")
			Expect(utils.CreateVaultRoleCR(ctx, BuildTestRole(cnRoleName, cnSAName, cnPolicyName))).To(Succeed())

			By("waiting for the VaultRole to become Active")
			ExpectRoleActive(ctx, cnRoleName)

			By("verifying status.vaultRoleName carries the cluster prefix")
			r, err := utils.GetVaultRole(ctx, cnRoleName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Status.VaultRoleName).To(Equal(prefixedRoleName))

			By("reading the role back from Vault at the prefixed name")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			var roleData map[string]interface{}
			Eventually(func(g Gomega) {
				var readErr error
				roleData, readErr = vaultClient.ReadAuthRole(ctx, "kubernetes", prefixedRoleName)
				g.Expect(readErr).NotTo(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying token_policies references the PREFIXED policy name (linkage survives prefixing)")
			dataJSON, err := json.Marshal(roleData)
			Expect(err).NotTo(HaveOccurred())
			var roleConfig struct {
				Policies []string `json:"token_policies"`
			}
			Expect(json.Unmarshal(dataJSON, &roleConfig)).To(Succeed())
			Expect(roleConfig.Policies).To(ContainElement(prefixedPolicyName),
				"role token_policies must reference the cluster-prefixed policy name, not the bare {ns}-{name}")
		})
	})
})
