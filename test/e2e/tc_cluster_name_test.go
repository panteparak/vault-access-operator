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
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/shared/naming"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// Naming-variant tests (ADR 0006 / ADR 0010). These exercise the operator's
// `--cluster-name` flag, which becomes the identity segment of every derived
// Vault resource name — vao.{cluster}.{namespace}.{name} — so multiple
// operators can share one Vault CE server without collisions.
//
// They require the operator to be deployed WITH `--cluster-name` set, which the
// default E2E stack is NOT. The expected identity is read from E2E_CLUSTER_NAME,
// set by the `e2e-local-test-cluster-name` target to the SAME value passed to
// the operator's flag (`make e2e-local-up-with-cluster-name`). When
// E2E_CLUSTER_NAME is empty (any normal run), the whole container skips — so
// these identity assertions never run against an operator that isn't
// configured with a cluster name, and the default suite is unaffected.
var _ = Describe("Cluster Name Identity", Ordered, Label("cluster-name"), func() {
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

	Context("TC-CN: cluster-name identity segment on Vault resource names", func() {
		It("TC-CN01: VaultPolicy is created in Vault under the cluster-identity name", func() {
			expectedName := utils.ExpectedVaultName(clusterPrefix, testNamespace, cnPolicyName)
			placeholderName := utils.ExpectedVaultName(naming.Placeholder, testNamespace, cnPolicyName)

			By("creating a VaultPolicy")
			Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(cnPolicyName))).To(Succeed())

			By("waiting for the VaultPolicy to become Active")
			ExpectPolicyActive(ctx, cnPolicyName)

			By("verifying status.vaultName carries the cluster identity")
			p, err := utils.GetVaultPolicy(ctx, cnPolicyName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Status.VaultName).To(Equal(expectedName),
				"status.vaultName should be vao.{cluster}.{namespace}.{name}")

			By("verifying the cluster-identity policy exists in Vault")
			ExpectPolicyInVault(ctx, expectedName)

			By("verifying the placeholder-identity name does NOT exist in Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			exists, err := vaultClient.PolicyExists(ctx, placeholderName)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeFalse(),
				"placeholder-identity policy %q must not exist — the cluster name did not take effect", placeholderName)
		})

		It("TC-CN02: VaultRole binds the cluster-identity policy name (token_policies)", func() {
			expectedRoleName := utils.ExpectedVaultName(clusterPrefix, testNamespace, cnRoleName)
			expectedPolicyName := utils.ExpectedVaultName(clusterPrefix, testNamespace, cnPolicyName)
			placeholderRoleName := utils.ExpectedVaultName(naming.Placeholder, testNamespace, cnRoleName)

			By("creating a VaultRole referencing the policy from TC-CN01")
			Expect(utils.CreateVaultRoleCR(ctx, BuildTestRole(cnRoleName, cnSAName, cnPolicyName))).To(Succeed())

			By("waiting for the VaultRole to become Active")
			ExpectRoleActive(ctx, cnRoleName)

			By("verifying status.vaultRoleName carries the cluster identity")
			r, err := utils.GetVaultRole(ctx, cnRoleName, testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Status.VaultRoleName).To(Equal(expectedRoleName))

			By("reading the role back from Vault at the cluster-identity name")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			var roleData map[string]interface{}
			Eventually(func(g Gomega) {
				var readErr error
				roleData, readErr = vaultClient.ReadAuthRole(ctx, "kubernetes", expectedRoleName)
				g.Expect(readErr).NotTo(HaveOccurred())
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying the placeholder-identity role name does NOT exist in Vault")
			exists, err := vaultClient.RoleExists(ctx, "kubernetes", placeholderRoleName)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeFalse(),
				"placeholder-identity role %q must not exist — the cluster name did not take effect", placeholderRoleName)

			By("verifying token_policies references the policy's full cluster-identity name")
			dataJSON, err := json.Marshal(roleData)
			Expect(err).NotTo(HaveOccurred())
			var roleConfig struct {
				Policies []string `json:"token_policies"`
			}
			Expect(json.Unmarshal(dataJSON, &roleConfig)).To(Succeed())
			Expect(roleConfig.Policies).To(ContainElement(expectedPolicyName),
				"role token_policies must reference the cluster-identity policy name, not a placeholder-identity one")
		})
	})
})
