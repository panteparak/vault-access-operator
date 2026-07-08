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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// TC-RM: roles carry no mount fields — the referenced VaultConnection is the
// sole source of the auth mount. A connection whose login has no role-capable
// mount (token, no defaults.authPath) must fail roles loudly: webhook denial
// when webhooks are enabled, permanent ValidationFailed status otherwise.
var _ = Describe("VaultRole mount resolution Tests", Ordered, Label("module"), func() {
	ctx := context.Background()

	const (
		mountlessConnName = "tc-rm-mountless-connection"
		roleName          = "tc-rm-role"
	)

	BeforeAll(func() {
		By("creating a token-auth VaultConnection WITHOUT defaults.authPath")
		conn := &vaultv1alpha1.VaultConnection{
			ObjectMeta: metav1.ObjectMeta{Name: mountlessConnName},
			Spec: vaultv1alpha1.VaultConnectionSpec{
				Address: vaultK8sAddr,
				Auth: vaultv1alpha1.AuthConfig{
					Token: &vaultv1alpha1.TokenAuth{
						SecretRef: vaultv1alpha1.SecretKeySelector{
							Name:      sharedVaultTokenSecretName,
							Namespace: testNamespace,
							Key:       "token",
						},
					},
				},
				HealthCheckInterval: "10s",
			},
		}
		Expect(utils.CreateVaultConnectionCR(ctx, conn)).To(Succeed())
	})

	AfterAll(func() {
		_ = utils.DeleteVaultRoleCR(ctx, roleName, testNamespace)
		_ = utils.DeleteVaultConnectionCR(ctx, mountlessConnName)
	})

	Context("TC-RM01: role on a role-incapable connection fails loudly", func() {
		It("should deny at admission or reach ValidationFailed at reconcile", func() {
			role := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      roleName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   mountlessConnName,
					ServiceAccounts: []string{"default"},
					Policies: []vaultv1alpha1.PolicyReference{
						{Kind: "VaultPolicy", Name: "tc-rm-nonexistent-policy"},
					},
				},
			}

			err := utils.CreateVaultRoleCR(ctx, role)
			if err != nil {
				// Webhook-enabled stack: denied at admission with the
				// role-capable-mount message.
				Expect(err.Error()).To(ContainSubstring("role-capable"),
					"admission denial should name the missing role mount")
				return
			}

			// Webhook-less stack: the reconcile backstop must park the CR in
			// a permanent error naming the connection problem, and never
			// write to Vault.
			Eventually(func(g Gomega) {
				r, err := utils.GetVaultRole(ctx, roleName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(string(r.Status.Phase)).To(Equal("Error"))
				g.Expect(strings.ToLower(r.Status.Message)).To(
					ContainSubstring("role-capable"),
					"status message should name the missing role mount")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})
