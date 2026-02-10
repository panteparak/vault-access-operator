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

var _ = Describe("Authentication Tests", Ordered, Label("auth"), func() {
	const (
		authSAName     = "tc-au-sa"
		authPolicyName = "tc-au-policy"
		authRoleName   = "tc-au-role"
	)

	ctx := context.Background()

	BeforeAll(func() {
		By("creating test service account for auth tests")
		_ = utils.CreateServiceAccount(
			ctx, testNamespace, authSAName,
		)

		By("creating VaultPolicy for auth tests")
		policy := &vaultv1alpha1.VaultPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      authPolicyName,
				Namespace: testNamespace,
			},
			Spec: vaultv1alpha1.VaultPolicySpec{
				ConnectionRef: sharedVaultConnectionName,
				Rules: []vaultv1alpha1.PolicyRule{
					{
						Path: "secret/data/auth-test/*",
						Capabilities: []vaultv1alpha1.Capability{
							vaultv1alpha1.CapabilityRead,
						},
					},
				},
			},
		}
		err := utils.CreateVaultPolicyCR(ctx, policy)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for auth test policy to become Active")
		Eventually(func(g Gomega) {
			status, err := utils.GetVaultPolicyStatus(
				ctx, authPolicyName, testNamespace,
			)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(status).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("creating VaultRole for auth tests")
		role := &vaultv1alpha1.VaultRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:      authRoleName,
				Namespace: testNamespace,
			},
			Spec: vaultv1alpha1.VaultRoleSpec{
				ConnectionRef:   sharedVaultConnectionName,
				ServiceAccounts: []string{authSAName},
				Policies: []vaultv1alpha1.PolicyReference{
					{
						Kind:      "VaultPolicy",
						Name:      authPolicyName,
						Namespace: testNamespace,
					},
				},
				TokenTTL: "5m",
			},
		}
		err = utils.CreateVaultRoleCR(ctx, role)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for auth role to become Active")
		Eventually(func(g Gomega) {
			status, err := utils.GetVaultRoleStatus(
				ctx, authRoleName, testNamespace,
			)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(status).To(Equal("Active"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterAll(func() {
		By("cleaning up authentication test resources")
		_ = utils.DeleteVaultRoleCR(
			ctx, authRoleName, testNamespace,
		)
		_ = utils.DeleteVaultPolicyCR(
			ctx, authPolicyName, testNamespace,
		)
		_ = utils.DeleteServiceAccount(
			ctx, testNamespace, authSAName,
		)
	})

	Context("TC-AU01: Service Account Authentication", func() {
		It("TC-AU01-01: Allow bound service account "+
			"to authenticate with Vault", func() {
			expectedPolicyName := fmt.Sprintf(
				"%s-%s", testNamespace, authPolicyName,
			)
			expectedRoleName := fmt.Sprintf(
				"%s-%s", testNamespace, authRoleName,
			)

			By("getting a JWT token for the service account")
			saToken, err :=
				utils.CreateServiceAccountTokenClientGo(
					ctx, testNamespace, authSAName,
				)
			Expect(err).NotTo(HaveOccurred())
			Expect(saToken).NotTo(BeEmpty(),
				"SA token should not be empty")

			By("logging in to Vault with the SA JWT")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				secret, loginErr := vaultClient.Write(
					ctx,
					"auth/kubernetes/login",
					map[string]interface{}{
						"role": expectedRoleName,
						"jwt":  saToken,
					},
				)
				g.Expect(loginErr).NotTo(HaveOccurred(),
					"Vault login should succeed")
				g.Expect(secret).NotTo(BeNil())
				g.Expect(secret.Auth).NotTo(BeNil())

				g.Expect(
					secret.Auth.ClientToken,
				).NotTo(BeEmpty(),
					"Should receive a Vault client token")

				g.Expect(
					secret.Auth.Policies,
				).To(ContainElement(expectedPolicyName),
					"Token should have auth test policy")

				// tokenTTL "5m" = 300 seconds
				g.Expect(
					secret.Auth.LeaseDuration,
				).To(Equal(300),
					"Token lease should be 300s (5m)")
			}, 30*time.Second, 2*time.Second).Should(
				Succeed(),
			)
		})

		It("TC-AU01-02: Reject authentication with "+
			"incorrect service account", func() {
			wrongSAName := "tc-au02-wrong-sa"
			expectedRoleName := fmt.Sprintf(
				"%s-%s", testNamespace, authRoleName,
			)

			By("creating a SA NOT bound to the role")
			_ = utils.CreateServiceAccount(
				ctx, testNamespace, wrongSAName,
			)

			By("getting a JWT for the wrong SA")
			wrongToken, err :=
				utils.CreateServiceAccountTokenClientGo(
					ctx, testNamespace, wrongSAName,
				)
			Expect(err).NotTo(HaveOccurred())
			Expect(wrongToken).NotTo(BeEmpty())

			By("attempting Vault login with wrong SA JWT")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			_, err = vaultClient.LoginKubernetes(
				ctx, "kubernetes",
				expectedRoleName, wrongToken,
			)
			Expect(err).To(HaveOccurred(),
				"Login should fail with unbound SA")

			By("cleaning up wrong service account")
			_ = utils.DeleteServiceAccount(
				ctx, testNamespace, wrongSAName,
			)
		})

		It("TC-AU01-03: Reject authentication with "+
			"invalid JWT token", func() {
			expectedRoleName := fmt.Sprintf(
				"%s-%s", testNamespace, authRoleName,
			)

			By("attempting Vault login with invalid JWT")
			invalidJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6" +
				"IkpXVCJ9.invalid.token"
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			_, err = vaultClient.LoginKubernetes(
				ctx, "kubernetes",
				expectedRoleName, invalidJWT,
			)
			Expect(err).To(HaveOccurred(),
				"Login should fail with invalid JWT")
		})

		It("TC-AU01-04: Successfully re-authenticate "+
			"after token expiration", func() {
			expectedRoleName := fmt.Sprintf(
				"%s-%s", testNamespace, authRoleName,
			)

			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			By("getting initial service account token")
			saToken, err :=
				utils.CreateServiceAccountTokenClientGo(
					ctx, testNamespace, authSAName,
				)
			Expect(err).NotTo(HaveOccurred())

			By("performing initial Vault authentication")
			initialToken, err :=
				vaultClient.LoginKubernetes(
					ctx, "kubernetes",
					expectedRoleName, saToken,
				)
			Expect(err).NotTo(HaveOccurred())
			Expect(initialToken).NotTo(BeEmpty())

			By("revoking the token to simulate expiration")
			err = vaultClient.RevokeToken(
				ctx, initialToken,
			)
			Expect(err).NotTo(HaveOccurred())

			By("verifying revoked token is invalid")
			_, err = vaultClient.TokenLookupSelfWithToken(
				ctx, initialToken,
			)
			Expect(err).To(HaveOccurred(),
				"Revoked token should not be valid")

			By("re-authenticating with a fresh SA token")
			newSAToken, err :=
				utils.CreateServiceAccountTokenClientGo(
					ctx, testNamespace, authSAName,
				)
			Expect(err).NotTo(HaveOccurred())

			newToken, err := vaultClient.LoginKubernetes(
				ctx, "kubernetes",
				expectedRoleName, newSAToken,
			)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the new token is valid")
			Expect(newToken).NotTo(BeEmpty())
			Expect(newToken).NotTo(Equal(initialToken),
				"Re-auth should produce a different token")
		})

		It("TC-AU01-05: Verify multiple SAs can "+
			"authenticate to the same role", func() {
			additionalSAName := "tc-au01-05-additional-sa"
			expectedRoleName := fmt.Sprintf(
				"%s-%s", testNamespace, authRoleName,
			)

			By("creating an additional service account")
			err := utils.CreateServiceAccount(
				ctx, testNamespace, additionalSAName,
			)
			Expect(err).NotTo(HaveOccurred())

			By("updating VaultRole to include both SAs")
			err = utils.UpdateVaultRoleCR(
				ctx, authRoleName, testNamespace,
				func(r *vaultv1alpha1.VaultRole) {
					r.Spec.ServiceAccounts = []string{
						authSAName,
						additionalSAName,
					}
				},
			)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for role update to propagate to Vault")
			Eventually(func(g Gomega) {
				r, err := utils.GetVaultRole(
					ctx, authRoleName, testNamespace,
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(r.Status.Phase).To(Equal(
					vaultv1alpha1.PhaseActive,
				))
				g.Expect(r.Status.BoundServiceAccounts).To(
					ContainElement(fmt.Sprintf(
						"%s/%s", testNamespace,
						additionalSAName,
					)),
				)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())

			By("authenticating with the original SA")
			saToken, err :=
				utils.CreateServiceAccountTokenClientGo(
					ctx, testNamespace, authSAName,
				)
			Expect(err).NotTo(HaveOccurred())
			_, err = vaultClient.LoginKubernetes(
				ctx, "kubernetes",
				expectedRoleName, saToken,
			)
			Expect(err).NotTo(HaveOccurred(),
				"Original SA should still authenticate")

			By("authenticating with the additional SA")
			addToken, err :=
				utils.CreateServiceAccountTokenClientGo(
					ctx, testNamespace, additionalSAName,
				)
			Expect(err).NotTo(HaveOccurred())
			_, err = vaultClient.LoginKubernetes(
				ctx, "kubernetes",
				expectedRoleName, addToken,
			)
			Expect(err).NotTo(HaveOccurred(),
				"Additional SA should authenticate")

			By("cleaning up the additional SA")
			_ = utils.DeleteServiceAccount(
				ctx, testNamespace, additionalSAName,
			)
		})
	})
})
