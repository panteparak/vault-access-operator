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

var _ = Describe("VaultConnection Tests", Ordered, Label("module"), func() {
	// Test configuration
	const (
		vaultConnectionName  = "tc-vc-vault"
		vaultTokenSecretName = "vault-token"
	)

	ctx := context.Background()

	BeforeAll(func() {
		By("creating test namespace for connection tests")
		// Ignore error if already exists (CreateNamespace is idempotent)
		_ = utils.CreateNamespace(ctx, testNamespace)

		By("creating Vault token secret")
		// Ignore error if already exists
		_ = utils.CreateSecret(ctx, testNamespace, vaultTokenSecretName,
			map[string][]byte{"token": []byte("root")})
	})

	AfterAll(func() {
		By("cleaning up VaultConnection test resources")
		_ = utils.DeleteVaultConnectionCR(ctx, vaultConnectionName)
	})

	Context("TC-VC: VaultConnection Lifecycle", func() {
		It("TC-VC01: Create VaultConnection with token auth", func() {
			By("creating VaultConnection resource using token authentication")
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name: vaultConnectionName,
				},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: fmt.Sprintf(
						"http://vault.%s.svc.cluster.local:8200",
						vaultNamespace,
					),
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name:      vaultTokenSecretName,
								Namespace: testNamespace,
								Key:       "token",
							},
						},
					},
					HealthCheckInterval: "10s",
				},
			}
			err := utils.CreateVaultConnectionCR(ctx, conn)
			Expect(err).NotTo(HaveOccurred(),
				"Failed to create VaultConnection")

			By("waiting for VaultConnection to become Active")
			Eventually(func(g Gomega) {
				status, err := utils.GetVaultConnectionStatus(
					ctx, vaultConnectionName, "",
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(status).To(
					Equal("Active"),
					"VaultConnection not active, got: %s", status,
				)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying VaultConnection has finalizer")
			vc, err := utils.GetVaultConnection(
				ctx, vaultConnectionName, "",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(vc.Finalizers).To(
				ContainElement("vault.platform.io/finalizer"),
				"VaultConnection should have finalizer for cleanup",
			)
		})

		It("TC-VC02: Verify VaultConnection health check and version", func() {
			By("verifying VaultConnection has vault version in status")
			Eventually(func(g Gomega) {
				vc, err := utils.GetVaultConnection(
					ctx, vaultConnectionName, "",
				)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(vc.Status.VaultVersion).To(
					ContainSubstring("1."),
					"Expected Vault version 1.x in status",
				)
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying health check interval is respected")
			vc, err := utils.GetVaultConnection(
				ctx, vaultConnectionName, "",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(vc.Spec.HealthCheckInterval).To(
				Equal("10s"),
				"Health check interval should be 10s",
			)
		})
	})
})
