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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

var _ = Describe("VaultKVSecret Tests", Ordered, Label("module"), func() {
	const (
		seedName   = "tc-kvs-seed"
		retainName = "tc-kvs-retain"
	)

	ctx := context.Background()

	var (
		k8s        client.Client
		seedPath   string
		retainPath string
	)

	BeforeAll(func() {
		RefreshSharedVaultToken(ctx)
		var err error
		k8s, err = utils.GetK8sClient()
		Expect(err).NotTo(HaveOccurred())
		seedPath = fmt.Sprintf("secret/data/%s/tc-kvs01", testNamespace)
		retainPath = fmt.Sprintf("secret/data/%s/tc-kvs02", testNamespace)
	})

	AfterAll(func() {
		By("cleaning up VaultKVSecret test resources")
		_ = k8s.Delete(ctx, &vaultv1alpha1.VaultKVSecret{
			ObjectMeta: metav1.ObjectMeta{Name: seedName, Namespace: testNamespace},
		})
		_ = k8s.Delete(ctx, &vaultv1alpha1.VaultKVSecret{
			ObjectMeta: metav1.ObjectMeta{Name: retainName, Namespace: testNamespace},
		})
	})

	Context("TC-KVS: VaultKVSecret seeding lifecycle", func() {
		It("TC-KVS01: seeds an empty KV path so consumers can read it", func() {
			By("creating a VaultKVSecret with placeholder keys")
			kvs := &vaultv1alpha1.VaultKVSecret{
				ObjectMeta: metav1.ObjectMeta{Name: seedName, Namespace: testNamespace},
				Spec: vaultv1alpha1.VaultKVSecretSpec{
					ConnectionRef: sharedVaultConnectionName,
					Path:          seedPath,
					Data:          map[string]string{"username": "", "password": ""},
				},
			}
			Expect(k8s.Create(ctx, kvs)).To(Succeed())

			By("waiting for it to become Active and seeded")
			Eventually(func(g Gomega) {
				got := &vaultv1alpha1.VaultKVSecret{}
				g.Expect(k8s.Get(ctx, client.ObjectKey{Name: seedName, Namespace: testNamespace}, got)).To(Succeed())
				g.Expect(string(got.Status.Phase)).To(Equal("Active"), "phase not Active")
				g.Expect(got.Status.Seeded).To(BeTrue(), "status.seeded should be true")
				g.Expect(got.Status.SeededVersion).To(Equal(1))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the path now exists in Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				secret, err := vaultClient.Read(ctx, seedPath)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(secret).NotTo(BeNil(), "seeded path should be readable")
			}, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("TC-KVS02: retains a secret written to since seeding (delete-if-untouched)", func() {
			By("creating a VaultKVSecret")
			kvs := &vaultv1alpha1.VaultKVSecret{
				ObjectMeta: metav1.ObjectMeta{Name: retainName, Namespace: testNamespace},
				Spec: vaultv1alpha1.VaultKVSecretSpec{
					ConnectionRef: sharedVaultConnectionName,
					Path:          retainPath,
				},
			}
			Expect(k8s.Create(ctx, kvs)).To(Succeed())

			By("waiting for it to be seeded")
			Eventually(func(g Gomega) {
				got := &vaultv1alpha1.VaultKVSecret{}
				g.Expect(k8s.Get(ctx, client.ObjectKey{Name: retainName, Namespace: testNamespace}, got)).To(Succeed())
				g.Expect(got.Status.Seeded).To(BeTrue())
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("writing real data to the path (simulating ESO/user), bumping the version")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			_, err = vaultClient.Write(ctx, retainPath, map[string]interface{}{
				"data": map[string]interface{}{"password": "s3cr3t-real"},
			})
			Expect(err).NotTo(HaveOccurred())

			By("deleting the VaultKVSecret")
			Expect(k8s.Delete(ctx, kvs)).To(Succeed())
			Eventually(func(g Gomega) {
				got := &vaultv1alpha1.VaultKVSecret{}
				err := k8s.Get(ctx, client.ObjectKey{Name: retainName, Namespace: testNamespace}, got)
				g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "CR should be fully deleted")
			}, 1*time.Minute, 3*time.Second).Should(Succeed())

			By("verifying the real data survived (retained, NOT deleted)")
			secret, err := vaultClient.Read(ctx, retainPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret).NotTo(BeNil(), "modified secret must be retained on CR deletion")
			data, ok := secret.Data["data"].(map[string]interface{})
			Expect(ok).To(BeTrue())
			Expect(data["password"]).To(Equal("s3cr3t-real"))
		})
	})
})
