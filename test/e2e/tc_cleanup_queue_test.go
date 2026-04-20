/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/cleanup"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// TC-CLEAN pins the IMPROVEMENTS §1 + §2 fix end-to-end: when a VaultPolicy
// is deleted while Vault is not reachable for the operator, the cleanup
// workflow enqueues a retry item into the vault-cleanup-queue ConfigMap, and
// the cleanup.Controller (now wired into main.go) drains it once Vault is
// reachable again. Before §1/§2, the finalizer would be removed and the
// Vault policy would leak forever.

var _ = Describe("Cleanup Queue Tests", Ordered, Label("cleanup"), func() {
	ctx := context.Background()

	const (
		cleanupConnectionName = "e2e-cleanup"
		cleanupTokenSecret    = "vault-token-cleanup"
	)

	refreshCleanupToken := func() {
		By("ensuring a fresh token secret for cleanup connection")
		vc, err := utils.GetTestVaultClient()
		Expect(err).NotTo(HaveOccurred())
		operatorToken, err := vc.CreateToken(ctx, []string{operatorPolicyName}, "1h")
		Expect(err).NotTo(HaveOccurred())
		_ = utils.DeleteSecret(ctx, testNamespace, cleanupTokenSecret)
		Expect(utils.CreateSecret(ctx, testNamespace, cleanupTokenSecret,
			map[string][]byte{"token": []byte(operatorToken)})).To(Succeed())
	}

	BeforeAll(func() {
		refreshCleanupToken()
	})

	AfterAll(func() {
		By("cleaning up cleanup-test connection")
		_ = utils.DeleteVaultConnectionCR(ctx, cleanupConnectionName)
		_ = utils.DeleteSecret(ctx, testNamespace, cleanupTokenSecret)
	})

	Context("TC-CLEAN: Queue drain after Vault-unavailable cleanup", func() {
		It("TC-CLEAN01-QUEUE-DRAIN: retries a Vault delete that failed while Vault was unreachable (§1+§2)", func() {
			refreshCleanupToken()

			const policyName = "tc-clean01-policy"

			By("creating a VaultConnection + VaultPolicy and waiting for sync")
			boolTrue := true
			conn := &vaultv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{Name: cleanupConnectionName},
				Spec: vaultv1alpha1.VaultConnectionSpec{
					Address: vaultK8sAddr,
					Auth: vaultv1alpha1.AuthConfig{
						Token: &vaultv1alpha1.TokenAuth{
							SecretRef: vaultv1alpha1.SecretKeySelector{
								Name: cleanupTokenSecret, Namespace: testNamespace, Key: "token",
							},
						},
					},
					Discovery: &vaultv1alpha1.DiscoveryConfig{
						Enabled: boolTrue, Interval: "30s",
					},
				},
			}
			Expect(utils.CreateVaultConnectionCR(ctx, conn)).To(Succeed())
			DeferCleanup(func() { _ = utils.DeleteVaultConnectionCR(ctx, cleanupConnectionName) })

			Eventually(func(g Gomega) {
				vc, err := utils.GetVaultConnection(ctx, cleanupConnectionName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(vc.Status.Phase).To(Equal(vaultv1alpha1.PhaseActive))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			policy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: testNamespace},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: cleanupConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{Path: "secret/data/tc-clean01/*", Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead}},
					},
				},
			}
			Expect(utils.CreateVaultPolicyCR(ctx, policy)).To(Succeed())

			Eventually(func(g Gomega) {
				p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(p.Status.Phase).To(Equal(vaultv1alpha1.PhaseActive))
			}, 90*time.Second, 5*time.Second).Should(Succeed())

			By("pointing the connection at an unreachable Vault address to simulate outage")
			// Simulating outage via address swap exercises the real recovery
			// path: the connection reconciler detects Vault unreachability,
			// marks the connection Error, evicts the cached client (see
			// handler.go:895-897). The cleanup workflow then can't get a
			// client and enqueues. Swapping the address back lets the
			// reconciler re-auth with the valid token from the Secret and
			// lets the cleanup controller drain using the fresh client.
			//
			// An earlier attempt overwrote the token Secret: the operator
			// caches *vault.Client in memory and doesn't watch Secrets, so
			// the cached token outlives the Secret update until TTL-based
			// renewal — which for a 1h token is far outside the test budget.
			const unreachableAddr = "http://vault-unreachable-tc-clean01.invalid:8200"
			Expect(utils.UpdateVaultConnectionCR(ctx, cleanupConnectionName, func(c *vaultv1alpha1.VaultConnection) {
				c.Spec.Address = unreachableAddr
			})).To(Succeed())

			By("waiting for the connection to flip to Error (cache evicted)")
			Eventually(func(g Gomega) {
				c, err := utils.GetVaultConnection(ctx, cleanupConnectionName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(c.Status.Phase).To(Equal(vaultv1alpha1.PhaseError))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("deleting the VaultPolicy while the operator cannot reach Vault")
			Expect(utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)).To(Succeed())

			By("verifying the cleanup queue ConfigMap is populated (indicates enqueue-on-failure worked)")
			// Operator chart installs into "vault-access-operator-system" by default;
			// that's where the cleanup.Queue writes its ConfigMap.
			const operatorNS = "vault-access-operator-system"
			Eventually(func(g Gomega) {
				cm := &corev1.ConfigMap{}
				err := utils.GetObject(ctx, cleanup.ConfigMapName, operatorNS, cm)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(cm.Data).To(HaveKey(cleanup.QueueDataKey),
					"queue should have a data key — §2 enqueue-on-failure missing?")
				g.Expect(cm.Data[cleanup.QueueDataKey]).To(ContainSubstring(policyName),
					"queue should contain the deleted policy's name")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("restoring the real Vault address so the connection re-auths and cleanup can drain")
			Expect(utils.UpdateVaultConnectionCR(ctx, cleanupConnectionName, func(c *vaultv1alpha1.VaultConnection) {
				c.Spec.Address = vaultK8sAddr
			})).To(Succeed())
			Eventually(func(g Gomega) {
				c, err := utils.GetVaultConnection(ctx, cleanupConnectionName, "")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(c.Status.Phase).To(Equal(vaultv1alpha1.PhaseActive))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the cleanup controller drains the queue within a retry cycle (§1 wiring)")
			Eventually(func(g Gomega) {
				cm := &corev1.ConfigMap{}
				err := utils.GetObject(ctx, cleanup.ConfigMapName, operatorNS, cm)
				g.Expect(err).NotTo(HaveOccurred())
				queueData := cm.Data[cleanup.QueueDataKey]
				g.Expect(queueData).NotTo(ContainSubstring(policyName),
					"queue did not drain — cleanup controller not running or blocked (§1 regression)")
			}, 5*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying the Vault policy is actually deleted from Vault")
			vaultClient, err := utils.GetTestVaultClient()
			Expect(err).NotTo(HaveOccurred())
			exists, err := vaultClient.PolicyExists(ctx, testNamespace+"-"+policyName)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeFalse(),
				"Vault policy must be removed by the cleanup controller after retry")
		})
	})
})
