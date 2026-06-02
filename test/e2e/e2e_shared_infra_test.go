/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Shared test infrastructure that every spec depends on: the K8s test
// namespace, the Vault auth mounts, the operator policy + non-root token,
// and the shared VaultConnection.
//
// setupSharedTestInfrastructure() is the top-level orchestrator. It runs
// in BeforeSuite (see e2e_suite_test.go) and reads as a sequence of named
// steps — "init, ensure, wait, configure, attach, connect" — rather than
// 100+ lines of inline plumbing. Each step is a small helper below.

package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// ─────────────────────────────────────────────────────────────────────────────
// Top-level orchestrators — call sites are BeforeSuite / AfterSuite.
// ─────────────────────────────────────────────────────────────────────────────

// setupSharedTestInfrastructure creates everything every spec depends on.
// Each step is a named helper so the recipe is auditable in one screen.
func setupSharedTestInfrastructure() {
	ctx := context.Background()

	initK8sClient()
	ensureTestNamespace(ctx)
	ensureVaultRBACDeployed(ctx)

	vaultClient := waitForVaultAPIReady(ctx)
	enableAndConfigureAllAuthBackends(ctx, vaultClient)

	operatorToken := createOperatorPolicyAndToken(ctx, vaultClient)
	createSharedVaultConnection(ctx, operatorToken)
	waitForSharedVaultConnectionActive(ctx)
}

// cleanupSharedTestInfrastructure removes the shared VaultConnection and
// test namespace. AfterSuite-level resources only — per-test resources
// clean up in their own AfterAll blocks.
func cleanupSharedTestInfrastructure() {
	ctx := context.Background()

	utils.TimedBy("cleaning up shared VaultConnection")
	_ = utils.DeleteVaultConnectionCR(ctx, sharedVaultConnectionName)

	if err := utils.WaitForClusterDeletion(
		ctx, &vaultv1alpha1.VaultConnection{}, sharedVaultConnectionName,
		60*time.Second, 2*time.Second,
	); err != nil {
		fmt.Fprintf(GinkgoWriter,
			"Warning: VaultConnection deletion timed out: %v\n", err)
	}

	utils.TimedBy("cleaning up test namespace")
	_ = utils.DeleteNamespace(ctx, testNamespace)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 1: K8s client + namespace + Vault RBAC
// ─────────────────────────────────────────────────────────────────────────────

func initK8sClient() {
	utils.TimedBy("initializing K8s client")
	_ = utils.MustGetK8sClient()
}

func ensureTestNamespace(ctx context.Context) {
	utils.TimedBy("creating test namespace")
	ExpectWithOffset(1, utils.CreateNamespace(ctx, testNamespace)).
		To(Succeed(), "Failed to create test namespace")
}

// ensureVaultRBACDeployed applies test/e2e/fixtures/vault-rbac.yaml if the
// vault namespace doesn't already exist. CI and local both deploy this via
// Makefile; this is the fallback when running tests outside that flow.
func ensureVaultRBACDeployed(ctx context.Context) {
	utils.TimedBy("checking if Vault RBAC is deployed")
	exists, err := utils.NamespaceExists(ctx, vaultNamespace)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	if exists {
		return
	}
	utils.TimedBy("deploying Vault RBAC (not found, deploying for fallback)")
	cmd := exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/vault-rbac.yaml")
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to deploy Vault RBAC")
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2: Vault readiness + auth backend enable/configure
// ─────────────────────────────────────────────────────────────────────────────

// waitForVaultAPIReady polls Vault's /sys/health until it reports
// initialized+unsealed, then returns the client. Vault runs as a docker
// container, so this is the first network reachability check.
func waitForVaultAPIReady(ctx context.Context) *utils.TestVaultClient {
	utils.TimedBy("waiting for Vault API to be accessible")
	vaultClient, err := utils.GetTestVaultClient()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create Vault test client")

	Eventually(func(g Gomega) {
		healthy, err := vaultClient.Health(ctx)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(healthy).To(BeTrue(), "Vault should be initialized and unsealed")
	}, 1*time.Minute, 5*time.Second).Should(Succeed())

	return vaultClient
}

// enableAndConfigureAllAuthBackends enables the four auth backends every
// spec assumes is present and configures the ones that need TokenReview /
// OIDC discovery. Configuration failures degrade the relevant suite to
// skips rather than failing the whole run.
func enableAndConfigureAllAuthBackends(ctx context.Context, vaultClient *utils.TestVaultClient) {
	enableAuthBackend(ctx, vaultClient, "kubernetes", "kubernetes")
	if err := configureKubernetesAuth(); err != nil {
		fmt.Fprintf(GinkgoWriter, "Warning: Kubernetes auth configuration failed: %v\n", err)
		fmt.Fprintf(GinkgoWriter, "VaultRole tests may fail\n")
	}

	enableAuthBackend(ctx, vaultClient, "jwt", "jwt")
	if err := configureJWTAuth(); err != nil {
		fmt.Fprintf(GinkgoWriter, "Warning: JWT auth configuration failed: %v\n", err)
		fmt.Fprintf(GinkgoWriter, "JWT auth tests will be skipped\n")
	}

	enableAuthBackend(ctx, vaultClient, "approle", "approle")

	enableAuthBackend(ctx, vaultClient, "oidc", "jwt")
	if err := configureOIDCAuth(); err != nil {
		fmt.Fprintf(GinkgoWriter, "Warning: OIDC auth configuration failed: %v\n", err)
		fmt.Fprintf(GinkgoWriter, "OIDC auth tests will be skipped\n")
	}
}

// enableAuthBackend wraps EnableAuth with a TimedBy banner and a uniform
// failure assertion so the orchestrator above stays declarative.
func enableAuthBackend(ctx context.Context, vaultClient *utils.TestVaultClient, mount, engine string) {
	utils.TimedBy(fmt.Sprintf("enabling %s auth method", mount))
	err := vaultClient.EnableAuth(ctx, mount, engine)
	ExpectWithOffset(2, err).NotTo(HaveOccurred(),
		"Failed to enable %s auth", mount)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 3: Operator policy + non-root token
// ─────────────────────────────────────────────────────────────────────────────

// createOperatorPolicyAndToken writes the least-privilege operator policy
// to Vault and creates a token bound to it. Returns the token so the
// caller can plumb it into the shared VaultConnection secret.
func createOperatorPolicyAndToken(ctx context.Context, vaultClient *utils.TestVaultClient) string {
	utils.TimedBy("creating operator policy with least-privilege permissions")
	ExpectWithOffset(1,
		vaultClient.WritePolicy(ctx, operatorPolicyName, operatorPolicyHCL),
	).To(Succeed(), "Failed to create operator policy")

	utils.TimedBy("creating operator token (non-root)")
	operatorToken, err := vaultClient.CreateToken(ctx, []string{operatorPolicyName}, "4h")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create operator token")
	ExpectWithOffset(1, operatorToken).NotTo(BeEmpty(), "Operator token should not be empty")
	return operatorToken
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 4: Shared VaultConnection
// ─────────────────────────────────────────────────────────────────────────────

// createSharedVaultConnection stores the operator token in a K8s Secret
// and creates the VaultConnection CR every spec references.
func createSharedVaultConnection(ctx context.Context, operatorToken string) {
	utils.TimedBy("creating Vault token secret for shared VaultConnection " +
		"(using operator token, not root)")
	ExpectWithOffset(1,
		utils.CreateSecret(ctx, testNamespace, sharedVaultTokenSecretName,
			map[string][]byte{"token": []byte(operatorToken)}),
	).To(Succeed(), "Failed to create token secret")

	utils.TimedBy("creating shared VaultConnection for tests")
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: sharedVaultConnectionName},
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
	ExpectWithOffset(1, utils.CreateVaultConnectionCR(ctx, conn)).
		To(Succeed(), "Failed to create shared VaultConnection")
}

// waitForSharedVaultConnectionActive polls the shared VaultConnection's
// status until Active, with a Vault version and heartbeat — proving the
// operator successfully authenticated and probed the backend.
func waitForSharedVaultConnectionActive(ctx context.Context) {
	utils.TimedBy("waiting for shared VaultConnection to become Active and healthy")
	Eventually(func(g Gomega) {
		vc, err := utils.GetVaultConnection(ctx, sharedVaultConnectionName, "")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(string(vc.Status.Phase)).To(
			Equal("Active"), "VaultConnection phase should be Active",
		)
		g.Expect(vc.Status.VaultVersion).NotTo(
			BeEmpty(), "VaultConnection should report vault version",
		)
		g.Expect(vc.Status.LastHeartbeat).NotTo(
			BeNil(), "VaultConnection should have a lastHeartbeat timestamp",
		)
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}
