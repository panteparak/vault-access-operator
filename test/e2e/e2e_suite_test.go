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
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Shared constants for all E2E tests
const (
	// vaultNamespace is where Vault dev server is deployed
	vaultNamespace = "vault"

	// testNamespace is where namespaced test resources are created
	testNamespace = "e2e-test"

	// sharedVaultConnectionName is the VaultConnection used by most tests
	sharedVaultConnectionName = "e2e-vault"

	// sharedVaultTokenSecretName is the secret containing the Vault token
	sharedVaultTokenSecretName = "vault-token"

	// operatorPolicyName is the Vault policy for the operator
	operatorPolicyName = "vault-access-operator"
)

// Dex OIDC provider constants for OIDC auth tests.
// Dex runs as a Docker container alongside k3s (docker-compose) and is reachable:
// - From host/tests: http://localhost:5556 (port mapping)
// - From k8s pods: http://dex.default.svc.cluster.local:5556 (K8s Service + Endpoints bridge)
// - From Vault container: http://dex.default.svc.cluster.local:5556 (docker network alias)
const (
	dexTokenEndpoint      = "http://localhost:5556/token"
	dexIssuer             = "http://dex.default.svc.cluster.local:5556"
	dexDiscoveryURL       = "http://localhost:5556/.well-known/openid-configuration"
	dexClientID           = "vault"
	dexClientSecret       = "vault-secret"
	dexCustomClientID     = "custom-audience"
	dexCustomClientSecret = "custom-audience-secret"
	dexTestEmail          = "admin@example.com"
	dexTestPassword       = "password" //nolint:gosec // Test-only static password for Dex
)

// operatorPolicyHCL defines the minimum permissions required for the operator.
// This follows the Principle of Least Privilege - only granting what's needed.
const operatorPolicyHCL = `
# Policy management - operator needs to create/update/delete policies
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/policies/acl" {
  capabilities = ["list"]
}

# Kubernetes auth role management
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/kubernetes/role" {
  capabilities = ["list"]
}

# Kubernetes auth configuration (for initial setup)
path "auth/kubernetes/config" {
  capabilities = ["create", "read", "update", "delete"]
}

# JWT auth role management (for JWT auth tests)
path "auth/jwt/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/jwt/role" {
  capabilities = ["list"]
}

# JWT auth configuration
path "auth/jwt/config" {
  capabilities = ["create", "read", "update", "delete"]
}

# Auth method management (enable/disable auth methods)
path "sys/auth" {
  capabilities = ["read"]
}
path "sys/auth/*" {
  capabilities = ["sudo", "create", "read", "update", "delete", "list"]
}

# AppRole auth management
path "auth/approle/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
path "auth/approle" {
  capabilities = ["read"]
}

# OIDC (JWT at oidc path) auth management
path "auth/oidc/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
path "auth/oidc" {
  capabilities = ["read"]
}

# Health checks
path "sys/health" {
  capabilities = ["read"]
}

# Mount listing (used by bootstrap to verify auth methods)
path "sys/mounts" {
  capabilities = ["read"]
}

# KV v2 managed resource metadata (ownership tracking)
# The operator stores metadata about which K8s resource manages each Vault policy/role
# KV v2 requires separate data/ and metadata/ path prefixes
path "secret/data/vault-access-operator/managed/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/vault-access-operator/managed/*" {
  capabilities = ["list", "read", "delete"]
}
`

// envTrue is the canonical string value for boolean environment variables.
const envTrue = "true"

var (
	// projectImage is the name of the image which will be build and loaded
	// with the code source changes to be tested.
	// Can be overridden via E2E_OPERATOR_IMAGE environment variable.
	projectImage = "vault-access-operator:local"

	// skipBuild skips building the image (useful when image is pre-built in CI).
	// Set E2E_SKIP_BUILD=true to skip.
	skipBuild = os.Getenv("E2E_SKIP_BUILD") == envTrue

	// skipImageLoad skips loading image to cluster (useful when image is pre-loaded by CI).
	// Set E2E_SKIP_IMAGE_LOAD=true to skip.
	skipImageLoad = os.Getenv("E2E_SKIP_IMAGE_LOAD") == envTrue

	// isCI detects if running in a CI environment (GitHub Actions, GitLab CI, etc.)
	isCI = os.Getenv("CI") == envTrue || os.Getenv("GITHUB_ACTIONS") == envTrue

	// Default timeout values - CI environments get longer timeouts due to
	// slower shared runners, network latency, and resource contention
	defaultTimeout = func() time.Duration {
		if isCI {
			return 5 * time.Minute
		}
		return 3 * time.Minute
	}()

	// Polling interval for Eventually assertions
	defaultPollingInterval = 2 * time.Second
)

func init() {
	// Allow overriding image via environment variable (same as Makefile)
	if img := os.Getenv("E2E_OPERATOR_IMAGE"); img != "" {
		projectImage = img
	}
}

// TestE2E runs the end-to-end (e2e) test suite for the project. These tests execute in an isolated,
// temporary environment to validate project changes with the purpose to be used in CI jobs.
// Both local and CI use docker-compose (k3s + Vault + Dex) with identical Makefile targets.
// In CI, E2E_SKIP_BUILD and E2E_SKIP_IMAGE_LOAD are set to use pre-built images.
// Note: Webhooks use self-signed TLS certificates instead of cert-manager.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting vault-access-operator integration test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	utils.TimedBy(fmt.Sprintf("using image: %s (skipBuild=%v, skipImageLoad=%v)", projectImage, skipBuild, skipImageLoad))

	if !skipBuild {
		utils.TimedBy("building the manager(Operator) image")
		cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
		_, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager(Operator) image")
	} else {
		utils.TimedBy("skipping image build (E2E_SKIP_BUILD=true)")
	}

	if !skipImageLoad {
		utils.TimedBy("loading the manager(Operator) image into cluster")
		err := utils.LoadImageToCluster(projectImage)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager(Operator) image into cluster")
	} else {
		utils.TimedBy("skipping image load (E2E_SKIP_IMAGE_LOAD=true)")
	}

	// Set default timeouts for all tests
	// CI environments get longer timeouts due to resource contention and network latency
	SetDefaultEventuallyTimeout(defaultTimeout)
	SetDefaultEventuallyPollingInterval(defaultPollingInterval)
	if isCI {
		utils.TimedBy(fmt.Sprintf("running in CI mode with extended timeouts (%v)", defaultTimeout))
	}

	// Setup shared test infrastructure
	setupSharedTestInfrastructure()
})

var _ = AfterSuite(func() {
	// Cleanup shared test infrastructure
	cleanupSharedTestInfrastructure()
})

// ReportAfterEach captures debugging context when tests fail.
// This provides operator logs, Vault status, and CRD status for easier debugging.
var _ = ReportAfterEach(func(report SpecReport) {
	if report.Failed() {
		fmt.Fprintf(GinkgoWriter, "\n=== FAILURE CONTEXT ===\n")
		fmt.Fprintf(GinkgoWriter, "Test: %s\n", report.FullText())
		fmt.Fprintf(GinkgoWriter, "Duration: %v\n", report.RunTime)
		fmt.Fprintf(GinkgoWriter, "Failure: %s\n", report.FailureMessage())

		// Capture operator logs (last 50 lines)
		cmd := exec.Command("kubectl", "logs", "-n", "vault-access-operator-system",
			"-l", "control-plane=controller-manager", "--tail=50")
		if output, err := utils.Run(cmd); err == nil {
			fmt.Fprintf(GinkgoWriter, "\n--- Operator Logs (last 50 lines) ---\n%s\n", output)
		} else {
			fmt.Fprintf(GinkgoWriter, "\n--- Failed to get Operator Logs: %v ---\n", err)
		}

		// Capture Vault status (Vault runs as docker container, check via API)
		vaultAddr := os.Getenv("VAULT_ADDR")
		if vaultAddr == "" {
			vaultAddr = "http://localhost:8200"
		}
		cmd = exec.Command("curl", "-sf", vaultAddr+"/v1/sys/health")
		if output, err := utils.Run(cmd); err == nil {
			fmt.Fprintf(GinkgoWriter, "\n--- Vault Health ---\n%s\n", output)
		} else {
			fmt.Fprintf(GinkgoWriter, "\n--- Failed to get Vault Health: %v ---\n", err)
		}

		// Capture CRD status
		crdTypes := "vaultconnections,vaultpolicies,vaultroles,vaultclusterpolicies,vaultclusterroles"
		crdColumns := "KIND:.kind,NAMESPACE:.metadata.namespace,NAME:.metadata.name," +
			"PHASE:.status.phase,MESSAGE:.status.message"
		cmd = exec.Command("kubectl", "get", crdTypes, "-A", "-o", "custom-columns="+crdColumns)
		if output, err := utils.Run(cmd); err == nil {
			fmt.Fprintf(GinkgoWriter, "\n--- CRD Status ---\n%s\n", output)
		} else {
			fmt.Fprintf(GinkgoWriter, "\n--- Failed to get CRD Status: %v ---\n", err)
		}

		// Capture recent events
		eventColumns := "NAMESPACE:.metadata.namespace,TYPE:.type,REASON:.reason,MESSAGE:.message"
		cmd = exec.Command("kubectl", "get", "events", "-A", "--sort-by=.lastTimestamp",
			"--field-selector=type!=Normal", "-o", "custom-columns="+eventColumns)
		if output, err := utils.Run(cmd); err == nil {
			fmt.Fprintf(GinkgoWriter, "\n--- Recent Warning/Error Events ---\n%s\n", output)
		}

		fmt.Fprintf(GinkgoWriter, "=== END FAILURE CONTEXT ===\n\n")
	}
})

// setupSharedTestInfrastructure creates resources shared across all test files.
// Uses typed Go clients (client-go + vault/api) instead of kubectl subprocesses.
func setupSharedTestInfrastructure() {
	ctx := context.Background()

	// Initialize the K8s client (must be first — other helpers depend on it)
	utils.TimedBy("initializing K8s client")
	_ = utils.MustGetK8sClient()

	utils.TimedBy("creating test namespace")
	err := utils.CreateNamespace(ctx, testNamespace)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create test namespace")

	// Deploy Vault RBAC resources if vault namespace doesn't exist
	// (CI and local both deploy these via Makefile, but this handles fallback)
	utils.TimedBy("checking if Vault RBAC is deployed")
	vaultExists, err := utils.NamespaceExists(ctx, vaultNamespace)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	if !vaultExists {
		utils.TimedBy("deploying Vault RBAC (not found, deploying for fallback)")
		cmd := exec.Command("kubectl", "apply", "-f", "test/e2e/fixtures/vault-rbac.yaml")
		_, err = utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to deploy Vault RBAC")
	}

	// Wait for Vault API to be accessible via the Go client
	// Vault now runs as a docker container (not a k8s pod), so we check the API directly
	utils.TimedBy("waiting for Vault API to be accessible")
	vaultClient, err := utils.GetTestVaultClient()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create Vault test client")

	Eventually(func(g Gomega) {
		healthy, err := vaultClient.Health(ctx)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(healthy).To(BeTrue(), "Vault should be initialized and unsealed")
	}, 1*time.Minute, 5*time.Second).Should(Succeed())

	// Enable and configure auth methods using the Vault Go client
	utils.TimedBy("enabling Kubernetes auth method")
	err = vaultClient.EnableAuth(ctx, "kubernetes", "kubernetes")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to enable kubernetes auth")

	utils.TimedBy("configuring Kubernetes auth")
	if err := configureKubernetesAuth(); err != nil {
		fmt.Fprintf(GinkgoWriter, "Warning: Kubernetes auth configuration failed: %v\n", err)
		fmt.Fprintf(GinkgoWriter, "VaultRole tests may fail\n")
	}

	utils.TimedBy("enabling JWT auth method")
	err = vaultClient.EnableAuth(ctx, "jwt", "jwt")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to enable jwt auth")

	utils.TimedBy("configuring JWT auth with JWKS")
	if err := configureJWTAuth(); err != nil {
		fmt.Fprintf(GinkgoWriter, "Warning: JWT auth configuration failed: %v\n", err)
		fmt.Fprintf(GinkgoWriter, "JWT auth tests will be skipped\n")
	}

	utils.TimedBy("enabling AppRole auth method")
	err = vaultClient.EnableAuth(ctx, "approle", "approle")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to enable approle auth")

	utils.TimedBy("enabling OIDC auth method (JWT at oidc path)")
	err = vaultClient.EnableAuth(ctx, "oidc", "jwt")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to enable oidc auth")

	utils.TimedBy("configuring OIDC auth with JWKS")
	if err := configureOIDCAuth(); err != nil {
		fmt.Fprintf(GinkgoWriter, "Warning: OIDC auth configuration failed: %v\n", err)
		fmt.Fprintf(GinkgoWriter, "OIDC auth tests will be skipped\n")
	}

	// Create operator policy with least-privilege permissions
	utils.TimedBy("creating operator policy with least-privilege permissions")
	err = vaultClient.WritePolicy(ctx, operatorPolicyName, operatorPolicyHCL)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create operator policy")

	// Create operator token (non-root) with the operator policy
	utils.TimedBy("creating operator token (non-root)")
	operatorToken, err := vaultClient.CreateToken(
		ctx, []string{operatorPolicyName}, "24h",
	)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create operator token")
	ExpectWithOffset(1, operatorToken).NotTo(BeEmpty(), "Operator token should not be empty")

	utils.TimedBy("creating Vault token secret for shared VaultConnection (using operator token, not root)")
	err = utils.CreateSecret(ctx, testNamespace, sharedVaultTokenSecretName,
		map[string][]byte{"token": []byte(operatorToken)})
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create token secret")

	utils.TimedBy("creating shared VaultConnection for tests")
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name: sharedVaultConnectionName,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: fmt.Sprintf(
				"http://vault.%s.svc.cluster.local:8200", vaultNamespace,
			),
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
	err = utils.CreateVaultConnectionCR(ctx, conn)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to create shared VaultConnection")

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

// cleanupSharedTestInfrastructure removes shared test resources
func cleanupSharedTestInfrastructure() {
	ctx := context.Background()

	utils.TimedBy("cleaning up shared VaultConnection")
	_ = utils.DeleteVaultConnectionCR(ctx, sharedVaultConnectionName)

	// Wait for finalizers to complete
	err := utils.WaitForClusterDeletion(
		ctx, &vaultv1alpha1.VaultConnection{}, sharedVaultConnectionName,
		60*time.Second, 2*time.Second,
	)
	if err != nil {
		fmt.Fprintf(GinkgoWriter,
			"Warning: VaultConnection deletion timed out: %v\n", err)
	}

	utils.TimedBy("cleaning up test namespace")
	_ = utils.DeleteNamespace(ctx, testNamespace)
}

// configureKubernetesAuth configures Vault's Kubernetes auth method at
// "auth/kubernetes". It retrieves the vault-auth SA token (which has
// TokenReview permissions) and a combined CA bundle, then writes them
// to auth/kubernetes/config so Vault can validate K8s SA tokens.
//
// Uses a combined CA bundle (TLS handshake + kubeconfig + ConfigMap)
// to handle k3s 1.25+ which uses separate server-ca and client-ca.
func configureKubernetesAuth() error {
	ctx := context.Background()

	// Get a token for the vault-auth ServiceAccount
	reviewerJWT, err := utils.CreateServiceAccountTokenClientGo(
		ctx, vaultAuthNamespace, vaultAuthSA,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to get vault-auth SA token: %w", err,
		)
	}

	// Build CA bundle from all available sources
	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(GinkgoWriter, format+"\n", args...)
	}
	caCert, err := utils.BuildCABundle(ctx, logf)
	if err != nil {
		return fmt.Errorf(
			"failed to build CA bundle: %w", err,
		)
	}

	// Configure Kubernetes auth via Vault Go client
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return fmt.Errorf(
			"failed to get vault client: %w", err,
		)
	}

	// E2E_K8S_HOST overrides the Kubernetes API host that Vault uses.
	// When Vault runs external to k8s (docker-compose), it connects via
	// the docker network (e.g., https://k3s:6443) instead of the in-cluster DNS.
	k8sHost := os.Getenv("E2E_K8S_HOST")
	if k8sHost == "" {
		k8sHost = "https://kubernetes.default.svc.cluster.local:443"
	}

	return vaultClient.WriteKubernetesAuthConfig(
		ctx, "kubernetes",
		k8sHost,
		strings.TrimSpace(reviewerJWT),
		strings.TrimSpace(caCert),
	)
}

// configureJWTAuth configures Vault's JWT auth method at the default "auth/jwt" path.
func configureJWTAuth() error {
	return configureJWTAuthAtPath("auth/jwt")
}

// configureOIDCAuth configures Vault's JWT auth method at the "auth/oidc" mount path
// using Dex as the OIDC provider. Dex must be running on the host at dexDiscoveryURL.
func configureOIDCAuth() error {
	ctx := context.Background()

	resp, err := http.Get(dexDiscoveryURL) //nolint:gosec
	if err != nil {
		return fmt.Errorf("Dex not reachable at %s: %w", dexDiscoveryURL, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Dex discovery returned status %d", resp.StatusCode)
	}

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}

	err = vaultClient.WriteAuthConfig(ctx, "auth/oidc/config", map[string]interface{}{
		"oidc_discovery_url": dexIssuer,
		"bound_issuer":       dexIssuer,
	})
	if err != nil {
		return fmt.Errorf("failed to configure OIDC auth with Dex: %w", err)
	}
	fmt.Fprintf(GinkgoWriter, "auth/oidc configured with Dex OIDC discovery (%s)\n", dexIssuer)
	return nil
}

// getDexToken obtains an id_token from Dex using the OAuth2 Resource Owner Password
// Credentials grant. The clientID determines the "aud" claim in the returned JWT.
func getDexToken(clientID, clientSecret string) (string, error) {
	data := url.Values{
		"grant_type":    {"password"},
		"username":      {dexTestEmail},
		"password":      {dexTestPassword},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"openid email profile"},
	}
	resp, err := http.PostForm(dexTokenEndpoint, data)
	if err != nil {
		return "", fmt.Errorf("failed to request Dex token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read Dex response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Dex token request failed (status %d): %s", resp.StatusCode, body)
	}
	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse Dex token response: %w", err)
	}
	if tokenResp.IDToken == "" {
		return "", fmt.Errorf("empty id_token in Dex response")
	}
	return tokenResp.IDToken, nil
}

// configureJWTAuthAtPath configures a JWT/OIDC auth method at the given
// Vault path.
//
// Strategy: build a combined CA bundle from all available sources (TLS
// handshake, kubeconfig, ConfigMap) and use it for OIDC discovery. This
// handles k3s 1.25+ which uses separate server-ca and client-ca — only
// the server CA can verify kubernetes.default.svc, but different sources
// may expose different CAs. The combined bundle ensures the right one is
// included. Falls back to static JWKS PEM keys if no CA is available.
//
//nolint:unparam // authPath is parameterised for flexibility (jwt vs oidc)
func configureJWTAuthAtPath(authPath string) error {
	ctx := context.Background()

	// Get OIDC configuration to find the issuer
	output, err := utils.GetK8sRawEndpoint(
		ctx, "/.well-known/openid-configuration",
	)
	if err != nil {
		return fmt.Errorf("failed to get OIDC config: %w", err)
	}

	var oidcConfig struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(output, &oidcConfig); err != nil {
		return fmt.Errorf(
			"failed to parse OIDC config: %w", err,
		)
	}

	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return fmt.Errorf(
			"failed to get vault client: %w", err,
		)
	}

	configPath := fmt.Sprintf("%s/config", authPath)

	// Build a combined CA bundle from all available sources.
	// This ensures the correct server CA is included regardless
	// of k3s version or CA configuration (server-ca vs client-ca).
	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(GinkgoWriter, format+"\n", args...)
	}
	caBundle, err := utils.BuildCABundle(ctx, logf)
	if err == nil && caBundle != "" {
		err = vaultClient.WriteAuthConfig(
			ctx, configPath, map[string]interface{}{
				"oidc_discovery_url":    oidcConfig.Issuer,
				"bound_issuer":          oidcConfig.Issuer,
				"oidc_discovery_ca_pem": caBundle,
			},
		)
		if err == nil {
			fmt.Fprintf(GinkgoWriter,
				"%s configured with OIDC discovery "+
					"(CA bundle)\n", authPath,
			)
			return nil
		}
		fmt.Fprintf(GinkgoWriter,
			"OIDC config write failed for %s (%v), "+
				"falling back to JWKS\n",
			authPath, err,
		)
	} else {
		fmt.Fprintf(GinkgoWriter,
			"Could not build CA bundle (%v), "+
				"falling back to JWKS\n", err,
		)
	}

	// Fall back to static JWKS public keys.
	// This extracts PEM-encoded RSA public keys from the K8s JWKS
	// endpoint and passes them directly to Vault — no network call
	// from Vault to the K8s API is needed.
	jwksOutput, err := utils.GetK8sRawEndpoint(
		ctx, "/openid/v1/jwks",
	)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	pemKeys, err := utils.JWKSToPEMKeys(jwksOutput)
	if err != nil {
		return fmt.Errorf(
			"failed to convert JWKS to PEM keys: %w", err,
		)
	}

	err = vaultClient.WriteAuthConfig(
		ctx, configPath, map[string]interface{}{
			"jwt_validation_pubkeys": pemKeys,
			"bound_issuer":           oidcConfig.Issuer,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"failed to configure %s with JWKS: %w",
			authPath, err,
		)
	}

	fmt.Fprintf(GinkgoWriter,
		"%s configured with JWKS PEM keys\n", authPath,
	)
	return nil
}
