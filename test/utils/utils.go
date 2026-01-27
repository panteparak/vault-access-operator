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

package utils

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" // nolint:revive,staticcheck
)

const (
	prometheusOperatorVersion = "v0.77.1"
	prometheusOperatorURL     = "https://github.com/prometheus-operator/prometheus-operator/" +
		"releases/download/%s/bundle.yaml"

	certmanagerVersion = "v1.16.3"
	certmanagerURLTmpl = "https://github.com/cert-manager/cert-manager/releases/download/%s/cert-manager.yaml"
)

func warnError(err error) {
	_, _ = fmt.Fprintf(GinkgoWriter, "warning: %v\n", err)
}

// Run executes the provided command within this context
func Run(cmd *exec.Cmd) (string, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "chdir dir: %q\n", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	_, _ = fmt.Fprintf(GinkgoWriter, "running: %q\n", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%q failed with error %q: %w", command, string(output), err)
	}

	return string(output), nil
}

// InstallPrometheusOperator installs the prometheus Operator to be used to export the enabled metrics.
func InstallPrometheusOperator() error {
	url := fmt.Sprintf(prometheusOperatorURL, prometheusOperatorVersion)
	cmd := exec.Command("kubectl", "create", "-f", url)
	_, err := Run(cmd)
	return err
}

// UninstallPrometheusOperator uninstalls the prometheus
func UninstallPrometheusOperator() {
	url := fmt.Sprintf(prometheusOperatorURL, prometheusOperatorVersion)
	cmd := exec.Command("kubectl", "delete", "-f", url)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// IsPrometheusCRDsInstalled checks if any Prometheus CRDs are installed
// by verifying the existence of key CRDs related to Prometheus.
func IsPrometheusCRDsInstalled() bool {
	// List of common Prometheus CRDs
	prometheusCRDs := []string{
		"prometheuses.monitoring.coreos.com",
		"prometheusrules.monitoring.coreos.com",
		"prometheusagents.monitoring.coreos.com",
	}

	cmd := exec.Command("kubectl", "get", "crds", "-o", "custom-columns=NAME:.metadata.name")
	output, err := Run(cmd)
	if err != nil {
		return false
	}
	crdList := GetNonEmptyLines(output)
	for _, crd := range prometheusCRDs {
		for _, line := range crdList {
			if strings.Contains(line, crd) {
				return true
			}
		}
	}

	return false
}

// UninstallCertManager uninstalls the cert manager
func UninstallCertManager() {
	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)
	cmd := exec.Command("kubectl", "delete", "-f", url)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// InstallCertManager installs the cert manager bundle.
func InstallCertManager() error {
	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)
	cmd := exec.Command("kubectl", "apply", "-f", url)
	if _, err := Run(cmd); err != nil {
		return err
	}
	// Wait for cert-manager-webhook to be ready, which can take time if cert-manager
	// was re-installed after uninstalling on a cluster.
	cmd = exec.Command("kubectl", "wait", "deployment.apps/cert-manager-webhook",
		"--for", "condition=Available",
		"--namespace", "cert-manager",
		"--timeout", "5m",
	)

	_, err := Run(cmd)
	return err
}

// IsCertManagerCRDsInstalled checks if any Cert Manager CRDs are installed
// by verifying the existence of key CRDs related to Cert Manager.
func IsCertManagerCRDsInstalled() bool {
	// List of common Cert Manager CRDs
	certManagerCRDs := []string{
		"certificates.cert-manager.io",
		"issuers.cert-manager.io",
		"clusterissuers.cert-manager.io",
		"certificaterequests.cert-manager.io",
		"orders.acme.cert-manager.io",
		"challenges.acme.cert-manager.io",
	}

	// Execute the kubectl command to get all CRDs
	cmd := exec.Command("kubectl", "get", "crds")
	output, err := Run(cmd)
	if err != nil {
		return false
	}

	// Check if any of the Cert Manager CRDs are present
	crdList := GetNonEmptyLines(output)
	for _, crd := range certManagerCRDs {
		for _, line := range crdList {
			if strings.Contains(line, crd) {
				return true
			}
		}
	}

	return false
}

// TLSCertificates holds the generated certificate and key in PEM format
type TLSCertificates struct {
	CertPEM   []byte
	KeyPEM    []byte
	CACertPEM []byte
}

// GenerateSelfSignedCert generates a self-signed TLS certificate for webhook testing.
// It creates a CA certificate and a server certificate signed by that CA.
// The dnsNames should include the webhook service DNS names (e.g., "webhook-service.namespace.svc").
func GenerateSelfSignedCert(dnsNames []string) (*TLSCertificates, error) {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Vault Access Operator E2E Test CA"},
			CommonName:   "e2e-test-ca",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // Valid for 24 hours
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the CA certificate for signing the server cert
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	// Create server certificate template
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Vault Access Operator E2E Test"},
			CommonName:   dnsNames[0],
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // Valid for 24 hours
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	// Sign server certificate with CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Encode CA certificate to PEM
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	// Encode server certificate to PEM
	serverCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertDER,
	})

	// Encode server private key to PEM
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})

	return &TLSCertificates{
		CertPEM:   serverCertPEM,
		KeyPEM:    serverKeyPEM,
		CACertPEM: caCertPEM,
	}, nil
}

// CreateWebhookTLSSecret creates a Kubernetes TLS secret for webhook certificates.
// This is used for e2e tests to avoid requiring cert-manager.
func CreateWebhookTLSSecret(namespace, secretName string, certs *TLSCertificates) error {
	// Encode cert and key to base64 for kubectl
	certB64 := base64.StdEncoding.EncodeToString(certs.CertPEM)
	keyB64 := base64.StdEncoding.EncodeToString(certs.KeyPEM)

	// Create secret manifest
	secretManifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: kubernetes.io/tls
data:
  tls.crt: %s
  tls.key: %s
`, secretName, namespace, certB64, keyB64)

	// Apply the secret using kubectl
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(secretManifest)
	_, err := Run(cmd)
	if err != nil {
		return fmt.Errorf("failed to create webhook TLS secret: %w", err)
	}

	return nil
}

// DeleteWebhookTLSSecret deletes the webhook TLS secret.
func DeleteWebhookTLSSecret(namespace, secretName string) {
	cmd := exec.Command("kubectl", "delete", "secret", secretName, "-n", namespace, "--ignore-not-found=true")
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// PatchValidatingWebhookCABundle patches a ValidatingWebhookConfiguration with the CA bundle.
// This is needed when using self-signed certs instead of cert-manager's CA injection.
func PatchValidatingWebhookCABundle(webhookName string, caBundle []byte) error {
	caBundleB64 := base64.StdEncoding.EncodeToString(caBundle)

	// Patch each webhook in the configuration with the CA bundle
	patchJSON := fmt.Sprintf(
		`[{"op": "replace", "path": "/webhooks/0/clientConfig/caBundle", "value": "%s"},`+
			`{"op": "replace", "path": "/webhooks/1/clientConfig/caBundle", "value": "%s"}]`,
		caBundleB64, caBundleB64)

	cmd := exec.Command("kubectl", "patch", "validatingwebhookconfiguration", webhookName,
		"--type=json", "-p", patchJSON)
	_, err := Run(cmd)
	if err != nil {
		return fmt.Errorf("failed to patch ValidatingWebhookConfiguration with CA bundle: %w", err)
	}

	return nil
}

// LoadImageToKindClusterWithName loads a local docker image to the kind cluster
func LoadImageToKindClusterWithName(name string) error {
	cluster := "kind"
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	kindOptions := []string{"load", "docker-image", name, "--name", cluster}
	cmd := exec.Command("kind", kindOptions...)
	_, err := Run(cmd)
	return err
}

// GetNonEmptyLines converts given command output string into individual objects
// according to line breakers, and ignores the empty elements in it.
func GetNonEmptyLines(output string) []string {
	var res []string
	elements := strings.Split(output, "\n")
	for _, element := range elements {
		if element != "" {
			res = append(res, element)
		}
	}

	return res
}

// GetProjectDir will return the directory where the project is
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, fmt.Errorf("failed to get current working directory: %w", err)
	}
	wd = strings.ReplaceAll(wd, "/test/e2e", "")
	return wd, nil
}

// =============================================================================
// Vault E2E Test Helpers
// =============================================================================

// VaultNamespace is where the Vault dev server runs
const VaultNamespace = "vault"

// VaultPod is the name of the Vault pod
const VaultPod = "vault-0"

// RunVaultCommand executes a vault CLI command inside the Vault pod
func RunVaultCommand(args ...string) (string, error) {
	cmdArgs := append([]string{"exec", "-n", VaultNamespace, VaultPod, "--", "vault"}, args...)
	cmd := exec.Command("kubectl", cmdArgs...)
	return Run(cmd)
}

// RunVaultCommandWithToken executes a vault CLI command with a specific token
// This is useful for testing operations with a non-root token
func RunVaultCommandWithToken(token string, args ...string) (string, error) {
	// Set the VAULT_TOKEN environment variable for the command
	cmdArgs := []string{"exec", "-n", VaultNamespace, VaultPod, "--",
		"sh", "-c", fmt.Sprintf("VAULT_TOKEN=%s vault %s", token, strings.Join(args, " "))}
	cmd := exec.Command("kubectl", cmdArgs...)
	return Run(cmd)
}

// ReadVaultPolicy reads a policy from Vault and returns the HCL content
func ReadVaultPolicy(policyName string) (string, error) {
	return RunVaultCommand("policy", "read", policyName)
}

// VaultPolicyExists checks if a policy exists in Vault
func VaultPolicyExists(policyName string) (bool, error) {
	_, err := RunVaultCommand("policy", "read", policyName)
	if err != nil {
		// Check if the error indicates "not found"
		if strings.Contains(err.Error(), "No policy") || strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CreateUnmanagedVaultPolicy creates a policy directly in Vault (bypassing the operator)
// This is useful for testing conflict handling
func CreateUnmanagedVaultPolicy(policyName, hclContent string) error {
	// Write HCL to a temp location in the pod and apply it
	// Using heredoc-style input via stdin
	cmd := exec.Command("kubectl", "exec", "-n", VaultNamespace, VaultPod, "-i", "--",
		"vault", "policy", "write", policyName, "-")
	cmd.Stdin = strings.NewReader(hclContent)
	_, err := Run(cmd)
	return err
}

// DeleteVaultPolicy deletes a policy directly from Vault
func DeleteVaultPolicy(policyName string) error {
	_, err := RunVaultCommand("policy", "delete", policyName)
	return err
}

// ReadVaultRole reads a Kubernetes auth role from Vault and returns the JSON output
func ReadVaultRole(authPath, roleName string) (string, error) {
	return RunVaultCommand("read", "-format=json", fmt.Sprintf("%s/role/%s", authPath, roleName))
}

// VaultRoleExists checks if a Kubernetes auth role exists in Vault
func VaultRoleExists(authPath, roleName string) (bool, error) {
	_, err := RunVaultCommand("read", fmt.Sprintf("%s/role/%s", authPath, roleName))
	if err != nil {
		if strings.Contains(err.Error(), "No value found") || strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CreateUnmanagedVaultRole creates a Kubernetes auth role directly in Vault (bypassing the operator)
func CreateUnmanagedVaultRole(authPath, roleName string, boundSA, boundNS string, policies []string) error {
	args := []string{
		"write",
		fmt.Sprintf("%s/role/%s", authPath, roleName),
		fmt.Sprintf("bound_service_account_names=%s", boundSA),
		fmt.Sprintf("bound_service_account_namespaces=%s", boundNS),
		fmt.Sprintf("policies=%s", strings.Join(policies, ",")),
		"ttl=1h",
	}
	_, err := RunVaultCommand(args...)
	return err
}

// DeleteVaultRole deletes a Kubernetes auth role from Vault
func DeleteVaultRole(authPath, roleName string) error {
	_, err := RunVaultCommand("delete", fmt.Sprintf("%s/role/%s", authPath, roleName))
	return err
}

// VaultLoginWithJWT attempts to login to Vault using a JWT token
// Returns the client token if successful
func VaultLoginWithJWT(authPath, role, jwt string) (string, error) {
	output, err := RunVaultCommand("write", "-format=json",
		fmt.Sprintf("%s/login", authPath),
		fmt.Sprintf("role=%s", role),
		fmt.Sprintf("jwt=%s", jwt))
	if err != nil {
		return "", err
	}
	return output, nil
}

// GetServiceAccountToken retrieves a token for a service account using TokenRequest API
func GetServiceAccountToken(namespace, saName string) (string, error) {
	cmd := exec.Command("kubectl", "create", "token", saName, "-n", namespace)
	return Run(cmd)
}

// ReadVaultSecret reads a secret from the KV v2 secrets engine
func ReadVaultSecret(path string) (string, error) {
	return RunVaultCommand("kv", "get", "-format=json", path)
}

// WriteVaultSecret writes a secret to the KV v2 secrets engine
func WriteVaultSecret(path string, data map[string]string) error {
	args := make([]string, 0, 3+len(data))
	args = append(args, "kv", "put", path)
	for k, v := range data {
		args = append(args, fmt.Sprintf("%s=%s", k, v))
	}
	_, err := RunVaultCommand(args...)
	return err
}

// EnableVaultSecretsEngine enables a secrets engine at a given path
func EnableVaultSecretsEngine(engineType, path string) error {
	_, err := RunVaultCommand("secrets", "enable", "-path="+path, engineType)
	// Ignore "already enabled" errors
	if err != nil && strings.Contains(err.Error(), "already in use") {
		return nil
	}
	return err
}

// GetVaultManagedByMetadata reads the managed-by metadata for a policy
// The operator stores this in a specific path in the KV engine
func GetVaultManagedByMetadata(secretEnginePath, resourceType, name string) (string, error) {
	path := fmt.Sprintf("%s/data/_operator/%s/%s", secretEnginePath, resourceType, name)
	return RunVaultCommand("kv", "get", "-format=json", path)
}

// UncommentCode searches for target in the file and remove the comment prefix
// of the target content. The target content may span multiple lines.
func UncommentCode(filename, target, prefix string) error {
	// false positive
	// nolint:gosec
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file %q: %w", filename, err)
	}
	strContent := string(content)

	idx := strings.Index(strContent, target)
	if idx < 0 {
		return fmt.Errorf("unable to find the code %q to be uncomment", target)
	}

	out := new(bytes.Buffer)
	_, err = out.Write(content[:idx])
	if err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewBufferString(target))
	if !scanner.Scan() {
		return nil
	}
	for {
		if _, err = out.WriteString(strings.TrimPrefix(scanner.Text(), prefix)); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
		// Avoid writing a newline in case the previous line was the last in target.
		if !scanner.Scan() {
			break
		}
		if _, err = out.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
	}

	if _, err = out.Write(content[idx+len(target):]); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	// false positive
	// nolint:gosec
	if err = os.WriteFile(filename, out.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write file %q: %w", filename, err)
	}

	return nil
}
