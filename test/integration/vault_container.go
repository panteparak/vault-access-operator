/*
Package integration provides testcontainers-based integration testing for the vault-access-operator.

This file implements the VaultTestContainer wrapper around testcontainers-go's Vault module,
providing a domain-specific API for spawning and configuring Vault instances in tests.
*/
package integration

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/modules/vault"
)

// VaultTestContainer wraps a testcontainers Vault instance with operator-specific utilities
type VaultTestContainer struct {
	*vault.VaultContainer
	rootToken   string
	address     string
	initialized bool
}

// VaultContainerOption configures a VaultTestContainer
type VaultContainerOption func(*vaultContainerOptions)

type vaultContainerOptions struct {
	imageTag        string
	rootToken       string
	enableTLS       bool
	tlsCertPath     string
	tlsKeyPath      string
	initCommands    []string
	envVars         map[string]string
	reuse           bool
	reuseName       string
	startupTimeout  time.Duration
	logLevel        string
	enableAuditLog  bool
	enableFileAudit bool
	policies        map[string]string // name -> HCL content
	secretEngines   []string          // paths to enable
}

func defaultOptions() *vaultContainerOptions {
	return &vaultContainerOptions{
		imageTag:       "1.17.2",
		rootToken:      "root-token",
		startupTimeout: 30 * time.Second,
		logLevel:       "info",
		envVars:        make(map[string]string),
		policies:       make(map[string]string),
		secretEngines:  []string{},
	}
}

// WithImageTag sets the Vault image tag
func WithImageTag(tag string) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.imageTag = tag
	}
}

// WithRootToken sets a custom root token
func WithRootToken(token string) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.rootToken = token
	}
}

// WithTLS enables TLS with the provided certificate and key paths
func WithTLS(certPath, keyPath string) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.enableTLS = true
		o.tlsCertPath = certPath
		o.tlsKeyPath = keyPath
	}
}

// WithReuse enables container reuse for faster test execution
func WithReuse(name string) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.reuse = true
		o.reuseName = name
	}
}

// WithStartupTimeout sets custom startup timeout
func WithStartupTimeout(timeout time.Duration) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.startupTimeout = timeout
	}
}

// WithLogLevel sets Vault log level (trace, debug, info, warn, err)
func WithLogLevel(level string) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.logLevel = level
	}
}

// WithAuditLog enables file audit logging
func WithAuditLog() VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.enableAuditLog = true
		o.enableFileAudit = true
	}
}

// WithPolicy pre-configures a policy in Vault
func WithPolicy(name, hcl string) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.policies[name] = hcl
	}
}

// WithOperatorPolicy adds the standard operator management policy.
// This matches the E2E operatorPolicyHCL and follows Principle of Least Privilege.
func WithOperatorPolicy() VaultContainerOption {
	return WithPolicy("operator-policy", `
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

# Auth method management (enable/disable kubernetes auth)
path "sys/auth" {
  capabilities = ["read"]
}
path "sys/auth/*" {
  capabilities = ["sudo", "create", "read", "update", "delete", "list"]
}

# Health checks
path "sys/health" {
  capabilities = ["read"]
}

# Secret engine management for testing (not in production operator policy)
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`)
}

// WithSecretEngine enables a secret engine at the specified path
func WithSecretEngine(path string) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.secretEngines = append(o.secretEngines, path)
	}
}

// WithKV2SecretEngine enables KV v2 secret engine at the specified path
// Note: Vault dev mode already has KV v2 at "secret/" so we skip that path
func WithKV2SecretEngine(path string) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		// Skip "secret" path as Vault dev mode already has KV v2 enabled there
		if path == "secret" || path == "secret/" {
			return
		}
		// Use || true to make the command idempotent (won't fail if already exists)
		o.initCommands = append(o.initCommands, fmt.Sprintf("secrets enable -path=%s kv-v2 || true", path))
	}
}

// WithEnvVar sets an environment variable for the container
func WithEnvVar(key, value string) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.envVars[key] = value
	}
}

// WithInitCommand adds a command to run during initialization
func WithInitCommand(cmd string) VaultContainerOption {
	return func(o *vaultContainerOptions) {
		o.initCommands = append(o.initCommands, cmd)
	}
}

// NewVaultTestContainer creates and starts a new Vault test container
func NewVaultTestContainer(ctx context.Context, opts ...VaultContainerOption) (*VaultTestContainer, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	// Build container options
	// Use || true for idempotent auth enable (may already be enabled)
	containerOpts := []testcontainers.ContainerCustomizer{
		vault.WithToken(options.rootToken),
		vault.WithInitCommand(
			"auth enable kubernetes || true",
		),
	}

	// Add policies as init commands
	for name, hcl := range options.policies {
		escapedHCL := strings.ReplaceAll(hcl, "'", "'\\''")
		cmd := fmt.Sprintf("policy write %s - <<'EOF'\n%s\nEOF", name, escapedHCL)
		containerOpts = append(containerOpts, vault.WithInitCommand(cmd))
	}

	// Add secret engines (use || true for idempotency)
	for _, path := range options.secretEngines {
		containerOpts = append(containerOpts, vault.WithInitCommand(
			fmt.Sprintf("secrets enable -path=%s kv || true", path),
		))
	}

	// Add custom init commands
	for _, cmd := range options.initCommands {
		containerOpts = append(containerOpts, vault.WithInitCommand(cmd))
	}

	// Add log level
	if options.logLevel != "" {
		containerOpts = append(containerOpts, testcontainers.WithEnv(map[string]string{
			"VAULT_LOG_LEVEL": options.logLevel,
		}))
	}

	// Add custom env vars
	if len(options.envVars) > 0 {
		containerOpts = append(containerOpts, testcontainers.WithEnv(options.envVars))
	}

	// Enable audit logging if requested (use || true for idempotency)
	if options.enableAuditLog {
		containerOpts = append(containerOpts, vault.WithInitCommand(
			"audit enable file file_path=/vault/logs/audit.log || true",
		))
	}

	// Create the container
	container, err := vault.Run(ctx, "hashicorp/vault:"+options.imageTag, containerOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to start vault container: %w", err)
	}

	// Get the address
	address, err := container.HttpHostAddress(ctx)
	if err != nil {
		container.Terminate(ctx) //nolint:errcheck
		return nil, fmt.Errorf("failed to get vault address: %w", err)
	}

	return &VaultTestContainer{
		VaultContainer: container,
		rootToken:      options.rootToken,
		address:        address,
		initialized:    true,
	}, nil
}

// Address returns the HTTP address of the Vault container
func (v *VaultTestContainer) Address() string {
	return v.address
}

// RootToken returns the root token
func (v *VaultTestContainer) RootToken() string {
	return v.rootToken
}

// Exec executes a vault CLI command inside the container
func (v *VaultTestContainer) Exec(ctx context.Context, cmd []string) (int, string, error) {
	// Prepend vault command and set token
	fullCmd := append([]string{"vault"}, cmd...)

	exitCode, reader, err := v.VaultContainer.Exec(ctx, fullCmd, exec.Multiplexed())
	if err != nil {
		return exitCode, "", fmt.Errorf("exec failed: %w", err)
	}

	var output string
	if reader != nil {
		data, err := io.ReadAll(reader)
		if err != nil {
			return exitCode, "", fmt.Errorf("failed to read exec output: %w", err)
		}
		output = string(data)
	}

	return exitCode, output, nil
}

// ExecRaw executes an arbitrary command inside the container (without prepending "vault").
// Use this for shell commands or non-vault commands.
func (v *VaultTestContainer) ExecRaw(ctx context.Context, cmd []string) (int, string, error) {
	exitCode, reader, err := v.VaultContainer.Exec(ctx, cmd, exec.Multiplexed())
	if err != nil {
		return exitCode, "", fmt.Errorf("exec failed: %w", err)
	}

	var output string
	if reader != nil {
		data, err := io.ReadAll(reader)
		if err != nil {
			return exitCode, "", fmt.Errorf("failed to read exec output: %w", err)
		}
		output = string(data)
	}

	return exitCode, output, nil
}

// WritePolicy writes a policy to Vault using the CLI
func (v *VaultTestContainer) WritePolicy(ctx context.Context, name, hcl string) error {
	// Use heredoc to write policy
	cmd := []string{"policy", "write", name, "-"}
	exitCode, output, err := v.Exec(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to write policy: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("policy write failed with exit code %d: %s", exitCode, output)
	}
	return nil
}

// ReadPolicy reads a policy from Vault
func (v *VaultTestContainer) ReadPolicy(ctx context.Context, name string) (string, error) {
	exitCode, output, err := v.Exec(ctx, []string{"policy", "read", name})
	if err != nil {
		return "", fmt.Errorf("failed to read policy: %w", err)
	}
	if exitCode != 0 {
		return "", fmt.Errorf("policy read failed with exit code %d: %s", exitCode, output)
	}
	return output, nil
}

// DeletePolicy deletes a policy from Vault
func (v *VaultTestContainer) DeletePolicy(ctx context.Context, name string) error {
	exitCode, output, err := v.Exec(ctx, []string{"policy", "delete", name})
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("policy delete failed with exit code %d: %s", exitCode, output)
	}
	return nil
}

// EnableKubernetesAuth enables and configures Kubernetes auth method
func (v *VaultTestContainer) EnableKubernetesAuth(ctx context.Context, k8sHost string) error {
	// Enable kubernetes auth if not already enabled
	exitCode, _, _ := v.Exec(ctx, []string{"auth", "enable", "kubernetes"})
	// Ignore error if already enabled (exit code 2)
	if exitCode != 0 && exitCode != 2 {
		return fmt.Errorf("failed to enable kubernetes auth")
	}

	// Configure kubernetes auth
	exitCode, output, err := v.Exec(ctx, []string{
		"write", "auth/kubernetes/config",
		fmt.Sprintf("kubernetes_host=%s", k8sHost),
		"disable_local_ca_jwt=true",
	})
	if err != nil {
		return fmt.Errorf("failed to configure kubernetes auth: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("kubernetes auth config failed with exit code %d: %s", exitCode, output)
	}
	return nil
}

// CreateKubernetesRole creates a Kubernetes auth role
func (v *VaultTestContainer) CreateKubernetesRole(
	ctx context.Context,
	roleName string,
	boundSAs []string,
	boundNSs []string,
	policies []string,
) error {
	cmd := []string{
		"write", fmt.Sprintf("auth/kubernetes/role/%s", roleName),
		fmt.Sprintf("bound_service_account_names=%s", strings.Join(boundSAs, ",")),
		fmt.Sprintf("bound_service_account_namespaces=%s", strings.Join(boundNSs, ",")),
		fmt.Sprintf("policies=%s", strings.Join(policies, ",")),
		"ttl=1h",
	}

	exitCode, output, err := v.Exec(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes role: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("kubernetes role creation failed with exit code %d: %s", exitCode, output)
	}
	return nil
}

// Health checks if Vault is healthy
func (v *VaultTestContainer) Health(ctx context.Context) (bool, error) {
	exitCode, _, err := v.Exec(ctx, []string{"status"})
	if err != nil {
		return false, err
	}
	// exit code 0 means healthy, initialized, and unsealed
	return exitCode == 0, nil
}

// Terminate stops and removes the container
func (v *VaultTestContainer) Terminate(ctx context.Context) error {
	if v.VaultContainer != nil {
		return v.VaultContainer.Terminate(ctx)
	}
	return nil
}

// Cleanup is an alias for Terminate for use with t.Cleanup()
func (v *VaultTestContainer) Cleanup(ctx context.Context) func() {
	return func() {
		v.Terminate(ctx) //nolint:errcheck
	}
}
