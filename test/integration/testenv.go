/*
Package integration provides the TestEnvironment for coordinating envtest with testcontainers.

TestEnvironment manages the lifecycle of:
- Kubernetes API server (via envtest)
- Vault test container (via testcontainers-go)
- Controller manager for integration tests
*/
package integration

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	vaultclient "github.com/panteparak/vault-access-operator/pkg/vault"
)

var setupLog = logf.Log.WithName("test-setup")

// TestEnvironment coordinates envtest and Vault container for integration tests
type TestEnvironment struct {
	// Kubernetes components
	Config    *rest.Config
	K8sClient client.Client
	TestEnv   *envtest.Environment
	Ctx       context.Context
	Cancel    context.CancelFunc

	// Vault components
	VaultContainer *VaultTestContainer
	VaultClient    *vaultclient.Client

	// Options
	opts *testEnvOptions
}

// TestEnvOption configures TestEnvironment
type TestEnvOption func(*testEnvOptions)

type testEnvOptions struct {
	crdPaths           []string
	vaultOpts          []VaultContainerOption
	setupVault         bool
	startupTimeout     time.Duration
	useExistingCluster bool
	vaultOnly          bool // If true, skip envtest and only start Vault
}

func defaultTestEnvOptions() *testEnvOptions {
	// Get the directory of this source file to compute absolute CRD path
	_, currentFile, _, _ := runtime.Caller(0)
	currentDir := filepath.Dir(currentFile)
	crdPath := filepath.Join(currentDir, "..", "..", "config", "crd", "bases")

	return &testEnvOptions{
		crdPaths: []string{
			crdPath,
		},
		vaultOpts:      []VaultContainerOption{},
		setupVault:     true,
		startupTimeout: 60 * time.Second,
	}
}

// WithCRDPaths sets custom CRD paths
func WithCRDPaths(paths ...string) TestEnvOption {
	return func(o *testEnvOptions) {
		o.crdPaths = paths
	}
}

// WithVaultOptions configures Vault container options
func WithVaultOptions(opts ...VaultContainerOption) TestEnvOption {
	return func(o *testEnvOptions) {
		o.vaultOpts = append(o.vaultOpts, opts...)
	}
}

// WithoutVault disables Vault container startup
func WithoutVault() TestEnvOption {
	return func(o *testEnvOptions) {
		o.setupVault = false
	}
}

// WithTestEnvTimeout sets startup timeout
func WithTestEnvTimeout(timeout time.Duration) TestEnvOption {
	return func(o *testEnvOptions) {
		o.startupTimeout = timeout
	}
}

// WithExistingCluster uses an existing cluster instead of envtest
func WithExistingCluster() TestEnvOption {
	return func(o *testEnvOptions) {
		o.useExistingCluster = true
	}
}

// WithVaultOnly skips envtest and only starts Vault container.
// Use this for tests that only need Vault (e.g., permission tests, policy tests).
func WithVaultOnly() TestEnvOption {
	return func(o *testEnvOptions) {
		o.vaultOnly = true
	}
}

// NewTestEnvironment creates a new test environment
func NewTestEnvironment(opts ...TestEnvOption) *TestEnvironment {
	options := defaultTestEnvOptions()
	for _, opt := range opts {
		opt(options)
	}

	return &TestEnvironment{
		opts: options,
	}
}

// Start initializes and starts the test environment
func (te *TestEnvironment) Start() error {
	// Set up logging
	logf.SetLogger(zap.New(zap.WriteTo(nil), zap.UseDevMode(true)))

	// Create context with cancellation
	te.Ctx, te.Cancel = context.WithCancel(context.Background())

	// Register CRDs with scheme
	if err := vaultv1alpha1.AddToScheme(scheme.Scheme); err != nil {
		return fmt.Errorf("failed to add scheme: %w", err)
	}

	// Start envtest only if not in vaultOnly mode
	if !te.opts.vaultOnly {
		te.TestEnv = &envtest.Environment{
			CRDDirectoryPaths:     te.opts.crdPaths,
			ErrorIfCRDPathMissing: true,
			UseExistingCluster:    &te.opts.useExistingCluster,
		}

		cfg, err := te.TestEnv.Start()
		if err != nil {
			return fmt.Errorf("failed to start envtest: %w", err)
		}
		te.Config = cfg

		// Create K8s client
		k8sClient, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
		if err != nil {
			te.TestEnv.Stop() //nolint:errcheck
			return fmt.Errorf("failed to create k8s client: %w", err)
		}
		te.K8sClient = k8sClient
	}

	// Start Vault container if enabled
	if te.opts.setupVault {
		if err := te.startVault(); err != nil {
			if te.TestEnv != nil {
				te.TestEnv.Stop() //nolint:errcheck
			}
			return fmt.Errorf("failed to start vault: %w", err)
		}
	}

	k8sHost := ""
	if te.Config != nil {
		k8sHost = te.Config.Host
	}
	setupLog.Info("test environment started",
		"k8s_host", k8sHost,
		"vault_address", te.VaultAddress(),
		"vault_only", te.opts.vaultOnly,
	)

	return nil
}

// startVault starts the Vault container and creates a client
func (te *TestEnvironment) startVault() error {
	ctx, cancel := context.WithTimeout(te.Ctx, te.opts.startupTimeout)
	defer cancel()

	// Default options for operator testing
	defaultOpts := []VaultContainerOption{
		WithOperatorPolicy(),
		WithLogLevel("info"),
	}
	allOpts := append(defaultOpts, te.opts.vaultOpts...)

	container, err := NewVaultTestContainer(ctx, allOpts...)
	if err != nil {
		return fmt.Errorf("failed to create vault container: %w", err)
	}
	te.VaultContainer = container

	// Create Vault client
	vaultClient, err := vaultclient.NewClient(vaultclient.ClientConfig{
		Address: container.Address(),
	})
	if err != nil {
		container.Terminate(ctx) //nolint:errcheck
		return fmt.Errorf("failed to create vault client: %w", err)
	}

	// Authenticate with root token
	if err := vaultClient.AuthenticateToken(container.RootToken()); err != nil {
		container.Terminate(ctx) //nolint:errcheck
		return fmt.Errorf("failed to authenticate vault client: %w", err)
	}

	te.VaultClient = vaultClient
	return nil
}

// Stop tears down the test environment
func (te *TestEnvironment) Stop() error {
	var errs []error

	// Cancel context first
	if te.Cancel != nil {
		te.Cancel()
	}

	// Stop Vault container
	if te.VaultContainer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := te.VaultContainer.Terminate(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop vault: %w", err))
		}
	}

	// Stop envtest
	if te.TestEnv != nil {
		if err := te.TestEnv.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop envtest: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}

	setupLog.Info("test environment stopped")
	return nil
}

// VaultAddress returns the Vault HTTP address
func (te *TestEnvironment) VaultAddress() string {
	if te.VaultContainer != nil {
		return te.VaultContainer.Address()
	}
	return ""
}

// VaultToken returns the Vault root token
func (te *TestEnvironment) VaultToken() string {
	if te.VaultContainer != nil {
		return te.VaultContainer.RootToken()
	}
	return ""
}

// NewVaultClient creates a new authenticated Vault client
func (te *TestEnvironment) NewVaultClient() (*vaultclient.Client, error) {
	if te.VaultContainer == nil {
		return nil, fmt.Errorf("vault container not started")
	}

	vc, err := vaultclient.NewClient(vaultclient.ClientConfig{
		Address: te.VaultContainer.Address(),
	})
	if err != nil {
		return nil, err
	}

	if err := vc.AuthenticateToken(te.VaultContainer.RootToken()); err != nil {
		return nil, err
	}

	return vc, nil
}

// CreateManager creates a controller manager for testing
func (te *TestEnvironment) CreateManager() (ctrl.Manager, error) {
	mgr, err := ctrl.NewManager(te.Config, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}
	return mgr, nil
}

// WaitForVaultHealthy waits for Vault to be healthy
func (te *TestEnvironment) WaitForVaultHealthy(timeout time.Duration) error {
	if te.VaultContainer == nil {
		return fmt.Errorf("vault container not started")
	}

	ctx, cancel := context.WithTimeout(te.Ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for vault to be healthy")
		case <-ticker.C:
			healthy, err := te.VaultContainer.Health(ctx)
			if err == nil && healthy {
				return nil
			}
		}
	}
}

// GetVaultLogs returns the last N lines of Vault container logs.
// This is useful for debugging test failures.
func (te *TestEnvironment) GetVaultLogs(ctx context.Context, lines int) (string, error) {
	if te.VaultContainer == nil {
		return "", fmt.Errorf("vault container not running")
	}

	// Get logs from the container
	reader, err := te.VaultContainer.Logs(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get vault logs: %w", err)
	}
	defer reader.Close()

	logs, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read vault logs: %w", err)
	}

	// Return last N lines
	allLines := strings.Split(string(logs), "\n")
	if len(allLines) > lines {
		allLines = allLines[len(allLines)-lines:]
	}
	return strings.Join(allLines, "\n"), nil
}

// DumpVaultLogs writes Vault container logs to GinkgoWriter.
// Call this on test failure to capture debugging information.
func (te *TestEnvironment) DumpVaultLogs(ctx context.Context) {
	logs, err := te.GetVaultLogs(ctx, 100)
	if err != nil {
		fmt.Fprintf(GinkgoWriter, "Failed to get Vault logs: %v\n", err)
		return
	}
	fmt.Fprintf(GinkgoWriter, "\n=== VAULT LOGS (last 100 lines) ===\n%s\n=== END VAULT LOGS ===\n", logs)
}
