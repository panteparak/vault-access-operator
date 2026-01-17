# Vault Kubernetes Operator - Implementation Plan

## Project Overview

Build a Kubernetes operator using Operator SDK (Go) to manage HashiCorp Vault policies and roles via CRDs.

### Tech Stack
- **Language**: Go 1.22+
- **Framework**: Operator SDK v1.34+
- **Kubernetes**: 1.28+
- **Vault**: 1.15+

### Repository
```
vault-access-operator/
```

---

## Phase 1: Project Initialization

### Task 1.1: Initialize Operator SDK Project
```bash
# Create project
operator-sdk init --domain platform.io --repo github.com/example/vault-access-operator

# Create APIs
operator-sdk create api --group vault --version v1alpha1 --kind VaultConnection --resource --controller
operator-sdk create api --group vault --version v1alpha1 --kind VaultClusterPolicy --resource --controller
operator-sdk create api --group vault --version v1alpha1 --kind VaultPolicy --resource --controller
operator-sdk create api --group vault --version v1alpha1 --kind VaultClusterRole --resource --controller
operator-sdk create api --group vault --version v1alpha1 --kind VaultRole --resource --controller
```

### Task 1.2: Define Common Types
Create `api/v1alpha1/common_types.go`:
- Phase enum: `Pending`, `Syncing`, `Active`, `Conflict`, `Error`, `Deleting`
- ConflictPolicy enum: `Fail`, `Adopt`
- DeletionPolicy enum: `Delete`, `Retain`
- Condition struct with standard fields
- PolicyReference struct for role→policy references

### Task 1.3: Define VaultConnection Types
File: `api/v1alpha1/vaultconnection_types.go`

Spec fields:
- `address` (string, required)
- `tls.skipVerify` (bool)
- `tls.caSecretRef` (SecretKeySelector)
- `auth.kubernetes.role` (string)
- `auth.kubernetes.mountPath` (string)
- `auth.token.secretRef` (SecretKeySelector)
- `auth.appRole.roleId` (string)
- `auth.appRole.secretIdRef` (SecretKeySelector)
- `auth.appRole.mountPath` (string)
- `defaults.secretEnginePath` (string)
- `defaults.transitPath` (string)
- `defaults.authPath` (string)
- `healthCheckInterval` (string)

Status fields:
- `phase` (Phase)
- `vaultVersion` (string)
- `lastHeartbeat` (metav1.Time)
- `conditions` ([]Condition)

### Task 1.4: Define VaultClusterPolicy Types
File: `api/v1alpha1/vaultclusterpolicy_types.go`

Spec fields:
- `connectionRef` (string, required)
- `conflictPolicy` (ConflictPolicy, default: Fail)
- `rules` ([]PolicyRule, required)
- `deletionPolicy` (DeletionPolicy, default: Delete)

PolicyRule struct:
- `path` (string, required)
- `capabilities` ([]string, required) - enum: create, read, update, delete, list, sudo, deny
- `description` (string)
- `parameters.allowed` ([]string)
- `parameters.denied` ([]string)
- `parameters.required` ([]string)

Status fields:
- `phase` (Phase)
- `vaultName` (string)
- `managed` (bool)
- `rulesCount` (int)
- `lastAppliedHash` (string)
- `lastSyncedAt` (metav1.Time)
- `lastAttemptAt` (metav1.Time)
- `retryCount` (int)
- `nextRetryAt` (metav1.Time)
- `message` (string)
- `conditions` ([]Condition)

### Task 1.5: Define VaultPolicy Types
File: `api/v1alpha1/vaultpolicy_types.go`

Same as VaultClusterPolicy plus:
- `enforceNamespaceBoundary` (bool, default: true)

### Task 1.6: Define VaultClusterRole Types
File: `api/v1alpha1/vaultclusterrole_types.go`

Spec fields:
- `connectionRef` (string, required)
- `authPath` (string)
- `conflictPolicy` (ConflictPolicy)
- `serviceAccounts` ([]ServiceAccountRef, required) - name + namespace
- `policies` ([]PolicyReference, required)
- `tokenTTL` (string)
- `tokenMaxTTL` (string)
- `deletionPolicy` (DeletionPolicy)

Status fields:
- `phase` (Phase)
- `vaultRoleName` (string)
- `managed` (bool)
- `boundServiceAccounts` ([]string)
- `resolvedPolicies` ([]string)
- `lastSyncedAt` (metav1.Time)
- `retryCount` (int)
- `message` (string)
- `conditions` ([]Condition)

### Task 1.7: Define VaultRole Types
File: `api/v1alpha1/vaultrole_types.go`

Same as VaultClusterRole but:
- `serviceAccounts` is []string (names only, namespace implicit)

### Task 1.8: Generate CRDs and DeepCopy
```bash
make generate
make manifests
```

---

## Phase 2: Vault Client Package

### Task 2.1: Create Vault Client Wrapper
File: `pkg/vault/client.go`

```go
type Client struct {
    *api.Client
    connectionName string
}

func NewClient(config *api.Config) (*Client, error)
func (c *Client) Authenticate(ctx context.Context, auth AuthConfig) error
func (c *Client) IsHealthy(ctx context.Context) (bool, error)
```

### Task 2.2: Create Client Cache
File: `pkg/vault/client_cache.go`

```go
type ClientCache struct {
    clients map[string]*Client
    mu      sync.RWMutex
}

func NewClientCache() *ClientCache
func (c *ClientCache) Get(name string) (*Client, error)
func (c *ClientCache) Set(name string, client *Client)
func (c *ClientCache) Delete(name string)
func (c *ClientCache) Has(name string) bool
```

### Task 2.3: Create Auth Methods
File: `pkg/vault/auth.go`

```go
func AuthenticateKubernetes(client *api.Client, role, mountPath string) error
func AuthenticateToken(client *api.Client, token string) error
func AuthenticateAppRole(client *api.Client, roleId, secretId, mountPath string) error
```

### Task 2.4: Create Managed Resource Tracker
File: `pkg/vault/managed.go`

```go
const ManagedBasePath = "secret/data/vault-access-operator/managed"

func (c *Client) MarkPolicyManaged(ctx context.Context, policyName, k8sResource string) error
func (c *Client) IsPolicyManaged(ctx context.Context, policyName string) (bool, error)
func (c *Client) RemovePolicyManaged(ctx context.Context, policyName string) error
func (c *Client) MarkRoleManaged(ctx context.Context, roleName, k8sResource string) error
func (c *Client) IsRoleManaged(ctx context.Context, roleName string) (bool, error)
func (c *Client) RemoveRoleManaged(ctx context.Context, roleName string) error
```

### Task 2.5: Create HCL Generator
File: `pkg/vault/hcl.go`

```go
func GeneratePolicyHCL(rules []PolicyRule, namespace, name string) string
func substituteVariables(path, namespace, name string) string
```

### Task 2.6: Unit Tests for Vault Package
Files:
- `pkg/vault/client_test.go`
- `pkg/vault/client_cache_test.go`
- `pkg/vault/hcl_test.go`

---

## Phase 3: Retry and Error Handling

### Task 3.1: Define Error Types
File: `controllers/errors.go`

```go
type ConflictError struct { Message string }
type ValidationError struct { Message string }
type TransientError struct { Message string; Cause error }

func (e *ConflictError) Error() string
func (e *ValidationError) Error() string
func (e *TransientError) Error() string
func (e *TransientError) Unwrap() error

func IsRetryableError(err error) bool
```

### Task 3.2: Implement Exponential Backoff
File: `controllers/retry.go`

```go
const (
    InitialRetryDelay = 5 * time.Second
    MaxRetryDelay     = 30 * time.Minute
    BackoffMultiplier = 2.0
    JitterFactor      = 0.1
)

type RetryConfig struct {
    InitialDelay time.Duration
    MaxDelay     time.Duration
    Multiplier   float64
    JitterFactor float64
}

func DefaultRetryConfig() RetryConfig
func (c RetryConfig) CalculateBackoff(retryCount int) time.Duration

type RetryResult struct {
    Requeue      bool
    RequeueAfter time.Duration
    RetryCount   int
}

func ShouldRetry(err error, currentRetryCount int, config RetryConfig) RetryResult
```

### Task 3.3: Unit Tests for Retry
File: `controllers/retry_test.go`

Test cases:
- First retry delay
- Exponential increase
- Cap at max delay
- Jitter variance
- Non-retryable errors (ConflictError, ValidationError)
- Retryable errors

---

## Phase 4: VaultConnection Controller

### Task 4.1: Implement Controller
File: `controllers/vaultconnection_controller.go`

```go
type VaultConnectionReconciler struct {
    client.Client
    Log          logr.Logger
    Scheme       *runtime.Scheme
    ClientCache  *vault.ClientCache
}

func (r *VaultConnectionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
func (r *VaultConnectionReconciler) reconcileConnection(ctx context.Context, conn *v1alpha1.VaultConnection) error
func (r *VaultConnectionReconciler) buildVaultClient(ctx context.Context, conn *v1alpha1.VaultConnection) (*vault.Client, error)
func (r *VaultConnectionReconciler) authenticate(ctx context.Context, client *vault.Client, conn *v1alpha1.VaultConnection) error
func (r *VaultConnectionReconciler) getSecretData(ctx context.Context, ref *v1alpha1.SecretKeySelector) (string, error)
func (r *VaultConnectionReconciler) updateStatus(ctx context.Context, conn *v1alpha1.VaultConnection, err error) error
func (r *VaultConnectionReconciler) SetupWithManager(mgr ctrl.Manager) error
```

### Task 4.2: Health Check Loop
Add periodic health check for connections:
- Requeue after `healthCheckInterval`
- Update `lastHeartbeat` on success
- Update phase to Error on failure

### Task 4.3: Unit Tests
File: `controllers/vaultconnection_controller_test.go`

---

## Phase 5: VaultClusterPolicy Controller

### Task 5.1: Implement Controller
File: `controllers/vaultclusterpolicy_controller.go`

```go
type VaultClusterPolicyReconciler struct {
    client.Client
    Log          logr.Logger
    Scheme       *runtime.Scheme
    ClientCache  *vault.ClientCache
    RetryConfig  RetryConfig
}

func (r *VaultClusterPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
func (r *VaultClusterPolicyReconciler) reconcilePolicy(ctx context.Context, policy *v1alpha1.VaultClusterPolicy) error
func (r *VaultClusterPolicyReconciler) reconcileDelete(ctx context.Context, policy *v1alpha1.VaultClusterPolicy) (ctrl.Result, error)
func (r *VaultClusterPolicyReconciler) syncPolicy(ctx context.Context, policy *v1alpha1.VaultClusterPolicy, client *vault.Client) error
func (r *VaultClusterPolicyReconciler) checkConflict(ctx context.Context, policy *v1alpha1.VaultClusterPolicy, client *vault.Client) error
func (r *VaultClusterPolicyReconciler) resolvePolicyName(policy *v1alpha1.VaultClusterPolicy) string
func (r *VaultClusterPolicyReconciler) generateHCL(policy *v1alpha1.VaultClusterPolicy) string
func (r *VaultClusterPolicyReconciler) computeSpecHash(policy *v1alpha1.VaultClusterPolicy) string
func (r *VaultClusterPolicyReconciler) updateStatus(ctx context.Context, policy *v1alpha1.VaultClusterPolicy, err error, result RetryResult) error
func (r *VaultClusterPolicyReconciler) setCondition(policy *v1alpha1.VaultClusterPolicy, condType string, status metav1.ConditionStatus, reason, message string)
func (r *VaultClusterPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error
```

Reconcile flow:
1. Fetch resource
2. Handle deletion (finalizer)
3. Add finalizer if missing
4. Get Vault client from cache
5. Check for conflicts
6. Generate HCL
7. Apply to Vault
8. Mark as managed
9. Update status

### Task 5.2: Unit Tests
File: `controllers/vaultclusterpolicy_controller_test.go`

---

## Phase 6: VaultPolicy Controller

### Task 6.1: Implement Controller
File: `controllers/vaultpolicy_controller.go`

Same structure as VaultClusterPolicy plus:
- `validateNamespaceBoundary(policy *v1alpha1.VaultPolicy) error`
- Policy name: `{namespace}-{name}`
- Variable substitution: `{{namespace}}`, `{{name}}`

### Task 6.2: Namespace Boundary Validation
```go
func (r *VaultPolicyReconciler) validateNamespaceBoundary(policy *v1alpha1.VaultPolicy) error {
    if !policy.Spec.EnforceNamespaceBoundary {
        return nil
    }
    for _, rule := range policy.Spec.Rules {
        if !strings.Contains(rule.Path, "{{namespace}}") {
            return &ValidationError{...}
        }
        // Check namespace before wildcard
        nsIdx := strings.Index(rule.Path, "{{namespace}}")
        wcIdx := strings.Index(rule.Path, "*")
        if wcIdx != -1 && wcIdx < nsIdx {
            return &ValidationError{...}
        }
    }
    return nil
}
```

### Task 6.3: Unit Tests
File: `controllers/vaultpolicy_controller_test.go`

Test cases:
- Policy name resolution: `{namespace}-{name}`
- Namespace variable substitution
- Boundary validation (missing namespace, wildcard before namespace)
- HCL generation with parameters

---

## Phase 7: VaultClusterRole Controller

### Task 7.1: Implement Controller
File: `controllers/vaultclusterrole_controller.go`

```go
type VaultClusterRoleReconciler struct {
    client.Client
    Log          logr.Logger
    Scheme       *runtime.Scheme
    ClientCache  *vault.ClientCache
    RetryConfig  RetryConfig
}

func (r *VaultClusterRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
func (r *VaultClusterRoleReconciler) reconcileRole(ctx context.Context, role *v1alpha1.VaultClusterRole) error
func (r *VaultClusterRoleReconciler) reconcileDelete(ctx context.Context, role *v1alpha1.VaultClusterRole) (ctrl.Result, error)
func (r *VaultClusterRoleReconciler) syncRole(ctx context.Context, role *v1alpha1.VaultClusterRole, client *vault.Client) error
func (r *VaultClusterRoleReconciler) resolvePolicies(ctx context.Context, role *v1alpha1.VaultClusterRole) ([]string, error)
func (r *VaultClusterRoleReconciler) resolveRoleName(role *v1alpha1.VaultClusterRole) string
func (r *VaultClusterRoleReconciler) updateStatus(ctx context.Context, role *v1alpha1.VaultClusterRole, err error, result RetryResult) error
func (r *VaultClusterRoleReconciler) SetupWithManager(mgr ctrl.Manager) error
```

Policy resolution:
- VaultClusterPolicy: use `status.vaultName`
- VaultPolicy: lookup in specified namespace, use `status.vaultName`

### Task 7.2: Unit Tests
File: `controllers/vaultclusterrole_controller_test.go`

---

## Phase 8: VaultRole Controller

### Task 8.1: Implement Controller
File: `controllers/vaultrole_controller.go`

Same as VaultClusterRole with:
- Role name: `{namespace}-{name}`
- Service accounts: names only (namespace implicit from resource)
- Policy resolution: VaultPolicy defaults to same namespace

### Task 8.2: Unit Tests
File: `controllers/vaultrole_controller_test.go`

---

## Phase 9: Admission Webhooks

### Task 9.1: Create VaultPolicy Webhook
```bash
operator-sdk create webhook --group vault --version v1alpha1 --kind VaultPolicy --programmatic-validation
```

File: `webhooks/vaultpolicy_webhook.go`

Validations:
- Path syntax (regex: `^[a-zA-Z0-9/_*{}+-]+$`)
- Namespace boundary enforcement
- Deny not combined with other capabilities
- Parameters not both allowed and denied
- Capabilities are valid enum values

### Task 9.2: Create VaultRole Webhook
```bash
operator-sdk create webhook --group vault --version v1alpha1 --kind VaultRole --programmatic-validation
```

File: `webhooks/vaultrole_webhook.go`

Validations:
- At least one service account
- At least one policy reference
- Valid policy kinds (VaultPolicy, VaultClusterPolicy)
- VaultPolicy references don't specify namespace (must be same)

### Task 9.3: Webhook Tests
Files:
- `webhooks/vaultpolicy_webhook_test.go`
- `webhooks/vaultrole_webhook_test.go`

---

## Phase 10: Main Entry Point

### Task 10.1: Update main.go
File: `main.go`

```go
func main() {
    // Parse flags
    // Setup logger
    // Create manager

    // Initialize Vault client cache
    clientCache := vault.NewClientCache()
    retryConfig := controllers.DefaultRetryConfig()

    // Setup controllers
    if err := (&controllers.VaultConnectionReconciler{
        Client:      mgr.GetClient(),
        Log:         ctrl.Log.WithName("controllers").WithName("VaultConnection"),
        Scheme:      mgr.GetScheme(),
        ClientCache: clientCache,
    }).SetupWithManager(mgr); err != nil {
        setupLog.Error(err, "unable to create controller", "controller", "VaultConnection")
        os.Exit(1)
    }

    // ... other controllers

    // Setup webhooks
    if err := (&v1alpha1.VaultPolicy{}).SetupWebhookWithManager(mgr); err != nil {
        setupLog.Error(err, "unable to create webhook", "webhook", "VaultPolicy")
        os.Exit(1)
    }

    // ... other webhooks

    // Start manager
    if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
        setupLog.Error(err, "problem running manager")
        os.Exit(1)
    }
}
```

---

## Phase 11: Integration Tests

### Task 11.1: Test Suite Setup
File: `tests/integration/suite_test.go`

- Setup envtest
- Start Vault in dev mode (Docker)
- Configure Vault (enable KV, create operator policy)

### Task 11.2: Policy Integration Tests
File: `tests/integration/policy_test.go`

Test cases:
- Create policy → verify in Vault
- Update policy → verify HCL updated
- Delete policy → verify removed from Vault
- Conflict detection (pre-existing policy)
- Conflict adoption
- Deletion policy: Retain

### Task 11.3: Role Integration Tests
File: `tests/integration/role_test.go`

Test cases:
- Create role with policies
- Policy resolution across namespaces
- Service account binding
- Delete role → verify removed

---

## Phase 12: E2E Tests

### Task 12.1: E2E Test Setup
File: `tests/e2e/e2e_test.go`

Prerequisites:
- kind cluster
- Vault Helm chart installed
- Operator deployed

### Task 12.2: E2E Test Cases
- Full workflow: Connection → Policy → Role → Auth test
- Retry behavior with invalid connection
- Conflict handling
- Cross-namespace policy references

### Task 12.3: Test Fixtures
Directory: `tests/e2e/fixtures/`
- `vaultconnection.yaml`
- `vaultpolicy.yaml`
- `vaultrole.yaml`

---

## Phase 13: CI/CD

### Task 13.1: GitHub Actions Workflow
File: `.github/workflows/ci.yaml`

Jobs:
1. `lint` - golangci-lint
2. `unit-test` - go test ./controllers/... ./pkg/...
3. `integration-test` - Vault dev mode service
4. `e2e-test` - kind cluster + Vault Helm
5. `build` - Docker build + push
6. `release` - Helm package + GitHub release

### Task 13.2: Dockerfile
File: `Dockerfile`

Multi-stage build:
- Builder: golang:1.22-alpine
- Runtime: gcr.io/distroless/static:nonroot

### Task 13.3: Makefile
File: `Makefile`

Targets:
- `fmt`, `vet`, `lint`
- `test`, `test-integration`, `test-e2e`
- `build`, `docker-build`, `docker-push`
- `install`, `uninstall`, `deploy`, `undeploy`
- `generate`, `manifests`
- `kind-create`, `kind-delete`, `kind-load`
- `helm-lint`, `helm-package`

---

## Phase 14: Helm Chart

### Task 14.1: Create Chart Structure
Directory: `charts/vault-access-operator/`

Files:
- `Chart.yaml`
- `values.yaml`
- `templates/_helpers.tpl`
- `templates/deployment.yaml`
- `templates/serviceaccount.yaml`
- `templates/rbac.yaml`
- `templates/service.yaml` (metrics)
- `templates/servicemonitor.yaml` (optional)

### Task 14.2: Values Configuration
```yaml
replicaCount: 2
image:
  repository: ghcr.io/example/vault-access-operator
  tag: ""
  pullPolicy: IfNotPresent
serviceAccount:
  create: true
  name: vault-access-operator
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
metrics:
  enabled: true
  serviceMonitor:
    enabled: false
webhook:
  enabled: true
```

---

## Phase 15: Documentation

### Task 15.1: README.md
- Project overview
- Quick start
- Installation (Helm)
- CRD examples
- Configuration reference

### Task 15.2: docs/ Directory
- `getting-started.md`
- `crds/vaultconnection.md`
- `crds/vaultpolicy.md`
- `crds/vaultrole.md`
- `configuration.md`
- `troubleshooting.md`
- `migration.md`

---

## Implementation Order

```
Phase 1  → Phase 2  → Phase 3  → Phase 4  → Phase 5
(Init)     (Vault)    (Retry)    (Conn)     (ClusterPolicy)
   │                                            │
   └────────────────────────────────────────────┤
                                                ▼
Phase 6  → Phase 7  → Phase 8  → Phase 9  → Phase 10
(Policy)   (ClusterRole) (Role)  (Webhooks)  (Main)
                                                │
   ┌────────────────────────────────────────────┘
   ▼
Phase 11 → Phase 12 → Phase 13 → Phase 14 → Phase 15
(Integration) (E2E)    (CI/CD)    (Helm)     (Docs)
```

---

## File Checklist

### API Types
- [ ] `api/v1alpha1/common_types.go`
- [ ] `api/v1alpha1/vaultconnection_types.go`
- [ ] `api/v1alpha1/vaultclusterpolicy_types.go`
- [ ] `api/v1alpha1/vaultpolicy_types.go`
- [ ] `api/v1alpha1/vaultclusterrole_types.go`
- [ ] `api/v1alpha1/vaultrole_types.go`

### Vault Package
- [ ] `pkg/vault/client.go`
- [ ] `pkg/vault/client_cache.go`
- [ ] `pkg/vault/auth.go`
- [ ] `pkg/vault/managed.go`
- [ ] `pkg/vault/hcl.go`
- [ ] `pkg/vault/client_test.go`
- [ ] `pkg/vault/hcl_test.go`

### Controllers
- [ ] `controllers/errors.go`
- [ ] `controllers/retry.go`
- [ ] `controllers/retry_test.go`
- [ ] `controllers/vaultconnection_controller.go`
- [ ] `controllers/vaultclusterpolicy_controller.go`
- [ ] `controllers/vaultpolicy_controller.go`
- [ ] `controllers/vaultclusterrole_controller.go`
- [ ] `controllers/vaultrole_controller.go`
- [ ] `controllers/*_test.go`

### Webhooks
- [ ] `webhooks/vaultpolicy_webhook.go`
- [ ] `webhooks/vaultrole_webhook.go`
- [ ] `webhooks/*_test.go`

### Tests
- [ ] `tests/integration/suite_test.go`
- [ ] `tests/integration/policy_test.go`
- [ ] `tests/integration/role_test.go`
- [ ] `tests/e2e/e2e_test.go`
- [ ] `tests/e2e/fixtures/*.yaml`

### CI/CD & Build
- [ ] `Dockerfile`
- [ ] `Makefile`
- [ ] `.github/workflows/ci.yaml`
- [ ] `.golangci.yaml`

### Helm
- [ ] `charts/vault-access-operator/Chart.yaml`
- [ ] `charts/vault-access-operator/values.yaml`
- [ ] `charts/vault-access-operator/templates/*.yaml`

### Documentation
- [ ] `README.md`
- [ ] `docs/*.md`
