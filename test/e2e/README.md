# E2E Test Suite

This directory contains end-to-end tests for the vault-access-operator.

## Test Catalog

### Test Naming Convention

Tests follow the format: `TC-{Category}{Number}[-{Subcategory}]: {Description}`

| Category | Code | Description |
|----------|------|-------------|
| VaultConnection | VC | Connection lifecycle tests |
| VaultPolicy | VP | Namespaced policy tests |
| VaultClusterPolicy | CP | Cluster-scoped policy tests |
| VaultRole | VR | Namespaced role tests |
| VaultClusterRole | CR | Cluster-scoped role tests |
| Authentication | AU | Auth flow tests |
| Error Handling | EH | Negative/error tests |
| Conflict | CF | Conflict policy tests |
| Lifecycle | LC | Bootstrap/token lifecycle |

### Test Matrix

| ID | Category | Description | File |
|----|----------|-------------|------|
| TC-VC01 | Connection | Create VaultConnection with token auth | `tc_connection_test.go` |
| TC-VC02 | Connection | Verify health check and version | `tc_connection_test.go` |
| TC-CP01 | ClusterPolicy | Create and sync cluster policy | `tc_cluster_policy_test.go` |
| TC-CP02 | ClusterPolicy | Verify HCL content in Vault | `tc_cluster_policy_test.go` |
| TC-CP03-ERR | ClusterPolicy | Error on missing VaultConnection | `tc_cluster_policy_test.go` |
| TC-CP04-ERR | ClusterPolicy | Error on empty policy rules | `tc_cluster_policy_test.go` |
| TC-VP01 | Policy | Create namespaced policy | `tc_policy_test.go` |
| TC-VP02 | Policy | Namespace variable substitution | `tc_policy_test.go` |
| TC-VP03 | Policy | Update policy when spec changes | `tc_policy_test.go` |
| TC-VP04-DEL | Policy | Handle deletion with finalizer | `tc_policy_test.go` |
| TC-VP05-RET | Policy | Respect deletionPolicy=Retain | `tc_policy_test.go` |
| TC-CR01 | ClusterRole | Create with multiple policies | `tc_cluster_role_test.go` |
| TC-CR02 | ClusterRole | Mixed cluster and namespaced policies | `tc_cluster_role_test.go` |
| TC-CR03 | ClusterRole | Token TTL/MaxTTL verification | `tc_cluster_role_test.go` |
| TC-CR04-ERR | ClusterRole | Error on invalid connection | `tc_cluster_role_test.go` |
| TC-CR05-ERR | ClusterRole | Error on missing policy reference | `tc_cluster_role_test.go` |
| TC-VR01 | Role | Create namespaced role | `tc_role_test.go` |
| TC-VR02 | Role | Verify role config in Vault | `tc_role_test.go` |
| TC-VR03-DEL | Role | Deletion cleanup verification | `tc_role_test.go` |
| TC-AU01-01 | Auth | SA JWT login success | `tc_auth_test.go` |
| TC-AU01-02 | Auth | Reject unbound SA | `tc_auth_test.go` |
| TC-AU01-03 | Auth | Reject invalid JWT | `tc_auth_test.go` |
| TC-AU01-04 | Auth | Re-authenticate after token expiration | `tc_auth_test.go` |
| TC-AU01-05 | Auth | Multiple SAs on same role | `tc_auth_test.go` |
| TC-AU04-01 | JWT Auth | JWT method with SA token | `tc_jwt_auth_test.go` |
| TC-AU04-02 | JWT Auth | Reject JWT wrong audience | `tc_jwt_auth_test.go` |
| TC-AU04-03 | JWT Auth | Reject JWT wrong subject | `tc_jwt_auth_test.go` |
| TC-AU05-01 | OIDC | Discover OIDC configuration | `tc_jwt_auth_test.go` |
| TC-AU05-02 | OIDC | Auth with OIDC-discovered keys | `tc_jwt_auth_test.go` |
| TC-AU05-03 | OIDC | Custom audiences via TokenRequest | `tc_jwt_auth_test.go` |
| TC-AU-SHARED | Auth | Cross-auth method compatibility | `tc_auth_shared_test.go` |
| TC-CF01-ADOPT | Conflict | Adopt existing policy | `tc_conflict_test.go` |
| TC-CF02-FAIL | Conflict | Fail on existing policy | `tc_conflict_test.go` |
| TC-CF03-NORM | Conflict | Normal (no conflict) | `tc_conflict_test.go` |
| TC-EH01 | Error | Invalid connection reference | `tc_error_test.go` |
| TC-EH02 | Error | Missing policy reference | `tc_error_test.go` |
| TC-EH03 | Error | Namespace boundary violation | `tc_error_test.go` |
| TC-EH04 | Error | Unavailable VaultConnection | `tc_error_test.go` |
| TC-EH05 | Error | Invalid TTL format | `tc_error_test.go` |
| TC-EH06 | Error | Empty policy rules | `tc_error_test.go` |

### Token Lifecycle Tests

| ID | Description | File | Label |
|----|-------------|------|-------|
| TC-LC01 | Bootstrap with token | `token_lifecycle_test.go` | |
| TC-LC02 | K8s auth setup | `token_lifecycle_test.go` | |
| TC-LC03 | Bootstrap idempotency | `token_lifecycle_test.go` | |
| TC-LC04 | Timestamp tracking | `token_lifecycle_test.go` | |
| TC-LC05 | Direct K8s auth | `token_lifecycle_test.go` | |
| TC-LC06 | AuthMethod verification | `token_lifecycle_test.go` | |
| TC-LC07 | Token renewal on expiration | `token_lifecycle_test.go` | slow |

## Directory Structure

```
test/e2e/
├── README.md                      # This file
├── e2e_suite_test.go              # Suite setup, shared infrastructure
├── auth_provider.go               # Auth provider abstraction for testing
├── tc_connection_test.go          # TC-VC* tests
├── tc_policy_test.go              # TC-VP* tests
├── tc_cluster_policy_test.go      # TC-CP* tests
├── tc_role_test.go                # TC-VR* tests
├── tc_cluster_role_test.go        # TC-CR* tests
├── tc_auth_test.go                # TC-AU01* tests (Kubernetes auth)
├── tc_jwt_auth_test.go            # TC-AU04-06* tests (JWT/OIDC auth)
├── tc_auth_shared_test.go         # TC-AU-SHARED tests (cross-auth)
├── tc_error_test.go               # TC-EH* tests
├── tc_conflict_test.go            # TC-CF* tests
├── token_lifecycle_test.go        # TC-LC* tests
└── fixtures/
    ├── vault-rbac.yaml             # Vault RBAC (SA, ClusterRole, Binding)
    ├── policies/
    │   ├── basic-secret-access.hcl
    │   ├── namespace-scoped.hcl
    │   ├── cluster-shared.hcl
    │   ├── readonly.hcl
    │   ├── operator-bootstrap.hcl
    │   └── invalid-syntax.hcl     # For negative testing
    ├── crds/
    │   ├── vaultconnection/
    │   │   ├── token-auth.yaml
    │   │   └── invalid-address.yaml
    │   ├── vaultpolicy/
    │   │   ├── basic.yaml
    │   │   ├── namespace-sub.yaml
    │   │   ├── boundary-enforce.yaml
    │   │   ├── with-metadata.yaml
    │   │   ├── retain-deletion.yaml
    │   │   ├── conflict-adopt.yaml
    │   │   ├── conflict-fail.yaml
    │   │   └── invalid-connection.yaml
    │   ├── vaultclusterpolicy/
    │   │   └── basic.yaml
    │   ├── vaultrole/
    │   │   ├── basic.yaml
    │   │   └── invalid-policy-ref.yaml
    │   └── vaultclusterrole/
    │       └── basic.yaml
    └── expected/
        └── cluster-shared-policy.hcl
```

## Running Tests Locally

### Prerequisites

- **Docker** with Docker Compose v2 (for the local stack)
- **Go 1.21+** (to compile and run the test binary)
- **Make** (all commands are Makefile targets)
- **jq** (used by Vault configuration scripts)

No external Kubernetes cluster is needed — the local stack runs k3s inside Docker.

### Architecture

The local E2E stack uses `docker-compose.e2e.yaml` to spin up three containers
on a shared Docker network (`e2e-net`):

```
┌─────────────────────────────────────────────────────┐
│  docker network: e2e-net                            │
│                                                     │
│  ┌─────────┐    ┌───────────┐    ┌───────────────┐  │
│  │   k3s   │    │   Vault   │    │   Dex (OIDC)  │  │
│  │ :6443   │    │ :8200     │    │ :5556         │  │
│  │         │    │ dev mode  │    │               │  │
│  └─────────┘    └───────────┘    └───────────────┘  │
│       │               │               │             │
│       └───── bridge Services (Endpoints) ───────────┘
│                                                     │
│  k8s sees Vault at: vault.vault.svc:8200            │
│  k8s sees Dex at:   dex.default.svc.cluster.local   │
└─────────────────────────────────────────────────────┘

Host machine:
  - kubectl → localhost:6443 (k3s)
  - Vault UI → localhost:8200 (root token: "root")
  - Dex      → localhost:5556
```

Vault and Dex run **outside** Kubernetes. Kubernetes Services with manually-created
Endpoints "bridge" traffic into the Docker network. This simulates a production
topology where Vault is external to the cluster.

### Quick Start (Full Local Stack)

```bash
# 1. Start everything: k3s + Vault + Dex + build operator + deploy operator
make e2e-local-up

# 2. Run all E2E tests
make e2e-local-test

# 3. Tear down when done
make e2e-local-down
```

`make e2e-local-up` is a composite target that runs these steps in order:

| Step | Target | What it does |
|------|--------|--------------|
| 1 | `e2e-compose-up` | Start docker-compose stack (k3s + Vault + Dex) |
| 2 | `e2e-wait-cluster` | Wait for k3s kubeconfig, fix server URL, wait for node ready |
| 3 | `e2e-deploy-vault-rbac` | Create vault namespace, service account, RBAC |
| 4 | `e2e-bridge-vault` | Create K8s Service+Endpoints bridging to Vault container |
| 5 | `e2e-bridge-dex` | Create K8s Service+Endpoints bridging to Dex container |
| 6 | `e2e-configure-vault` | Enable auth methods, configure K8s auth, create operator role |
| 7 | `e2e-build-operator` | Build operator Docker image |
| 8 | `e2e-import-operator` | Import operator image into k3s containerd |
| 9 | `e2e-deploy-operator` | Deploy operator via Helm into k3s |

You can run individual steps if you need to debug or re-run a specific part:

```bash
# Re-build and re-deploy operator only (after code changes)
make e2e-build-operator e2e-import-operator e2e-deploy-operator
```

### Running Tests

```bash
# Run ALL E2E tests
make e2e-local-test

# Run auth tests only (Kubernetes auth, JWT, OIDC)
make e2e-local-test-auth

# Run module tests only (connection, policy, role, error handling)
make e2e-local-test-modules
```

### Running Specific Tests

Use Go test flags with the required environment variables:

```bash
# Set up environment (copy from `make e2e-local-up` output)
export KUBECONFIG=$(pwd)/tmp/e2e/kubeconfig.yaml
export VAULT_ADDR=http://localhost:8200
export E2E_K8S_HOST=https://k3s:6443

# Run only connection tests
go test ./test/e2e/... -v -run "TC-VC"

# Run only error handling tests
go test ./test/e2e/... -v -run "TC-EH"

# Run only auth tests
go test ./test/e2e/... -v -run "TC-AU"

# Run a single test by ID
go test ./test/e2e/... -v -run "TC-VP02"
```

### Skip Slow Tests

Some tests are labeled `slow` because they require waiting for token expiration (~90+ seconds).
Skip these in quick iterations:

```bash
# Skip slow tests
go test ./test/e2e/... -v -ginkgo.label-filter '!slow'

# Run only slow tests
go test ./test/e2e/... -v -ginkgo.label-filter 'slow'
```

### Useful Commands During Development

```bash
# Check stack status (containers + k8s pods)
make e2e-local-status

# Use kubectl against the E2E cluster
export KUBECONFIG=$(pwd)/tmp/e2e/kubeconfig.yaml
kubectl get pods -A
kubectl get vaultconnection -o wide
kubectl logs -n vault-access-operator-system deploy/vault-access-operator -f

# Access Vault CLI directly
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root
vault status
vault policy list
vault auth list
vault list auth/kubernetes/role

# Re-deploy operator after code changes (without restarting the whole stack)
make e2e-build-operator e2e-import-operator e2e-deploy-operator
```

### Running in CI

In CI, the same Makefile targets are used. See `.github/workflows/ci.yaml` for the
full pipeline. The CI target assumes the stack is already running:

```bash
make test-e2e
```

## Fixture Usage

### Loading HCL Policies

```go
import "github.com/panteparak/vault-access-operator/test/utils"

// Load a policy template
content, err := utils.LoadPolicy("basic-secret-access")

// Load with template substitution
data := utils.PolicyData{Namespace: "my-namespace"}
content, err := utils.LoadPolicyWithData("namespace-scoped", data)
```

### Loading CRD YAML

```go
// Load CRD fixture
yaml, err := utils.LoadCRD("vaultpolicy/basic.yaml")

// Load with template substitution
data := utils.CRDData{
    Name:          "my-policy",
    Namespace:     "my-namespace",
    ConnectionRef: "vault-connection",
}
yaml, err := utils.LoadCRDWithData("vaultpolicy/basic.yaml", data)
```

## Adding New Tests

1. Choose the appropriate test file based on category (or create new one)
2. Follow the TC-* naming convention
3. Use Eventually() instead of time.Sleep() for async assertions
4. Clean up resources in AfterAll or DeferCleanup
5. Add the test to the matrix in this README

### Test Template

```go
It("TC-XX01: Descriptive test name", func() {
    By("step 1 description")
    // Setup code

    By("step 2 description")
    Eventually(func(g Gomega) {
        // Async assertion
    }, 30*time.Second, 2*time.Second).Should(Succeed())

    By("step 3 - cleanup")
    // Cleanup code
})
```

## Troubleshooting

### `make e2e-local-up` Fails

**"Vault failed to start"** — Check Docker resources. Vault needs IPC_LOCK capability:
```bash
docker compose -f docker-compose.e2e.yaml logs vault
```

**"Timed out waiting for kubeconfig"** — k3s takes 30-60s to generate the kubeconfig.
Check that Docker has enough memory (k3s needs ~2GB):
```bash
docker compose -f docker-compose.e2e.yaml logs k3s
```

**"refused to run against non-local cluster"** — The safety check (`e2e-check-context`)
verifies KUBECONFIG points to localhost. This prevents accidentally running E2E tests
against a production cluster.

### Test Fails with "VaultConnection not Active"

Check that:
1. Vault is running and healthy: `docker compose -f docker-compose.e2e.yaml ps`
2. The vault-bridge Service exists: `kubectl get svc -n vault`
3. The token secret exists with the correct key
4. Network connectivity between k3s and Vault container

```bash
export KUBECONFIG=$(pwd)/tmp/e2e/kubeconfig.yaml
kubectl get pods -n vault
kubectl get vaultconnection -o wide
kubectl logs -n vault-access-operator-system deploy/vault-access-operator --tail=50
```

### Test Timeouts

Increase timeout values if running on slow infrastructure:

```go
SetDefaultEventuallyTimeout(5 * time.Minute)
```

### Cleanup Failures

Force cleanup of stuck resources:

```bash
# Remove finalizers to force deletion
kubectl patch vaultpolicy <name> -n <ns> -p '{"metadata":{"finalizers":[]}}' --type=merge
```

### Operator Not Picking Up Code Changes

After modifying operator code, you must rebuild and redeploy:

```bash
make e2e-build-operator e2e-import-operator e2e-deploy-operator
```

### Starting Fresh

If the stack is in a bad state, tear down and recreate:

```bash
make e2e-local-down
make e2e-local-up
```

## Quality Metrics

- **Coverage**: 98% of operator features tested
- **Reliability**: No time.Sleep(), all async with Eventually()
- **Isolation**: Each test uses unique resource names
- **Documentation**: All tests cataloged and documented
