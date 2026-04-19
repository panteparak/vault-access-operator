# Vault Access Operator — Internal Project Overview

> **Audience:** Contributors, reviewers, and maintainers working on the operator's internals.
> For user-facing docs (install, CRD examples, auth methods), see [docs/index.md](../index.md).

## What This Project Does

Vault Access Operator is a Kubernetes controller-manager that lets platform teams declare **HashiCorp Vault policies**, **Kubernetes auth roles**, and the **Vault connections** behind them as native Kubernetes CRDs. It reconciles these CRDs toward the actual state inside Vault: creating missing resources, correcting drift, cleaning up on deletion, and surfacing failures through Kubernetes status, conditions, and events.

It sits between your cluster's service accounts (which need to authenticate to Vault) and your Vault server (which needs policies describing what they can read/write). The operator owns the glue: it authenticates the operator itself, pushes your declared config into Vault, and watches for divergence.

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Language | `Go 1.22+` | controller binary |
| Framework | `controller-runtime v0.21+` | manager, caches, predicates, webhooks |
| CRD tooling | `kubebuilder` markers + `controller-gen` | CRD + RBAC + deepcopy generation |
| Vault SDK | `github.com/hashicorp/vault/api v1.22` | Vault REST calls |
| K8s SDK | `client-go` + `apimachinery` | K8s REST + TokenRequest API |
| Logging | `go-logr` + `zap` | structured logs with `reconcileID` correlation |
| Metrics | `prometheus/client_golang` (via `controller-runtime/metrics`) | gauges + counters under `vault_access_operator_*` |
| Test (unit) | `testing` stdlib + `testify` | table-driven unit tests, `httptest.Server` for mock Vault |
| Test (integration) | `ginkgo v2` + `gomega` + `envtest` + `testcontainers-go` | real K8s API + Vault container |
| Test (e2e) | `ginkgo v2` + k3s/Docker Compose | full cluster with Vault, Dex, operator |
| Build | `Makefile` + multi-stage `Dockerfile` | 32KB Makefile drives everything |
| Packaging | Helm chart (`charts/`) + OCI image | distribution |
| CI | GitHub Actions (`.github/`) | lint, test, release |

## Repository Structure

```
vault-access-operator/
├── cmd/main.go                 # Binary entry point — wires features, starts manager
├── api/v1alpha1/               # CRD Go types (all 5 kinds + common + accessors)
│   ├── vaultconnection_types.go
│   ├── vaultpolicy_types.go
│   ├── vaultclusterpolicy_types.go
│   ├── vaultrole_types.go
│   ├── vaultclusterrole_types.go
│   ├── common_types.go         # Phase, DriftMode, ConflictPolicy, etc.
│   └── sync_status_accessors.go # Generic status getters/setters
│
├── features/                   # Feature-Driven Design — one folder per CRD family
│   ├── connection/             # VaultConnection reconciliation + auth + ClientCache provider
│   ├── policy/                 # VaultPolicy + VaultClusterPolicy (shared Handler + PolicyAdapter)
│   ├── role/                   # VaultRole + VaultClusterRole (shared Handler + RoleAdapter)
│   └── discovery/              # Scans Vault for unmanaged resources, auto-creates CRs
│
├── shared/                     # Cross-feature utilities
│   ├── controller/
│   │   ├── base/               # BaseReconciler[T] — Template Method for all CRDs
│   │   ├── workflow/           # SyncWorkflow + CleanupWorkflow — the 9-step orchestration
│   │   ├── binding/            # Vault path builders (sys/policies/acl/{name}, auth/{mount}/role/{name})
│   │   ├── conditions/         # K8s-style condition list merge/update
│   │   ├── drift/              # Comparator — order-insensitive slice + scalar diffs
│   │   ├── driftmode/          # Cascading resolution (resource → connection → global default)
│   │   ├── hash/               # Deterministic SHA-256 of role data
│   │   ├── syncerror/          # Error classification → phase/condition/event
│   │   ├── vaultclient/        # Resolve connectionRef → *vault.Client
│   │   └── watches/            # Predicate + EnqueueRequestsFromMapFunc helpers
│   ├── events/                 # Type-safe in-process event bus (Subscribe/Publish)
│   └── infrastructure/errors/  # TransientError, ValidationError, ConflictError, DependencyError
│
├── pkg/                        # Importable utilities
│   ├── vault/                  # Vault client wrapper: HCL gen, managed markers, client cache
│   │   ├── auth/               # JWT/OIDC/AWS/GCP login data generators
│   │   ├── bootstrap/          # One-time Vault setup (creates k8s auth mount, role, policy)
│   │   └── token/              # TokenRequestProvider, MountedTokenProvider, lifecycle, rotation
│   ├── cleanup/                # Persistent retry queue (ConfigMap-backed) — NOT WIRED INTO main.go
│   ├── orphan/                 # Detects managed-but-deleted resources — NOT WIRED INTO main.go
│   ├── metrics/                # Prometheus metric registrations
│   └── logger/                 # Logger key constants
│
├── internal/webhook/           # Admission webhooks (VaultPolicy, VaultRole validators)
├── charts/                     # Helm chart
├── config/                     # Kustomize bases (RBAC, CRDs, samples)
├── test/                       # Integration (`test/integration/`) + e2e (`test/e2e/`)
└── docs/                       # User docs (MkDocs)
    └── internal/               # ← THIS series of contributor docs
```

## Quick Start (Development)

```bash
# Prerequisites: Go 1.22+, Docker, kubectl, make
make setup-envtest                   # one-time: install envtest binaries
make build                           # build binary
make test                            # unit tests only
make test-integration                # Ginkgo + Vault testcontainer
make manifests generate              # regenerate CRDs and deepcopy
make e2e-local-up                    # k3s + Vault + Dex + operator via docker-compose
make e2e-local-test                  # run all e2e scenarios
make e2e-local-down                  # teardown
```

## Key Concepts (Glossary)

| Term | Definition |
|------|------------|
| **Reconciliation** | The controller-runtime loop that calls `Reconcile(req)` on each observed change. Always idempotent. |
| **Finalizer** | K8s metadata entry (`vault.platform.io/finalizer`) that blocks deletion until `Cleanup()` runs. |
| **Drift** | Divergence between the declared spec and what exists in Vault. Three modes: `ignore`, `detect`, `correct`. |
| **Adoption** | Taking ownership of a Vault resource that already existed. Opt-in via `vault.platform.io/adopt=true` annotation or `ConflictPolicy: Adopt`. |
| **Managed marker** | KV-v2 entry at `secret/data/vault-access-operator/managed/{policies,roles}/{name}` storing the K8s owner reference. Used for orphan + discovery + conflict checks. |
| **Bootstrap** | One-time setup using a high-privilege root/management token to enable the k8s auth mount, create the operator's own role + policy, then (optionally) self-revoke. |
| **Binding** | `VaultResourceBinding` subresource in status linking a CR to its concrete Vault path (e.g., `sys/policies/acl/default-app`). |
| **Adapter** | Interface (`PolicyAdapter`, `RoleAdapter`) unifying namespaced + cluster-scoped variants so one `Handler` services both. |
| **Workflow** | `SyncWorkflow` / `CleanupWorkflow` — the shared 9-step orchestration called from the Handler. |
| **ResourceOps** | Interface implemented per resource kind (`PolicyOps`, `RoleOps`) supplying the varying steps (`WriteToVault`, `DetectDrift`, `CheckConflict`, etc.). |
| **ClientCache** | In-memory map of `connectionName → *vault.Client`, owned by the connection feature. |
| **reconcileID** | 8-char hex correlation ID generated per reconcile call, written to logs and status for kubectl-based log filtering. |
| **Phase** | CRD-level state machine: `Pending → Syncing → Active` (or `Conflict`/`Error`/`Deleting`). |

## CRD Summary

| CRD | Scope | Key Spec Fields | Vault Target |
|-----|-------|-----------------|--------------|
| `VaultConnection` | Cluster | `address`, `auth.{bootstrap,kubernetes,token,appRole,jwt,oidc,aws,gcp}`, `defaults`, `discovery` | N/A (the operator's view of Vault) |
| `VaultPolicy` | Namespaced | `connectionRef`, `rules[]`, `enforceNamespaceBoundary`, `driftMode` | `sys/policies/acl/{namespace}-{name}` |
| `VaultClusterPolicy` | Cluster | `connectionRef`, `rules[]`, `driftMode` | `sys/policies/acl/{name}` |
| `VaultRole` | Namespaced | `connectionRef`, `authPath`, `serviceAccounts[]`, `policies[]`, `tokenTTL`, `jwt` | `auth/{authPath}/role/{namespace}-{name}` |
| `VaultClusterRole` | Cluster | `connectionRef`, `authPath`, `serviceAccounts[]` (with ns), `policies[]` | `auth/{authPath}/role/{name}` |

## Configuration Reference

### Command-line Flags (cmd/main.go:64-97)

| Flag | Default | Description |
|------|---------|-------------|
| `--metrics-bind-address` | `0` (off) | `:8443` HTTPS / `:8080` HTTP / `0` disables |
| `--metrics-secure` | `true` | serve metrics over HTTPS |
| `--metrics-cert-path` | — | directory with `tls.crt`/`tls.key` |
| `--webhook-cert-path` | — | directory with webhook certs (required if `--enable-webhooks`) |
| `--enable-webhooks` | `false` | enable admission webhooks |
| `--enable-http2` | `false` | disabled by default (CVE-2023-44487) |
| `--health-probe-bind-address` | `:8081` | `/healthz`, `/readyz` |
| `--leader-elect` | `false` | leader election for HA deployments |

### Environment Variables

| Variable | Default | Read at |
|----------|---------|---------|
| `OPERATOR_SERVICE_ACCOUNT` | `vault-access-operator-controller-manager` | [handler.go:833](../../features/connection/controller/handler.go:833) |
| `OPERATOR_NAMESPACE` | read from `/var/run/secrets/.../namespace`, fallback `vault-access-operator-system` | [handler.go:841](../../features/connection/controller/handler.go:841) |
| `OPERATOR_REQUEUE_SUCCESS_INTERVAL` | `30s` | [base/status.go](../../shared/controller/base/status.go) |
| `OPERATOR_REQUEUE_ERROR_INTERVAL` | `30s` | [base/status.go](../../shared/controller/base/status.go) |
| `OPERATOR_MIN_SCAN_INTERVAL` | `5m` | [discovery/controller/controller.go:50](../../features/discovery/controller/controller.go:50) |

### Annotations (recognized on CRs)

| Annotation | Effect |
|------------|--------|
| `vault.platform.io/adopt=true` | take over a Vault resource that already exists; overrides `ConflictPolicy` |
| `vault.platform.io/allow-destructive=true` | required when `DriftMode: correct` — unlocks writes that would overwrite out-of-band changes |
| `vault.platform.io/discovery-pending=true` | added by discovery auto-create; tells `PolicyOps.WriteToVault` to **skip** the write until the user fills in real rules (raw string — see [IMPROVEMENTS.md §30](IMPROVEMENTS.md#30-raw-string-annotations-lack-constants-generalizes-14)) |
| `vault.platform.io/discovered-at=<RFC3339>` | timestamp, informational; constant `AnnotationDiscovered` at [common_types.go:447](../../api/v1alpha1/common_types.go:447) |
| `vault.platform.io/discovered-from=<connName>` | source connection for a discovered CR (raw string) |
| `vault.platform.io/reconcile-now=<any value>` | force an immediate reconcile of the CR even when spec.generation didn't change. Cleared by the operator after a successful sync (single-shot trigger). Set via `kubectl annotate vaultpolicy foo vault.platform.io/reconcile-now="$(date -Iseconds)" --overwrite`. Constant `AnnotationReconcileNow`. |
| `vault.platform.io/dry-run=true` | preview mode — operator skips ALL Vault writes (Write/Delete/MarkManaged) for this CR and surfaces the would-be operation via the `DryRun` status condition. Persistent (does NOT auto-clear); user removes when ready to apply. Combine with `DriftMode: correct` to preview what a correction WOULD overwrite. Constant `AnnotationDryRun` ([§I](IMPROVEMENTS.md#i-no-dry-run--plan-mode-still-missing)). |

## Document Index

Read in order for the clearest picture:

1. [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) — you are here
2. [ARCHITECTURE.md](ARCHITECTURE.md) — static layers, patterns, CRD relationships
3. [FLOW_OVERVIEW.md](FLOW_OVERVIEW.md) — ports, types, errors, file artifacts shared across flows
4. [FLOW_LIFECYCLE.md](FLOW_LIFECYCLE.md) — manager startup, leader election, shutdown
5. [FLOW_CONNECTION.md](FLOW_CONNECTION.md) — VaultConnection: bootstrap, auth, renewal, health
6. [FLOW_POLICY.md](FLOW_POLICY.md) — VaultPolicy / VaultClusterPolicy sync lifecycle
7. [FLOW_ROLE.md](FLOW_ROLE.md) — VaultRole / VaultClusterRole sync lifecycle
8. [FLOW_DISCOVERY.md](FLOW_DISCOVERY.md) — scanning, matching, auto-creation
9. [FLOW_DELETION.md](FLOW_DELETION.md) — finalizers, cleanup queue, orphan detection
10. [FLOW_AUTH.md](FLOW_AUTH.md) — auth-backend branching, TokenProvider, lifecycle, rotation
11. [FLOW_WEBHOOK.md](FLOW_WEBHOOK.md) — admission validators, TLS, cert-manager integration
12. [FLOW_EVENTS.md](FLOW_EVENTS.md) — event bus mechanics, publisher/subscriber matrix
13. [FLOW_METRICS.md](FLOW_METRICS.md) — Prometheus metrics, emission sites, dead metrics
14. [INSTRUCTIONS.md](INSTRUCTIONS.md) — **contributor procedures** (add an auth method, debug a stuck reconcile, etc.) ⭐
15. [IMPROVEMENTS.md](IMPROVEMENTS.md) — **disconnects, duplicates, gaps, and recommendations** ⭐
