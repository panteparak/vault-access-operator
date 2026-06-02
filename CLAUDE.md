# CLAUDE.md — Vault Access Operator

Orientation file for Claude Code sessions in this repo. Auto-loaded into every conversation. Keep it under ~200 lines so it stays in context efficiently.

## Project at a glance

A Kubernetes operator that manages HashiCorp Vault policies, roles, and connections via 5 CRDs (3 namespaced, 2 cluster-scoped). Go 1.25, controller-runtime v0.23, kubebuilder layout. Domain: platform.io.

CRDs: `VaultConnection` (namespaced), `VaultPolicy` + `VaultClusterPolicy`, `VaultRole` + `VaultClusterRole`.

## Where things live

| Want to … | Look in |
|-----------|---------|
| Add or modify a controller | `features/<connection\|policy\|role\|discovery>/controller/` |
| Add a cross-cutting concern | `shared/controller/<base\|binding\|conditions\|conflict\|drift\|driftmode\|dryrun\|hash\|syncerror\|vaultclient\|watches\|workflow>/` |
| Modify a CRD schema | `api/v1alpha1/*_types.go` — then run `make manifests generate helm-update-crds` |
| Add a webhook check | `internal/webhook/` |
| Add a Vault auth method | `pkg/vault/auth/` + `api/v1alpha1/vaultconnection_types.go` |
| Write a unit test | colocated `*_test.go` next to the code |
| Write an integration test | `test/integration/<category>/` (16 categories) |
| Write an E2E test | `test/e2e/tc_*_test.go` |
| Edit the public docs site | `docs/` (excluding `docs/internal/`) → renders at `mkdocs build` |
| Edit the contributor docs site | `docs/internal/` → renders at `mkdocs build -f mkdocs-internal.yml` |
| Record an architectural decision | `docs/adr/` — use `/new-adr <slug>` |
| Define a domain term | `docs/internal/CONTEXT.md` |

## Before editing X, read Y

| Editing | Read first |
|---------|-----------|
| `features/connection/controller/` | [`docs/internal/FLOW_CONNECTION.md`](docs/internal/FLOW_CONNECTION.md) |
| `features/policy/controller/` | [`docs/internal/FLOW_POLICY.md`](docs/internal/FLOW_POLICY.md) |
| `features/role/controller/` | [`docs/internal/FLOW_ROLE.md`](docs/internal/FLOW_ROLE.md) |
| `features/discovery/controller/` | [`docs/internal/FLOW_DISCOVERY.md`](docs/internal/FLOW_DISCOVERY.md) |
| `shared/controller/workflow/` | [`docs/internal/FLOW_POLICY.md`](docs/internal/FLOW_POLICY.md) (the canonical 9-step sequence) + ADRs 0001, 0002 |
| `shared/controller/drift/` or `driftmode/` | [`ADR 0003`](docs/adr/0003-two-level-drift-and-conflict-config.md) |
| `shared/events/` | [`ADR 0004`](docs/adr/0004-event-bus-closure-capture.md), [`FLOW_EVENTS.md`](docs/internal/FLOW_EVENTS.md) |
| Webhook (`internal/webhook/`) | [`docs/internal/FLOW_WEBHOOK.md`](docs/internal/FLOW_WEBHOOK.md), [`docs/webhooks.md`](docs/webhooks.md) |
| `cmd/main.go` | [`docs/internal/FLOW_LIFECYCLE.md`](docs/internal/FLOW_LIFECYCLE.md), [`docs/configuration.md`](docs/configuration.md) |
| CRD type (`api/v1alpha1/*_types.go`) | [`docs/api-reference.md`](docs/api-reference.md) for the public-facing field docs |
| Cleanup behavior | [`ADR 0005`](docs/adr/0005-cleanup-failure-configmap-queue.md), [`FLOW_DELETION.md`](docs/internal/FLOW_DELETION.md) |

When in doubt, [`docs/internal/FLOW_OVERVIEW.md`](docs/internal/FLOW_OVERVIEW.md) is the map.

## Test invariants (carry these in your head)

- **Vault mocks** — use `httptest.Server` against the concrete `*vault.Client`, not an interface mock. The Vault SDK v1.22's `ListPolicies` calls `GET /v1/sys/policies/acl?list=true` with a `data.keys` response (NOT the older `sys/policy` with `policies`).
- **Adapter staleness** — `updateStatusWithRetry` re-fetches from K8s; callers must re-fetch the adapter between sync passes.
- **Event bus async** — `PublishAsync` fires goroutines; use buffered channels for test synchronization. See [`ADR 0004`](docs/adr/0004-event-bus-closure-capture.md).
- **Build tags** — integration tests gated by `//go:build integration`; e2e tests need `make e2e-local-up` infrastructure.
- **Fake K8s client** — use `fake.NewClientBuilder().WithStatusSubresource(...)` for status update support; otherwise `Status().Update()` silently no-ops.
- **Test IDs** — unit tests use `TestSync*_*` Go convention; integration uses `INT-{CAT}{NN}`; e2e uses `TC-{CAT}{NN}`.

## Make targets cheat sheet

```
make test                  # Unit tests (excludes integration + e2e via build tags)
make test-integration      # Integration tests (needs Docker for Testcontainers)
make lint                  # golangci-lint with project config
make lint-fix              # golangci-lint with --fix
make manifests             # Regenerate CRDs from api/v1alpha1 markers
make generate              # Regenerate zz_generated.deepcopy.go
make helm-update-crds      # Copy generated CRDs into the Helm chart
make compare-templates     # Verify Kustomize and Helm template parity
make verify-templates      # Full template verification (= manifests + helm-update-crds + compare)
make build                 # Build operator binary
make pre-push-run          # Pre-commit hooks against all files

# E2E local stack (docker-compose-driven k3s + Vault + Dex + operator)
make e2e-local-up          # Bring up the full stack
make e2e-local-test        # Run all e2e tests
make e2e-local-test-auth   # Run auth tests only
make e2e-local-test-modules # Run module tests only
make e2e-local-down        # Tear down
make e2e-local-status      # Show stack status
```

## Project slash commands (defined in `.claude/commands/`)

| Command | What it does |
|---------|-------------|
| `/verify-operator` | Run codegen → lint → unit tests → template-compare (pre-push canary) |
| `/e2e-up` | `make e2e-local-up` |
| `/e2e-down` | `make e2e-local-down` |
| `/e2e-test [focus]` | Run e2e tests against local stack with optional Ginkgo focus or label filter |
| `/changelog-add` | Add an entry to `CHANGELOG.md` under `[Unreleased]` |
| `/new-adr <slug>` | Create a new ADR from the template |
| `/new-flow <NAME>` | Create a new `docs/internal/FLOW_<NAME>.md` from the canonical skeleton |
| `/docs-drift` | Audit the branch for code↔docs drift before opening a PR |

Full skill cheat-sheet at [`docs/internal/SKILLS.md`](docs/internal/SKILLS.md). End-to-end workflows at [`docs/internal/WORKFLOWS.md`](docs/internal/WORKFLOWS.md).

## Workflow nudges

A `PostToolUse` hook in `.claude/settings.json` echoes a reminder whenever you edit:

- `api/v1alpha1/*_types.go` → run codegen, update `docs/api-reference.md`, add CHANGELOG
- `features/*/controller/*.go` → update the matching FLOW_*.md doc
- `shared/controller/*/` → consider an ADR + CONTEXT.md update
- `cmd/main.go` → update `docs/configuration.md`
- `internal/webhook/` → STRIDE pass + `docs/webhooks.md`

The hook is a soft nudge, never blocking. To opt out per-session, edit `.claude/settings.local.json`. The hook script is at `.claude/hooks/post-edit-workflow-nudge.sh`.

## Conventions

- **Conventional commits** — see `.cz.toml`. Types: feat, fix, docs, style, refactor, perf, test, chore. Scope = feature name (`feat(policy):`, `fix(webhook):`).
- **Managed marker** — Vault path `secret/data/vault-access-operator/managed/{policies,roles}/{vault-name}` in KV v2 metadata. See [CONTEXT.md `Managed marker`](docs/internal/CONTEXT.md#managed-marker).
- **Test IDs** — `TestSync*_*` (unit), `INT-{CAT}{NN}` (integration), `TC-{CAT}{NN}` (e2e).
- **Finalizer** — `vault.platform.io/finalizer`.
- **Annotations** — `vault.platform.io/adopt=true` (override ConflictPolicy), `vault.platform.io/dry-run=true` (skip Vault writes).
- **Adapter pattern** — `PolicyAdapter` and `RoleAdapter` unify namespaced + cluster-scoped variants. See [ADR 0001](docs/adr/0001-adapter-pattern-for-cluster-scoped-types.md).

## Auto-generation guardrail

If you touch `api/v1alpha1/*_types.go`, **always** run:

```bash
make manifests generate helm-update-crds
```

before committing. CI auto-commits these on `main` but **fails PRs** with stale generated files. The PostToolUse hook will remind you.

## Pointers

- Contribution loop and PR process: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Public docs site: [`docs/`](docs/) → renders at `mkdocs build` (deployed to `https://panteparak.github.io/vault-access-operator/`)
- Contributor docs site: [`docs/internal/`](docs/internal/) → renders at `mkdocs build -f mkdocs-internal.yml`
- Architecture decisions: [`docs/adr/`](docs/adr/)
- Domain glossary: [`docs/internal/CONTEXT.md`](docs/internal/CONTEXT.md)
- Skill cheat-sheet: [`docs/internal/SKILLS.md`](docs/internal/SKILLS.md)
- End-to-end workflows: [`docs/internal/WORKFLOWS.md`](docs/internal/WORKFLOWS.md)
- Requirements template: [`docs/internal/REQUIREMENTS-TEMPLATE.md`](docs/internal/REQUIREMENTS-TEMPLATE.md)
- Known improvements backlog: [`docs/internal/IMPROVEMENTS.md`](docs/internal/IMPROVEMENTS.md)
