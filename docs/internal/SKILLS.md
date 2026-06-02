# Claude Code Skills Cheat-Sheet

This document maps Claude Code skills to dev-loop phases and additional clusters (documentation, requirements, business-flow). Each row lists the skill, when to use it for this operator, and operator-specific guidance.

**How to invoke a skill:** type `/skill-name` in Claude Code. Skills marked **(custom)** are defined under [`.claude/skills/`](../../.claude/skills/) and are repo-specific.

For end-to-end scenarios that compose these skills, see [WORKFLOWS.md](WORKFLOWS.md).

---

## Dev-loop phases

### Design

| Skill | When to use | Operator-specific notes |
|-------|-------------|------------------------|
| `dev-flow` | Any non-trivial feature | Runs explore → plan → implement → review → document. Default starting point for feature work. |
| `grill-with-docs` | Stress-testing a plan against CONTEXT/ADRs | Now actionable because both exist. Updates [CONTEXT.md](CONTEXT.md) and [`docs/adr/`](../adr/) inline as decisions crystallize. |
| `grill-me` | Stress-testing conversationally with no doc updates | Use before formalizing a PRD or ADR. |
| `security-threat-model` | New auth method, webhook change, token-handling change | STRIDE pass. Always pair with a `/security-audit` after implementation. |
| `to-prd` | Capturing a feature spec from a free-form discussion | Output lands at `docs/internal/prd/<slug>.md`. Pair with [REQUIREMENTS-TEMPLATE.md](REQUIREMENTS-TEMPLATE.md). |
| `improve-codebase-architecture` | Finding refactor / deepening opportunities | Reads CONTEXT.md + docs/adr/. Output is a list of candidates, not commits. |

### Implement

| Skill | When to use | Operator-specific notes |
|-------|-------------|------------------------|
| `dev-k8s-operator` | New controller / reconciliation logic | Knows controller-runtime patterns: predicates, indexers, watches. Compose with the project's `BaseReconciler` ([ADR 0002](../adr/0002-template-method-base-reconciler.md)). |
| `dev-go` | Pure Go (non-controller) code | Use for `shared/`, `pkg/`, `internal/` utilities. |
| `tdd` | Behavior changes | Write the integration test first under `test/integration/<category>/`; let the failing test drive the implementation. |
| `solid` | Refactoring `shared/` | The codebase already follows SOLID; the skill reinforces it. Often pairs with `improve-codebase-architecture` + a new ADR. |
| `refactor-code` | Pattern refactors across files | Use after `improve-codebase-architecture` identifies candidates. |

### Test

| Skill | When to use | Operator-specific notes |
|-------|-------------|------------------------|
| `test-unit` | New exported function | Vault mocks use `httptest.Server` against the concrete `*vault.Client` — see auto-memory and `pkg/vault/*_test.go`. |
| `test-integration` | Controller behavior with real Vault | Ginkgo + Testcontainers. `make test-integration`. Categories under `test/integration/<cat>/`. |
| `test-e2e` | User-facing feature | `make e2e-local-up && make e2e-local-test`. Test IDs follow `TC-{CAT}{NN}`. |
| `test-generate` | Backfilling coverage on existing code | Targets exported APIs. |
| `test-performance` | Load/throughput validation | Project already has profiling tests under `test/integration/profiling/`; this skill complements with k6/Locust if needed. |

### Review

| Skill | When to use | Operator-specific notes |
|-------|-------------|------------------------|
| `review-code` | Pre-PR self-review | Reads `git diff` and reports correctness/security issues. Run before pushing. |
| `pr-review-toolkit:review-pr` | Reviewing someone else's PR | Multi-agent: code-reviewer + test-analyzer + silent-failure-hunter + type-design-analyzer + comment-analyzer. |
| `security-audit` | PRs touching webhooks / auth / tokens | OWASP + secrets scan. |

### Ship

| Skill | When to use | Operator-specific notes |
|-------|-------------|------------------------|
| `dev-helm` | Chart changes | `charts/vault-access-operator/`. Run `make compare-templates` after to verify Kustomize parity. |
| `dev-dockerfile` | Dockerfile updates | Multi-arch build is already wired in CI; preserve the entry-point and non-root user. |
| `dev-ci-github` | Workflow updates | Follow the 4-stage gate pattern (lint+unit+integration+verify+docker → gate → security/profiled → E2E). |
| `verify` | Manual local verification | Drives the operator in the local k3s stack to confirm behavior end-to-end. Pairs with `/e2e-up` + `/e2e-test`. |

### Debug

| Skill | When to use | Operator-specific notes |
|-------|-------------|------------------------|
| `debug-k8s` | Pod / CRD / RBAC issues | First stop for "operator won't start." Knows kubectl debugging patterns. |
| `debug-backend` | Logic bugs | Generic structured root-cause loop. Pair with `diagnose` for hard ones. |
| `diagnose` | Hard bugs / regressions | Reproduce → minimise → hypothesise → instrument → fix → regression-test. |

---

## Documentation lifecycle

| Activity | Skill | Operator-specific notes |
|----------|-------|------------------------|
| Initialize repo-level docs | `init` | One-time. Used to create [CLAUDE.md](../../CLAUDE.md). |
| Detect docs drift | `/docs-drift` **(custom)** | See [`.claude/skills/docs-drift/SKILL.md`](../../.claude/skills/docs-drift/SKILL.md). Run before opening a PR. Output is a checklist; does **not** auto-edit. |
| Update CONTEXT/ADRs while planning | `grill-with-docs` | Updates the glossary and decisions inline as the plan crystallises. |
| Find architectural deepening | `improve-codebase-architecture` | Reads CONTEXT.md + docs/adr/; outputs a candidates list. |
| Memory hygiene | `anthropic-skills:consolidate-memory` | Reflective pass over your `~/.claude/.../memory/` auto-memory. Run periodically. |
| Author a new repo-specific skill | `write-a-skill` | Use this to add another `.claude/skills/*` for recurring repo-specific tasks. |

**Documentation drift — what gets checked:**

The `/docs-drift` skill applies these rules to the current branch diff (see [the skill's SKILL.md](../../.claude/skills/docs-drift/SKILL.md) for the canonical list):

- `api/v1alpha1/*_types.go` → `docs/api-reference.md`, `CHANGELOG.md`, generated CRDs
- `features/<X>/controller/*.go` → `docs/internal/FLOW_<X>.md`, possibly CONTEXT.md
- `features/connection/auth/*` → `docs/auth-methods/<method>.md`
- `shared/controller/<pkg>/` added/removed → new ADR + CONTEXT.md
- `cmd/main.go` new flag → `docs/configuration.md`
- `internal/webhook/*.go` → `docs/webhooks.md`, threat-model entry

In parallel, the `.claude/settings.json` PostToolUse hook nudges contributors **at edit time** with the same rule set, so most drift is caught before it ever lands in a PR.

---

## Requirements gathering

| Activity | Skill | Operator-specific notes |
|----------|-------|------------------------|
| Capture a feature spec | `to-prd` | Output lands under `docs/internal/prd/`. Use [REQUIREMENTS-TEMPLATE.md](REQUIREMENTS-TEMPLATE.md) as the structural guide. |
| Break a plan into tickets | `to-issues` | Vertical-slice issues; uses tracer-bullet pattern. |
| Triage incoming bugs/requests | `triage` | State machine for grooming the inbox. |
| Stress-test a plan conversationally | `grill-me` | No doc output. |
| Stress-test against docs | `grill-with-docs` | Updates CONTEXT/ADRs inline. |
| Threat-model a feature | `security-threat-model` | Required for auth/webhook/token changes. |

---

## Business-flow modeling

The 10 [`FLOW_*.md`](.) files are the project's existing business-flow convention. Each documents a single domain area with: purpose → trigger → sequence diagram (Mermaid) → step pseudocode → error paths → code references → related links.

| Activity | Approach | Operator-specific notes |
|----------|----------|------------------------|
| Document a new runtime flow | `/new-flow <NAME>` | Creates `docs/internal/FLOW_<NAME>.md` from the skeleton (see [WORKFLOWS.md](WORKFLOWS.md)). |
| Map a domain (vocabulary + relationships) | Update [CONTEXT.md](CONTEXT.md) + ADR | Domain terms → CONTEXT.md. Structural choices → docs/adr/. |
| Capture a recurring workflow | `write-a-skill` | E.g., a future `/add-auth-method` skill that runs WORKFLOWS Scenario A end-to-end. |

---

## Project slash commands

These wrap standardized operations. Source: [`.claude/commands/`](../../.claude/commands/).

| Command | Wraps |
|---------|-------|
| `/verify-operator` | `make manifests generate helm-update-crds && make lint && make test && make compare-templates` |
| `/e2e-up` | `make e2e-local-up` |
| `/e2e-down` | `make e2e-local-down` |
| `/e2e-test [focus]` | `make e2e-local-test` with optional Ginkgo focus or label filter |
| `/changelog-add` | Interactive add of an entry under `## [Unreleased]` |
| `/new-adr <slug>` | Copy `docs/adr/0000-template.md` to the next-numbered ADR |
| `/new-flow <NAME>` | Create `docs/internal/FLOW_<NAME>.md` from the canonical skeleton |
| `/docs-drift` | Run the docs-drift skill audit |

---

## When **not** to use a skill

Skills add overhead. Skip them when:

- The task is a one-line typo fix — just edit.
- You're navigating known code — Read/grep is faster than `dev-k8s-operator`.
- You're in the middle of a debugging session and the skill would interrupt your flow — finish the loop first.
- The skill catalog doesn't include something you need — consider authoring a custom one via `write-a-skill` rather than forcing an ill-fitting skill.
