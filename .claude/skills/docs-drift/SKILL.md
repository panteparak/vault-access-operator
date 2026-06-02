---
name: docs-drift
description: Audit the current branch for documentation drift — code changes without matching doc updates. Use before opening a PR to catch stale docs, missing CHANGELOG entries, untracked CRD changes, and undocumented architecture decisions in this Vault Access Operator codebase.
---

# docs-drift

Repo-scoped skill for detecting documentation drift in `vault-access-operator`. Reports a checklist of likely-stale docs; does **not** auto-edit.

## When to use

- Before opening a PR (the canonical use case)
- After completing a feature branch but before `/changelog-add`
- When you suspect a `git rebase` may have lost doc updates
- During code review of someone else's branch

## When **not** to use

- Tiny patches (typo fixes, single-line refactors) — too noisy
- Branches with only test changes — usually no docs needed
- Initial scaffolding work where docs are intentionally deferred

## What it checks

The skill compares the current branch against its merge base with `main` and applies repo-specific rules:

| Code change | Expected doc updates |
|-------------|----------------------|
| `api/v1alpha1/*_types.go` modified | `docs/api-reference.md`, `CHANGELOG.md`, generated CRDs under `config/crd/bases/` and `charts/vault-access-operator/crds/`, possibly `docs/configuration.md` |
| `features/<X>/controller/*.go` modified | `docs/internal/FLOW_<X>.md`, possibly `docs/internal/CONTEXT.md` if vocabulary changed |
| `features/connection/auth/*` modified or added | `docs/auth-methods/<method>.md`, `docs/internal/FLOW_AUTH.md`, possibly a new ADR |
| `shared/controller/<pkg>/` added or removed | A new `docs/adr/NNNN-*.md` explaining why, `docs/internal/CONTEXT.md` if it introduces vocabulary |
| `cmd/main.go` new flag | `docs/configuration.md` flag table |
| `internal/webhook/*.go` modified | `docs/webhooks.md`, possibly `docs/internal/FLOW_WEBHOOK.md`, threat-model entry |
| `.github/workflows/*.yaml` modified | Possibly `CHANGELOG.md` if user-visible |
| `Makefile` target added | `CONTRIBUTING.md` (Running Tests section), possibly `CLAUDE.md` Make-targets cheatsheet |
| `charts/vault-access-operator/` modified | `docs/getting-started.md` (install steps), possibly `docs/configuration.md` |
| New file under `api/v1alpha1/*_types.go` (new CRD) | Same as modify + new section in `docs/api-reference.md`, sample under `config/samples/`, getting-started snippet |

Additionally, the skill checks:

- **`CHANGELOG.md` touched** when non-trivial functional changes are present (heuristic: any Go file outside `_test.go` modified). If CHANGELOG is not in the diff, flag it.
- **ADR existence** when a new package under `shared/controller/` appears.
- **CONTEXT.md mentions** when new domain terms appear in new public type/method names (best-effort grep).

## How to run

1. Determine the merge base:
   ```bash
   git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main
   ```
2. List changed paths:
   ```bash
   git diff <base>..HEAD --name-only
   ```
3. For each rule, check whether the expected doc path is also in the diff. If not, surface it as a finding.

## Output format

Print a Markdown checklist grouped by severity:

```
## Documentation drift audit

### 🔴 Likely missing (high confidence)
- [ ] `docs/api-reference.md` — `api/v1alpha1/vaultpolicy_types.go` changed (3 fields added) but api-reference.md untouched
- [ ] `CHANGELOG.md` — functional code change without changelog entry

### 🟡 Worth checking (lower confidence)
- [ ] `docs/internal/FLOW_POLICY.md` — `features/policy/controller/handler.go` changed; verify the sync sequence still matches
- [ ] `docs/internal/CONTEXT.md` — new type `PolicyBindingMode` introduced; consider adding a glossary entry

### ✅ No drift detected for:
- Helm chart, mkdocs configs, CI workflows
```

## Caveats

- This is a heuristic detector. False positives are expected (e.g., a comment-only edit to `*_types.go` doesn't actually need doc updates). Treat the output as a checklist, not a blocker.
- The skill does **not** edit docs. To apply updates, use `grill-with-docs` (interactive) or edit manually.
- Run from the repo root; the rules assume the standard layout of this operator.

## Related

- `/changelog-add` — wraps adding to CHANGELOG.md
- `/new-adr <slug>` — creates an ADR for newly introduced architectural decisions
- `/new-flow <name>` — creates a new FLOW_*.md when a new feature is added
- `grill-with-docs` — updates CONTEXT.md and ADRs inline while planning a change
