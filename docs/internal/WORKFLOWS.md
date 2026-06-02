# End-to-End Workflows

Three canonical scenarios that compose the skills in [SKILLS.md](SKILLS.md) with the project's slash commands and Makefile targets. Each scenario ends with explicit "Done when" criteria.

---

## Scenario A — Add a new Vault auth method

**Frequency:** 1–2 per quarter as new Vault auth integrations land.
**Difficulty:** High. Touches CRD schema, webhook, Vault client, FLOW docs, public docs, e2e tests.

### Steps

1. **Capture requirements** — copy [REQUIREMENTS-TEMPLATE.md](REQUIREMENTS-TEMPLATE.md) to `docs/internal/prd/auth-<method>.md`. Fill in goals, acceptance criteria, affected docs.
2. **Threat-model** — `/security-threat-model`. Auth is in scope by definition.
3. **Record the design decision** — `/new-adr auth-<method>-support`. Capture: why this auth method, why now, alternatives (e.g., "could be done client-side with a sidecar"), trade-offs.
4. **Update CONTEXT.md** — add the new auth method to the Vault domain section. `grill-with-docs` can do this inline.
5. **Implement** — `/dev-k8s-operator` to scaffold; `/tdd` for the per-method auth handler under `pkg/vault/auth/`. The CRD schema goes in `api/v1alpha1/vaultconnection_types.go` under the `auth` discriminated union.
6. **Webhook validation** — extend `internal/webhook/vaultconnection_webhook.go` to validate the new auth fields. Tests under `internal/webhook/*_test.go`.
7. **Generate** — `make manifests generate helm-update-crds`. Commit the generated diff.
8. **Unit tests** — colocated `*_test.go` for the auth handler. Vault mock via `httptest.Server`.
9. **Integration tests** — under `test/integration/connection/` (or a new category if it fits). Real Vault via Testcontainers.
10. **E2E tests** — under `test/e2e/tc_auth_<method>_test.go`. Run against `make e2e-local-up`.
11. **Public docs** — add `docs/auth-methods/<method>.md` following the pattern of existing 8 method docs.
12. **FLOW doc** — if the auth flow has new participants or sequence, run `/new-flow AUTH_<METHOD>` and fill it in. Otherwise update FLOW_AUTH.md.
13. **CHANGELOG** — `/changelog-add` under `### Added`. Include all the public-facing field additions.
14. **Self-audit** — `/docs-drift`. Should come back clean if the above was followed.
15. **Verify** — `/verify-operator`. All static checks pass.
16. **Review** — open PR. Reviewer uses `pr-review-toolkit:review-pr` for multi-aspect review.

### Done when

- [ ] `/verify-operator` is green
- [ ] Integration test for the new auth method passes
- [ ] E2E test in `test/e2e/tc_auth_<method>_test.go` passes against local stack
- [ ] `docs/auth-methods/<method>.md` exists and matches the style of existing 8 docs
- [ ] CHANGELOG entry under `[Unreleased] → Added`
- [ ] ADR is `Status: Accepted` with the index updated
- [ ] CONTEXT.md mentions the new auth method
- [ ] `/docs-drift` reports no outstanding gaps

---

## Scenario B — Fix a reconcile bug

**Frequency:** Several per month. The common case.
**Difficulty:** Medium. Requires understanding the relevant FLOW doc.

### Steps

1. **Identify the symptom** — `kubectl describe`, operator logs, condition values. Note: which CR? what phase? what error condition?
2. **Read the relevant FLOW doc first** — for a `VaultPolicy` issue, `docs/internal/FLOW_POLICY.md` is your map of the runtime. Likewise FLOW_ROLE, FLOW_CONNECTION, FLOW_DISCOVERY, FLOW_DELETION.
3. **Reproduce** — `/diagnose` to set up the reproduction. Aim for a single failing integration test under `test/integration/<cat>/` (or a new one). This is the regression test for later.
4. **Root cause** — `/debug-backend` (or just step through manually). Use the FLOW doc step numbers to locate where state diverges.
5. **Fix** — minimal change. Don't refactor surrounding code; that's a separate workflow.
6. **Run the failing test** — `make test-integration` with focus on the new test; confirm it now passes.
7. **Full unit suite** — `make test` to catch regressions.
8. **Docs drift?** — `/docs-drift`. If the FLOW doc had a wrong step (the bug was a docs-drift in addition to a code drift), update it. Usually a fix doesn't need doc changes — the docs were right, the code was wrong.
9. **CHANGELOG** — `/changelog-add` under `### Fixed`. Reference the issue if there is one.

### Done when

- [ ] The failing integration test exists and now passes
- [ ] `make test` is green
- [ ] No drift surfaced by `/docs-drift`
- [ ] CHANGELOG entry under `[Unreleased] → Fixed`

---

## Scenario C — Refactor a `shared/controller/*` package

**Frequency:** Occasional, often opportunistic.
**Difficulty:** High. These are the cross-cutting layers; mistakes ripple.

### Steps

1. **Discover the opportunity** — `/improve-codebase-architecture`. Output: a candidates list with priority. Pick one.
2. **Decide if an ADR is needed** — if the refactor changes the *interface* of a shared package (not just the implementation), `/new-adr`. Cite the existing ADRs the refactor builds on or supersedes.
3. **Plan** — `/dev-flow`. Plan agent identifies all consumers of the package.
4. **Refactor** — `/solid` + `/refactor-code`. Make the structural changes; do not change behavior.
5. **Tests** — unit tests for the package itself must pass unchanged (if they don't, you changed behavior; either revert or update tests with justification).
6. **Integration tests** — `make test-integration`. These exercise the reconcile path and catch subtle behavioral regressions.
7. **Template parity** — `make compare-templates` after any change that affects RBAC, manifests, or chart values.
8. **Verify** — `/verify-operator`.
9. **Update CONTEXT.md** — if vocabulary changed (new types/concepts exposed).
10. **Update FLOW docs** — if the package's public API surface changed, all consuming FLOW docs likely need a tweak. `/docs-drift` will flag them.
11. **CHANGELOG** — `/changelog-add` under `### Changed`. Include a migration note if downstream callers need updates.
12. **Review** — open PR. Reviewer uses `pr-review-toolkit:review-pr`.

### Done when

- [ ] All existing tests pass without modification (or modifications are documented as intentional)
- [ ] `/verify-operator` is green
- [ ] Integration tests for at least 2 features that consume this package pass
- [ ] CHANGELOG entry under `[Unreleased] → Changed`
- [ ] If interface changed: ADR is `Status: Accepted`, CONTEXT.md updated, consumer FLOW docs updated
- [ ] `/docs-drift` reports no outstanding gaps

---

## How to add a new FLOW doc

Use `/new-flow <NAME>` to create one from the canonical skeleton. The skeleton (reproduced here for reference):

```markdown
# Flow: <Feature Title> (<NAME>)

## Purpose
One paragraph: what this flow accomplishes and why.

## Trigger
What event/condition starts this flow.

## Sequence
[Mermaid sequenceDiagram]

## Step-by-step
1. **Fetch resource** — code reference
2. **Validate** — code reference
... up to ~10 numbered steps

## Error paths
- **<error condition>** — what the operator does

## Code references
- Reconciler: `features/<feature>/controller/<feature>_reconciler.go`
- Handler: `features/<feature>/controller/handler.go`
... canonical code paths

## Related
- [CONTEXT.md](CONTEXT.md) — vocabulary
- Sibling FLOW docs
- Relevant ADRs
```

Update [`mkdocs-internal.yml`](../../mkdocs-internal.yml) nav so the new FLOW doc is discoverable in the rendered internal docs site.

---

## CHANGELOG conventions

This repo uses [Keep a Changelog v1.1.0](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Sections within a version, in canonical order:
- `### Added` — new features
- `### Changed` — changes to existing functionality
- `### Deprecated` — features that will be removed
- `### Removed` — features that have been removed
- `### Fixed` — bug fixes
- `### Security` — security-relevant changes

Each entry: a single imperative-mood sentence on the headline line, followed by 2–4 bullet sub-items explaining what/why and any caveats.

Use `/changelog-add` to add an entry; it walks you through the categorization.

---

## Common pitfalls

- **Skipping `make manifests generate helm-update-crds`** — CI auto-commits on `main` but blocks PRs. Run locally and commit the generated diff alongside your spec changes.
- **Forgetting `make compare-templates`** — Kustomize and Helm chart output must match. The diff is usually trivial, but skipping the check lets divergence accumulate.
- **E2E test cache** — `go test` caches results. Use `-count=1` (already in the Makefile's e2e target) when you want fresh runs.
- **Webhook re-enabling** — if you toggle `--enable-webhooks=true`, you also need cert-manager. Use `make e2e-local-up-with-webhooks`.
- **PublishAsync in tests** — see CONTEXT.md "Event bus". Use buffered channels for synchronization or your tests flake.
