# Requirements Template

Use this template to capture a feature requirement *before* implementation begins. Used as the input to `/new-adr` and `to-prd`.

Copy this file to `docs/internal/prd/<short-name>.md` and fill in the sections. Keep it under 200 lines — verbose rationale belongs in the resulting ADR or FLOW doc.

---

# <Feature title in sentence case>

- **Author:** <github handle>
- **Date:** <YYYY-MM-DD>
- **Status:** Draft | In Review | Approved | Implemented | Withdrawn
- **Tracking:** <link to GitHub issue or epic>

## Problem statement

One paragraph describing the user-visible pain or operator gap. Avoid "we should add feature X" framing; instead, describe the *outcome* a user can't achieve today and *why* that hurts.

Bad: "We should add Prometheus federation."
Good: "Teams running > 50 VaultPolicies report the operator's `/metrics` endpoint takes > 5 seconds to respond, which trips their Grafana scrape timeouts and breaks their dashboards."

## Goals

What does success look like? Bullet list, each item testable.

- [ ] G1: <observable behavior>
- [ ] G2: <observable behavior>

## Non-goals

What this requirement explicitly does **not** cover. Use this to fend off scope creep.

- N1: <thing we're choosing not to do, and why>
- N2: <thing we're choosing not to do, and why>

## Acceptance criteria

Concrete, testable bullets. Each should map to at least one test (unit, integration, or e2e).

- [ ] AC1: When <condition>, then <observable outcome>
- [ ] AC2: <…>
- [ ] AC3: All existing tests still pass; `make verify-templates` reports no drift

## Affected CRDs / API surface

List every CRD field added, removed, or changed. Use the form: `Kind.spec.field`.

- `VaultRole.spec.jwt.subjectClaim` — new optional string
- `VaultConnection.status.lastDiscovery` — new condition

If new CRDs are introduced, note that **explicitly** — a new CRD triggers a migration concern and a backward-compat plan.

## Affected docs

Pre-list the docs that must be updated. The `/docs-drift` skill will check these on PR.

- `docs/api-reference.md` — new field documentation
- `docs/internal/FLOW_<NAME>.md` — sequence diagram update or new flow
- `docs/internal/CONTEXT.md` — new domain term
- `docs/auth-methods/<method>.md` — if a new or modified auth method
- `CHANGELOG.md` — `### Added` or `### Changed` entry under `[Unreleased]`

## Compatibility & migration

- **Backward compatibility:** Existing CRs continue to reconcile correctly? If a default is added, what's the value for pre-existing resources?
- **Version skew:** Any concern with older operators running against newer CRDs (or vice versa) in mid-rollout?
- **Webhook validation:** Does this require webhook changes? If yes, gate behind `--enable-webhooks` and remember tests run both with and without webhooks.

## Security considerations

Trigger a STRIDE pass via `/security-threat-model` if any of these apply:

- [ ] Changes auth path (login, token issuance, token rotation)
- [ ] Changes webhook input/output handling
- [ ] Changes RBAC or service-account boundaries
- [ ] Introduces new user-controlled string that ends up in HCL, file paths, or shell

For each applicable item: link to the threat-model output here.

## Open questions

Things you don't know yet and need to resolve before implementation. Convert to GitHub issues if they merit independent tracking.

- Q1: <question> — owner: <name>
- Q2: <question>

## Implementation sketch

High-level outline — *not* a step-by-step plan (that comes in the ADR or PR description). Aim for 5–10 bullets.

1. Add CRD field <…>
2. Extend webhook to validate <…>
3. Update `<Feature>Ops` to handle <…>
4. Update FLOW doc
5. Tests: unit (`features/<feat>/controller/<feat>_test.go`), integration (`test/integration/<cat>/`), e2e if user-visible
6. CHANGELOG entry

## References

- Related ADRs: <links>
- Related FLOW docs: <links>
- External: Vault docs, controller-runtime docs, RFC links
- Prior art: similar features in this operator or others

---

After filling this out, run `/new-adr <slug>` if the requirement implies a non-obvious design choice. Otherwise, proceed directly to implementation using the `/dev-flow` skill chain (explore → plan → implement → review → document).
