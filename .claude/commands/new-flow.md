---
description: Create a new FLOW_<name>.md doc in docs/internal/ from the standard skeleton
argument-hint: <FEATURE_NAME_UPPER>
---

Create a new business-flow document under `docs/internal/FLOW_<NAME>.md`.

1. Require `$ARGUMENTS` to be a non-empty identifier. Transform to UPPER_SNAKE_CASE (e.g., user passes `audit` → `AUDIT`; passes `cleanup-queue` → `CLEANUP_QUEUE`). If empty, ask the user.

2. Verify `docs/internal/FLOW_<NAME>.md` doesn't already exist. If it does, stop and report.

3. Look at `docs/internal/FLOW_POLICY.md` and `docs/internal/FLOW_CONNECTION.md` to confirm the canonical structure (purpose → sequence diagram → step pseudocode → error paths → code references → related).

4. Create `docs/internal/FLOW_<NAME>.md` with the following skeleton, filling in `<NAME>` and `<feature>`:

```markdown
# Flow: <Feature Title> (<NAME>)

## Purpose

One paragraph: what this flow accomplishes and why it exists in the operator's domain.

## Trigger

What event/condition starts this flow (a watch, a periodic reconcile, an event-bus signal, etc.)?

## Sequence

\`\`\`mermaid
sequenceDiagram
    autonumber
    participant K as Kubernetes API
    participant R as Reconciler
    participant V as Vault
    K->>R: <event>
    R->>V: <action>
    V-->>R: <response>
    R->>K: <status update>
\`\`\`

## Step-by-step

1. **Fetch resource** — `Reconciler.Reconcile()` reads the CR from K8s.
2. **Validate** — webhook (if enabled) or in-reconciler checks.
3. **Resolve connection** — via `shared/controller/vaultclient.Resolve()`.
4. **Compute desired state** — hash spec, compare with last-synced.
5. **Apply to Vault** — `<feature>Ops.Sync()` or similar.
6. **Update status** — phase, conditions, observed generation.

## Error paths

- **Connection unhealthy** — requeue with backoff; surface `ConditionVaultUnreachable`.
- **Vault returns 403** — surface `ConditionUnauthorized`; do not retry.
- **Drift detected (DriftMode=correct)** — re-apply spec; emit `Drift` event.

## Code references

- Reconciler: `features/<feature>/controller/<feature>_reconciler.go`
- Handler: `features/<feature>/controller/handler.go`
- Ops: `features/<feature>/controller/ops.go`
- Adapter (if relevant): `features/<feature>/domain/adapter.go`

## Related

- [CONTEXT.md](CONTEXT.md) — vocabulary used here
- [FLOW_CONNECTION.md](FLOW_CONNECTION.md) — upstream dependency
- ADRs:
  - [`<NNNN>-<slug>.md`](../adr/<NNNN>-<slug>.md) — relevant decisions
```

5. After writing, remind the user to:
   - Update `mkdocs-internal.yml` nav to include the new flow
   - Add cross-references from related FLOW docs and CONTEXT.md
