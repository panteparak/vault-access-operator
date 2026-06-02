# ADR 0003: Two-level drift and conflict-policy configuration

- **Status:** Accepted
- **Date:** 2026-05-27
- **Related:** [`FLOW_POLICY.md`](../internal/FLOW_POLICY.md), [`FLOW_ROLE.md`](../internal/FLOW_ROLE.md), [`CONTEXT.md`](../internal/CONTEXT.md#drift-mode)

## Context

The operator has two policies that platform teams may want to set globally and individual app teams may want to override on specific resources:

- **DriftMode** — `Ignore` / `Detect` / `Correct`. Controls what the operator does when the Vault resource has diverged from the CR's spec (typically: someone edited Vault directly).
- **ConflictPolicy** — `Fail` / `Adopt`. Controls behavior when a Vault resource with the operator's managed-marker prefix already exists at apply time but isn't owned by the current CR.

A single global default is too coarse (platform teams want "Correct" for shared infra, app teams want "Ignore" for their experiment-y namespaces). A purely per-resource setting is too verbose (most resources should follow the connection-level convention).

## Decision

Implement a **two-level config hierarchy** for both DriftMode and ConflictPolicy:

1. **Connection-level default** — Set on `VaultConnection.spec` (`driftMode`, `defaultConflictPolicy`).
2. **Resource-level override** — Set on `VaultPolicy.spec` / `VaultRole.spec` (`driftMode`, `conflictPolicy`). When unset (empty string), inherits from the connection.

Resolution helpers live in dedicated packages:

- [`shared/controller/driftmode/resolve.go`](../../shared/controller/driftmode/resolve.go) — `Resolve(resource, connection, globalDefault) DriftMode`
- [`shared/controller/conflict/resolve.go`](../../shared/controller/conflict/resolve.go) — `Resolve(resource, connection) ConflictPolicy`

The resolution order is always: resource → connection → built-in default (`Detect` for drift, `Fail` for conflict).

Additionally, ConflictPolicy is overridable via the annotation `vault.platform.io/adopt=true` on the resource. The annotation takes precedence over the enum, giving operators a no-redeploy break-glass.

## Consequences

### Positive

- **Platform teams set policy once on the connection**; app teams opt out on specific resources only when needed.
- **Resolution is a pure function** — easy to unit test, easy to log ("resolved DriftMode=Correct via connection-level default").
- **Annotation override gives an audit trail** — `kubectl annotate` is logged in the K8s audit log, unlike spec changes that may be applied via GitOps.

### Negative

- Slightly more documentation surface — users must learn the hierarchy.
- Status conditions must clearly indicate the *effective* mode, not just the spec'd one, to avoid confusion when overrides are in play.

### Neutral

- The annotation precedence is intentional but non-obvious; flag it prominently in `docs/api-reference.md` and `docs/configuration.md`.

## Alternatives considered

### Alternative A: Single global default

A single env var or operator flag. Rejected — too coarse for multi-tenant clusters.

### Alternative B: Per-resource only

Force every resource to set DriftMode/ConflictPolicy explicitly. Rejected — too verbose and invites copy-paste drift.

### Alternative C: Three-level (resource → namespace → connection)

Add a third tier via a per-namespace ConfigMap. Rejected — namespace-scoped policy is uncommon in practice and adds a new lookup path; can be added later if demand emerges.

## References

- Resolution code: [`shared/controller/driftmode/`](../../shared/controller/driftmode/), [`shared/controller/conflict/`](../../shared/controller/conflict/)
- API surface: [`api/v1alpha1/common_types.go`](../../api/v1alpha1/common_types.go) (`DriftMode`, `ConflictPolicy` enums)
- Annotation handler: [`shared/controller/conflict/adoption.go`](../../shared/controller/conflict/)
