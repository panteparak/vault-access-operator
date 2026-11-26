# ADR 0011: Per-connection naming identity and always-on ownership checks

- **Status:** Proposed
- **Date:** 2026-11-25
- **Amends:** [ADR 0010](0010-structured-vault-names-and-recorded-name-authority.md) (identity precedence), [ADR 0008](0008-in-band-ownership-markers.md) (checks no longer gated by `--managed-markers`)
- **Related:** issue #18, [`docs/configuration.md`](../configuration.md#connection-identity), [`docs/internal/FLOW_CONNECTION.md`](../internal/FLOW_CONNECTION.md), [`docs/internal/CONTEXT.md`](../internal/CONTEXT.md#connection-identity)

## Context

Several clusters run their own operator against one shared Vault, and they write roles into one shared role mount (ADR 0009). The naming identity (ADR 0010) is `--cluster-name` or the connection's login mount, so a Vault name is tied to the cluster that declares it. A binding that belongs to no single cluster has no stable name when the declaring cluster or its login mount changes. CI access for a project that spans environments is one example.

Letting a name be chosen per connection makes two writers able to target the same name. That is only safe when every write and delete is gated on ownership. Until now those gates were off by default (`--managed-markers`, which no deployment sets). They also had gaps, which PR 1 of #18 closes: delete gates failed open, the cleanup queue replayed deletes by name, an unrecorded object at a rename target was taken over, and readback ignored the ownership record.

## Decision

`VaultConnection.spec.identity.name` sets the identity segment of every Vault name written through the connection. Ownership checks run for every connection.

- **API (additive, v1alpha1).** `spec.identity {name}` is an optional pointer; `name` has `^[a-z0-9-]+$` and maxLength 40. `status.identity {name, source}` has source `spec | cluster-name | auth-mount | none`. Policy and role `status.binding` gain `identity` and `connection`. All the new fields are optional with `omitempty`.
- **Precedence.** `spec.identity.name`, then `--cluster-name`, then the login mount, then `_`. This order applies to binding names (`naming.Identity`) and to the connection's `status.identity`.
- **Validation.** The controller re-checks the CRD pattern (CRDs in the chart's `crds/` are not upgraded by `helm upgrade`). It also refuses `_` and any identity equal to the sanitized name of an auth mount on the server, compared case-insensitively. For the mount check it reads `sys/auth`, only for connections that set an identity, and it fails closed if `sys/auth` cannot be read. A refusal sets Phase=Error with reason `IdentityCollidesWithAuthMount` (`ValidationFailed` for a pattern miss), so nothing syncs through the connection.
- **Records.** The policy header and the role `alias_metadata` gain an `identity` key, written only when spec.identity is set. `connection` lives in CR status only. With no identity, names, records and content hashes are byte-identical to v0.12.0 (golden tests), so an upgrade rewrites nothing.
- **Ownership is unchanged.** `SameOwner` is still managed-by + login mount + k8s-resource. The identity is a naming input, not an owner.
- **Checks always on.** The policy and role conflict checks and the readback record check run whatever `--managed-markers` says. That flag now gates only the discovery and orphan controllers. Adoption (`conflictPolicy: Adopt` or the adopt annotation) is accepted without the flag; the webhook refusal and the `ManagedMarkersDisabled` warning are removed. The static-token `OwnershipIdentityUnavailable` warning moves to always-on with the checks.
- **Co-location warning.** A role whose identity differs from a referenced policy's (read from the policy's recorded Vault name) gets a `PolicyIdentityMismatch` Warning on each write.
- **Identity moves are delete-then-create.** Moving an identity to another login mount changes the owner. Delete the CR on the old cluster first; its ownership-gated delete removes the Vault object. Then apply the CR on the new cluster. The gap is one reconcile. Applying on the new cluster first leaves the CR in Conflict backoff until the old CR is deleted.
- **Out of scope.** KV secrets: their paths do not use the identity. Orphan and discovery scans are not ownership-aware on a shared role mount; that is pre-existing and tracked separately.

## Consequences

### Positive

- A shared binding keeps one Vault name across clusters and login-mount changes.
- Every write and delete is ownership-gated on every install, so a second writer at a name is a `ConflictError`, never a silent takeover or deletion.
- No-identity installs see no Vault-side change on upgrade (byte-identical records and hashes).

### Negative

- **Default behaviour change.** A new CR pointed at an unrecorded existing Vault object used to overwrite it silently. It now gets `ConflictError` and needs `conflictPolicy: Adopt`. Objects written by v0.12.0 carry the record (the header and `alias_metadata` were always written), so they are recognised as ours.
- An identity move has a one-reconcile gap and is manual.
- Connections that set an identity need `read` on `sys/auth`.

### Neutral

- Static-token connections still have no login mount, so their records do not tell two static-token operators apart. They remain unsupported for multi-operator Vaults.

## Alternatives considered

### An opt-in `--connection-identity` operator flag

The first design gated `spec.identity` behind a flag and forced ownership checks on only when the flag was set. The flag existed only because checks were off by default. No deployment uses `--managed-markers`, and v0.12.0 already writes the ownership record into every policy and role, so turning checks on for everyone costs no rewrite. That makes the field safe on its own. The flag would have added a third configuration state to test and document for no remaining benefit. Rejected.

### `spec.identity.previousAuthMounts` handover

A list of earlier login mounts whose records the new connection would treat as its own, re-stamping them on the next write. It would close the one-reconcile gap of an identity move. But it makes ownership depend on a user-edited list: a typo or a stale entry silently grants takeover of another cluster's objects. A deliberate delete-then-create keeps ownership a pure function of the record. Rejected for now; it can be added later as an additive field.

### A KV identity claim

A KV entry `identity → owning mount` would let the operator refuse a second login mount claiming the same identity before any write. It needs a new Vault grant and a new KV path (which ADR 0008 moved away from), and it duplicates what the in-band records already prove per object. Rejected.

## References

- Source: [`features/connection/controller/identity.go`](../../features/connection/controller/identity.go), [`shared/naming/naming.go`](../../shared/naming/naming.go) (`Identity`, `IdentityOf`), [`pkg/vault/managed.go`](../../pkg/vault/managed.go) (`OwnershipIdentityKey`), [`features/role/controller/handler.go`](../../features/role/controller/handler.go) (`warnIdentityMismatch`)
- Tests: `TestResolveIdentity`, `TestIdentity`, `FuzzVaultName_Unique`, `TestGolden_V012_*`, `TestWarnIdentityMismatch`, `INT-MM10`, e2e `TC-ID01`–`TC-ID07`
- Related ADRs: [0005](0005-cleanup-failure-configmap-queue.md), [0008](0008-in-band-ownership-markers.md), [0009](0009-connection-owned-role-mount.md), [0010](0010-structured-vault-names-and-recorded-name-authority.md)
