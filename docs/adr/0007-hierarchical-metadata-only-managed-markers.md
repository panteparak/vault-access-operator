# ADR 0007: Hierarchical, metadata-only managed markers with opt-in flag

- **Status:** Accepted
- **Date:** 2026-07-02
- **Related:** [`docs/configuration.md`](../configuration.md#managed-markers), [`CONTEXT.md`](../internal/CONTEXT.md#managed-marker), [`FLOW_POLICY.md`](../internal/FLOW_POLICY.md), [`FLOW_ROLE.md`](../internal/FLOW_ROLE.md), [`FLOW_DISCOVERY.md`](../internal/FLOW_DISCOVERY.md), [`FLOW_DELETION.md`](../internal/FLOW_DELETION.md), [ADR 0006](0006-cluster-name-prefix.md)

## Context

The operator tracks the Vault policies and roles it owns with a **managed marker** — a record it writes to Vault, keyed to the K8s CR that owns each Vault object. Markers back conflict/ownership detection, discovery (adopting pre-existing Vault resources), and orphan detection. The original design had three problems:

- **No tenant or auth isolation.** Markers lived at a single flat path, `secret/data/vault-access-operator/managed/{policies,roles}/{cluster}-{ns}-{name}`. Every cluster's markers shared one leaf namespace differentiated only by a name prefix ([ADR 0006](0006-cluster-name-prefix.md)). A Vault token could not be ACL-scoped to *just* one cluster's or one kind's markers, because there were no path segments to scope on.
- **Needless `data` capability.** Markers were stored in KV v2 **data**, so the operator's policy needed CRUD on `secret/data/vault-access-operator/managed/*`. But a marker is pure ownership metadata — it never needs to be a secret. Granting data write on the `secret` mount is a broader capability than the job requires.
- **Opt-in not honored under the default `Fail` policy.** Marker tracking was always on and unconditionally required the grant. There was no way to run the operator in a simpler "write-and-forget" mode, and a CR that asked for `conflictPolicy: Adopt` while markers were somehow unavailable would fail opaquely rather than telling the user why.

## Decision

Move markers to a **hierarchical, metadata-only path**, and make the whole mechanism **opt-in** behind a flag.

- **Storage:** KV v2 `custom_metadata` **only — never `secret/data`**. Keys: `managed-by`, `k8s-resource`, `managed-at`, `last-updated`.
- **Path:** one segment per scoping axis (cluster / kind / mount / namespace / name):
  - roles: `secret/metadata/vault-access-operator/managed/{cluster}/roles/{mount}/{ns}/{name}`
  - policies: `secret/metadata/vault-access-operator/managed/{cluster}/policies/{ns}/{name}`
  - `{cluster}` is the `--cluster-name` value, **omitted entirely when unset**; `{mount}` is the bare auth-mount name (roles only); cluster-scoped CRs use the sentinel `_cluster` in the `{ns}` slot.
- **`--managed-markers` flag, default OFF** (`--managed-markers` / `MANAGED_MARKERS` env / `managedMarkers.enabled` Helm value). Off: no marker reads/writes, conflict/ownership detection skipped (write-and-forget), discovery and orphan controllers not run, no grant needed. On: full tracking; requires `create, read, update, list, delete` on `secret/metadata/vault-access-operator/managed/*` (metadata-only, no `data`), scopable per cluster.
- **Enforcement of "used but not activated":** when markers are OFF and a CR sets `conflictPolicy: Adopt` (or annotation `vault.platform.io/adopt=true`), the controller emits a `Warning` event `ManagedMarkersDisabled` (reconcile still proceeds) and the validating webhook (when `--enable-webhooks`) **rejects the create at admission**. Plain/defaulted `conflictPolicy: Fail` is allowed silently. On a `VaultConnection` becoming Active with markers on, a one-time preflight emits `ManagedMarkersPreflightFailed` if the grant is missing.
- **Boundary:** this does not migrate existing markers automatically, and does not change the Vault policies/roles themselves — only the ownership-tracking record.

## Consequences

### Positive

- **Per-segment ACL scoping.** A token can be limited to `.../managed/{cluster}/*` (or a single kind), which the flat path could not express — the enabling win for multi-tenant shared Vault CE.
- **Least privilege.** The operator's marker grant drops the `data` capability entirely; it touches only `custom_metadata`. `secret/data/test` stays denied, and the never-read-secrets guarantee is now structural for markers too.
- **Simpler default.** Off-by-default means a minimal deployment needs no marker grant at all and runs write-and-forget; teams opt into tracking only when they want discovery/adoption/orphan detection.

### Negative

- **Breaking migration ×2.** (a) Default-off: deployments that relied on always-on markers silently lose ownership tracking / discovery / orphan detection until they set `--managed-markers=true`. (b) Path+storage change: enabling markers after upgrade finds the new metadata path empty, so existing managed resources read as unmanaged and conflict under the default `Fail` policy. Remedy: enable with `ConflictPolicy: Adopt` (or the adopt annotation), let resources re-mark, then revert; old inert `secret/data/.../managed/*` markers can be deleted manually. Vault policies/roles are untouched — no data loss, only tracking reset.
- **Recursive LIST cost.** Enumeration (discovery, orphan scan) is now a recursive LIST that walks the hierarchy per segment plus a metadata read per leaf, versus one flat LIST. More round-trips at scan time.

### Neutral

- The `_cluster` sentinel reserves a namespace name; a real K8s namespace literally named `_cluster` is impossible (invalid DNS label), so there is no collision.
- The cluster prefix now lives in a **path segment** rather than the leaf name, superseding the leaf-prefix approach [ADR 0006](0006-cluster-name-prefix.md) chose for markers (0006's prefix on policy/role *names* is unchanged).

## Alternatives considered

- **Flat path + metadata fields.** Keep the single flat path but move the payload into `custom_metadata` and add cluster/kind as metadata *values*. Rejected: it fixes the data-capability problem but not isolation — a token still cannot be scoped to one cluster's markers, because ACLs match on path, not on metadata contents.
- **Auto-degrade on 403.** Keep markers always-on but silently fall back to write-and-forget when the grant is missing (Vault returns 403). Rejected: silent capability-based behavior changes are hard to reason about and hide misconfiguration; an explicit flag plus a preflight warning is auditable and predictable.

## References

- Code: `pkg/vault/` (marker path builders, `MarkPolicyManaged`/`MarkRoleManaged`, `ListManagedPolicies`/`ListManagedRoles`), `shared/controller/binding/`, `internal/webhook/`.
- Related ADRs: [ADR 0003](0003-two-level-drift-and-conflict-config.md) (conflict policy), [ADR 0006](0006-cluster-name-prefix.md) (cluster prefix).
- Vault: [KV v2 custom metadata](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#create-update-metadata), [ACL policy path syntax](https://developer.hashicorp.com/vault/docs/concepts/policies).
