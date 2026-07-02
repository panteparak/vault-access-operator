# ADR 0008: In-band ownership markers on the managed Vault objects

- **Status:** Accepted (supersedes [ADR 0007](0007-hierarchical-metadata-only-managed-markers.md))
- **Date:** 2026-07-02
- **Related:** [ADR 0006](0006-cluster-name-prefix.md), [`CONTEXT.md`](../internal/CONTEXT.md#managed-marker), [`FLOW_POLICY.md`](../internal/FLOW_POLICY.md), [`FLOW_ROLE.md`](../internal/FLOW_ROLE.md), [`FLOW_DISCOVERY.md`](../internal/FLOW_DISCOVERY.md), [`FLOW_DELETION.md`](../internal/FLOW_DELETION.md), [`FLOW_KVSECRET.md`](../internal/FLOW_KVSECRET.md)

## Context

ADR 0007 stored ownership markers in a **dedicated KV v2 subtree**
(`secret/metadata/vault-access-operator/managed/{cluster}/{kind}/...`,
custom_metadata only). That fixed the data-capability and isolation problems
of the original flat path, but the subtree itself remained a liability:

- It requires a **marker-specific Vault grant** (`create,read,update,list,delete`
  on the subtree) that exists only to serve the operator's bookkeeping.
- The marker lives **apart from the object it describes**: it can drift
  (marker without policy, policy without marker), needs its own cleanup step,
  and a wiped subtree loses all ownership memory (hence the
  restore-managed-markers annotation).
- Enumeration is a recursive LIST walk over a synthetic hierarchy.

Investigation of Vault's API surface (CE and Enterprise, through 1.20) found:

- **ACL policies** carry exactly two fields (`name`, `policy`) — no metadata —
  but Vault stores and returns the policy document **verbatim**, so HCL
  comments round-trip byte-for-byte.
- **KV v2 secrets** natively support `custom_metadata` on their own metadata
  path (the `VaultKVSecret` feature already used this in-band).
- **Auth roles have no metadata surface at all**: unknown parameters are
  dropped by Vault's SDK framework; the only candidate (`alias_metadata`) is
  Vault 1.21+, Enterprise-flagged, and leaks its keys into entity-alias
  custom metadata at every login — unusable as a marker.

## Decision

Delete the marker subtree. Store ownership **in-band, on the managed objects
themselves**, keyed to a new **operator identity: the auth mount path** the
operator's connection logged in through.

- **Deployment invariant (hard requirement):** on a shared Vault, **each
  cluster's operator authenticates through its own auth mount** (one cluster
  per mount). Auth mount paths are global on a Vault server, so the mount
  uniquely identifies the owning operator instance. A static-token connection
  has no mount and therefore no identity (Warning event
  `OwnershipIdentityUnavailable`; unsupported for multi-operator Vaults).
- **Policies:** a structured comment header is prepended to every generated
  policy document (stable identity fields only — no timestamps, so an
  unchanged spec never re-hashes):

  ```hcl
  # managed-by: vault-access-operator
  # auth-mount: k8s-prod-eu
  # cluster: prod-eu            <- only when --cluster-name is set
  # k8s-resource: team-a/my-policy
  # k8s-kind: VaultPolicy
  ```

  Ownership checks read the policy and parse the header
  (`vault.ParseOwnership`). Drift comparison already strips comments
  (`normalizeHCL`), so the header is drift-neutral.
- **KV secrets:** the existing custom_metadata stamp is enriched with
  `auth-mount`, `cluster`, `managed-at` (preserved across re-stamps) and
  `last-updated`; ownership checks compare identity + owning CR, not just the
  `managed-by` sentinel.
- **Roles:** no Vault-side record. Ownership memory is the owning CR's status
  (a CR that has synced owns its role); cross-cluster safety is structural
  (mount isolation). Conflict detection: role exists + CR never synced →
  adopt-or-fail.
- **Ownership = sentinel + identity + owning CR.** `Ownership.SameOwner`
  requires all three; a policy whose header names another auth mount is
  foreign — conflicts are reported, adoption is blocked, cleanup refuses to
  delete it, and discovery never offers it for adoption.
- **Destructive-op gate:** policy deletion re-reads the live header and skips
  the delete (Warning event `ForeignPolicyNotDeleted`) when the object is
  foreign-owned. Previously cleanup deleted unconditionally.
- **`--managed-markers` keeps its opt-in semantics** (default off:
  write-and-forget, no ownership checks, no discovery/orphan controllers) —
  but enabling it now requires **no additional Vault grant**.
- **Deleted with the subtree:** `PreflightMarkers` (nothing to preflight),
  the `vault.platform.io/restore-managed-markers` annotation (headers
  self-heal on every sync), and the marker read/write/list client surface.

`--cluster-name` (ADR 0006) is orthogonal: it *prevents* name collisions by
prefixing derived names; the identity *detects and blocks* fights when names
do collide. Multi-operator deployments should still set it.

## Consequences

### Positive

- **Zero marker grant.** The operator's Vault policy shrinks to exactly the
  paths it manages; `--managed-markers` no longer changes the required policy.
- **No split-brain.** The ownership record lives and dies with the object:
  deleting a policy deletes its record; no orphaned markers, no restore
  mechanism, no marker cleanup step.
- **Human-auditable.** `vault read sys/policies/acl/<name>` shows the owner
  directly; `vault kv metadata get` shows the enriched secret ownership.
- **Cross-cluster safety improved.** Ownership comparison now includes the
  operator identity, closing the collision blind spot where two clusters'
  CRs with identical `namespace/name` coordinates were indistinguishable
  (previously `IsOwnedBy` matched any operator instance).
- Discovery no longer offers foreign-operator policies as adoption candidates.

### Negative

- **Roles have no Vault-side ownership record** (Vault limitation, not a
  choice). Reinstalling the cluster (recreating CRs) loses role-ownership
  memory — pre-existing roles must be re-adopted (`ConflictPolicy: Adopt`).
  Two operators violating the one-cluster-per-mount invariant on the same
  mount cannot detect each other's role writes.
- **Discovery/orphan scans read each candidate policy** (one GET per policy
  that passes the filters) instead of one recursive LIST — more round-trips
  on servers with many policies, bounded by running filters first.
- **Breaking migration.** Existing subtree markers become inert (delete
  manually: `vault kv metadata delete` under
  `secret/metadata/vault-access-operator/managed/`). Policies written before
  this change parse as unmanaged — re-adopt via `ConflictPolicy: Adopt` or
  the adopt annotation; the next sync rewrites each policy once with the
  structured header. KV secrets stamped before enrichment lack the identity
  key and are conservatively retained (never deleted) by cleanup.

### Neutral

- The header adds ~5 comment lines to every managed policy document.
- `managed-at`/`last-updated` timestamps exist only where they are free
  (KV custom_metadata, CR status) — the policy header carries stable identity
  only, so reconciles stay write-free when nothing changed.

## Alternatives considered

- **`alias_metadata` for roles** (Vault 1.21+): stored on the role and
  returned on read, but Enterprise-flagged in the changelog and its keys are
  copied into entity-alias custom metadata for every workload that logs in —
  an identity-store side effect a marker must not have. Rejected.
- **Keep a KV subtree for roles only** (hybrid): preserves cross-reinstall
  role-ownership memory at the cost of keeping the marker grant and the
  split-brain failure modes for the one kind that benefits least. Rejected.
- **Name-prefix-only ownership** (no header): cannot distinguish "ours" from
  "another cluster's" when prefixes are unset/equal, and loses the owning-CR
  record that orphan detection needs. Rejected.

## References

- Code: `pkg/vault/managed.go` (`Ownership`, `OwnershipHeader`,
  `ParseOwnership`, `GetPolicyOwnership`), `pkg/vault/client.go`
  (`Client.AuthMount`), `pkg/vault/kvsecret.go` (`KVOwnedBy`, enriched
  `StampKVOwnership`), `features/*/controller/`, `pkg/orphan/`,
  `features/discovery/controller/scanner.go`.
- Vault: [Policies API](https://developer.hashicorp.com/vault/api-docs/system/policies)
  (name + policy only), [KV v2 custom metadata](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#create-update-metadata),
  [Limits and maximums](https://developer.hashicorp.com/vault/docs/internals/limits)
  (custom_metadata: 64 keys × 128B × 512B).
