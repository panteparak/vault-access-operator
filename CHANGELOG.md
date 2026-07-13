# Changelog

All notable changes to vault-access-operator are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Claims-only JWT roles (no `serviceAccounts`).** `VaultRole`/`VaultClusterRole`
  no longer require `serviceAccounts` when the `jwt` spec binds an identity via
  `boundClaims`, `boundClaimsList`, or `boundSubject` — serving OIDC tokens with
  no Kubernetes identity, e.g. GitHub Actions / GitLab CI `id_token`s bound on
  `repository`/`ref` claims. A CEL rule on the CRD (mirrored by the validating
  webhook) rejects roles that bind nothing. SA-based roles are unchanged.

## [0.11.1] - 2026-07-09

## [0.11.0] - 2026-07-08

### Changed

- **BREAKING: structured Vault resource names + recorded-name authority
  (ADR 0010).** Every derived Vault name now has the fixed 4-segment shape
  `vao.{identity}.{namespace}.{name}` (`_` fills absent segments). The
  identity segment is `--cluster-name` when set, else the connection's login
  auth mount, else `_`; `--cluster-name` no longer permits dots. The
  recorded `status.vaultName`/`status.vaultRoleName` is now authoritative
  for deletion and rename detection: a naming config change migrates each
  object on its next sync (write new name → verified → delete old name;
  failures queue on the cleanup queue with a `StaleVaultNameQueued` event)
  instead of orphaning it. Role→policy bindings resolve through the
  referenced policy CR's recorded `status.vaultName` (a not-yet-synced
  policy leaves the binding pending, `PoliciesResolved=False`, and the role
  converges via watch). Auth roles now carry an in-band ownership record in
  `alias_metadata` (kubernetes + jwt backends, Vault >= 1.21; older Vaults silently drop it), enabling real
  role conflict detection and ownership-gated deletes; orphan scans only
  consider `vao.`-prefixed role names, so hand-created roles are never
  flagged. The admission webhooks' naming-collision checks are removed —
  the injective name shape makes cross-scope and dash-join collisions
  structurally impossible, so CR pairs the old webhook denied (e.g.
  VaultClusterPolicy "ns-name" alongside VaultPolicy ns/name) are now
  admitted and coexist under distinct Vault names. Supersedes ADR 0006;
  amends ADR 0008.

## [0.10.0] - 2026-07-08

### Changed

- **BREAKING: the VaultConnection now owns the role auth mount.** New
  resolution rule (`VaultConnection.RoleMount()`): `spec.defaults.authPath`
  when set (with new optional `spec.defaults.authType` for mount names the
  `kubernetes*`/`jwt*` heuristic can't classify), otherwise the connection's
  own login mount (`auth.kubernetes`/`auth.jwt`/`auth.oidc` — OIDC resolves
  to the jwt family). Connections logging in via token/appRole/aws/gcp
  without `defaults.authPath` have no role-capable mount. `defaults.authPath`
  no longer defaults to `auth/kubernetes` — absent now means "follow the
  login mount". Discovery scans the resolved mount and skips the role scan
  (policies still scan) on connections without one. Changing the resolved
  mount under dependent roles emits an admission warning naming both mounts.

### Removed

- **BREAKING: `spec.authPath` and `spec.authType` on VaultRole and
  VaultClusterRole.** Roles carry no Vault infrastructure knowledge anymore —
  the auth mount and backend family come exclusively from the referenced
  VaultConnection (persona split: connections belong to the platform team,
  roles/policies to app teams). Migration: delete both fields from role
  manifests; declare the mount once on the connection via
  `spec.defaults.authPath` (or let it follow the login mount). A role that
  previously relied on the implicit `auth/kubernetes` default now follows its
  connection — verify the connection resolves the mount you intended. The
  webhook denies roles referencing a connection with no role-capable mount;
  cleanup deletes are pinned to the mount recorded in `status.binding` at
  last sync, so a later connection mount change never re-targets them.

- **BREAKING: `spec.defaults.secretEnginePath` and `spec.defaults.transitPath`
  on VaultConnection.** Both were declared but never consumed by any code
  path — dead schema removed. Re-add if a KV/transit feature actually reads
  them.

### Added

- **Traceable log context on every workflow line.** The sync and cleanup
  workflows now enrich the context logger once per reconcile with
  `vaultConnection` and (for auth-mount resources) `authPath`, so every
  downstream log line identifies the failure source alongside the existing
  `reconcileID` — no per-call-site fields. The discovery controller joins the
  context-logger chain (its scans now carry a `reconcileID` too).

### Fixed

- **`status.binding.vaultPath` no longer double-prefixed.** Role bindings
  recorded `auth/auth/kubernetes/role/<x>` (the normalized mount was passed
  to a helper that prepends `auth/` itself) and `authMount` carried the
  `auth/`-prefixed form. New bindings record the bare mount + correct path;
  consumers normalize legacy records.

- **Vault 403s now surface as `VaultPermissionDenied` instead of a generic
  transient failure.** When the operator's own Vault token lacks a policy
  grant on the target path (e.g. `auth/<mount>/role/*`), the CR's Ready
  condition now carries reason `VaultPermissionDenied` and the phase message
  names the denied path, instead of the misleading
  `transient error during write …` + `Failed` that retried every 30s with no
  hint that a human must extend the operator's Vault policy. Retry cadence is
  unchanged — fixing the Vault policy still self-heals without re-triggering.

- **Production logs are JSON as documented.** `cmd/main.go` hardcoded zap
  `Development: true` and the Helm chart never rendered its documented
  `logging.*` values into flags. The binary now defaults to controller-runtime's
  production config (JSON, info) and the chart passes `logging.*` through as
  `--zap-log-level` / `--zap-devel` / `--zap-encoder` / `--zap-stacktrace-level`.
  The local e2e stack keeps human-readable console logs.

## [0.9.2] - 2026-07-03

### Fixed

- **Webhook auth-mount inference now matches reconcile-time resolution.** The
  admission webhook used a raw prefix match, so a mount like `auth/jwtgitlab`
  (no `-`/`_` separator after the family name) was accepted at admission but
  rejected by every reconcile as an unsupported backend. The webhook now
  delegates to the same `pkg/vault` resolution the controllers use: such
  mounts are rejected at admission with a pointer to `spec.authType`. Bare
  `jwt`/`kubernetes` paths (docs shorthand) are now also consistently
  recognized as their families during `spec.jwt` validation. Docs updated to
  state the exact rule (`jwt` exact, or `jwt-*`/`jwt_*`).

## [0.9.1] - 2026-07-02

## [0.9.0] - 2026-07-02

### Added

- **In-band ownership markers (ADR 0008).** Ownership records now live ON the
  managed Vault objects themselves instead of the dedicated KV marker subtree
  that 0.8.0 introduced:
  - **Policies** carry a structured comment header inside the policy document
    (`managed-by`, `auth-mount`, `cluster`, `k8s-resource`, `k8s-kind`) — Vault
    stores HCL verbatim, and drift comparison already strips comments.
  - **KV secrets** (`VaultKVSecret`) keep their `custom_metadata` stamp,
    enriched with `auth-mount`, `cluster`, `managed-at` (preserved across
    re-stamps) and `last-updated`.
  - **Roles** carry nothing (Vault auth roles have no metadata surface):
    ownership memory is the owning CR's status plus the one-cluster-per-mount
    invariant.
  The operator's identity is the **auth mount path** its connection logged in
  through. **Hard requirement on shared Vaults: one cluster per auth mount.**
  Static-token connections have no identity → new `Warning` event
  `OwnershipIdentityUnavailable` (unsupported for multi-operator Vaults).
  `--managed-markers` keeps its opt-in semantics but now requires **no
  additional Vault grant**.
- **Cross-cluster collision safety.** Ownership comparison now requires the
  managed-by sentinel **plus** the auth-mount identity **plus** the owning CR
  (previously any operator instance passed). A foreign-owned policy: conflicts
  are reported, adoption is blocked (even with `ConflictPolicy: Adopt`),
  cleanup refuses to delete it (`Warning` event `ForeignPolicyNotDeleted`),
  and discovery never offers it for adoption.

### Changed

- **BREAKING — the managed-marker KV subtree is gone (ADR 0008).** The
  operator no longer writes, reads, or needs any grant on
  `secret/metadata/vault-access-operator/managed/*`. Remove that grant from
  operator Vault policies. **Migration from 0.8.0:** subtree markers are
  inert — delete them manually (`vault kv metadata delete` under
  `secret/metadata/vault-access-operator/managed/`). Policies written by
  0.8.0 and earlier read as *unmanaged* until re-adopted (`ConflictPolicy:
  Adopt` or the adopt annotation); the next sync then rewrites each policy
  once with the in-band ownership header. Roles: existing Active CRs keep
  ownership via their status; only fresh CRs pointing at pre-existing roles
  need `Adopt`. KV secrets stamped before enrichment lack the identity key
  and are conservatively retained (never deleted) by cleanup.

### Removed

- **`vault.platform.io/restore-managed-markers` annotation.** Obsolete under
  in-band ownership: the policy header self-heals on every sync. The operator
  now just clears the annotation with an explanatory log line.
- **Managed-marker connection preflight** (`ManagedMarkersPreflightFailed`
  event): there is no marker grant left to probe.

## [0.8.0] - 2026-07-02

### Added

- **`--managed-markers` flag — opt in to ownership tracking (default OFF).**
  New toggle (`--managed-markers` flag / `MANAGED_MARKERS` env / `managedMarkers.enabled`
  Helm value, default `false`) that gates the entire managed-marker mechanism.
  When OFF (default), the operator writes/reads no markers, skips
  conflict/ownership detection (write-and-forget), and does **not** run the
  discovery or orphan-detection controllers — so it needs no grant on the marker
  KV path. When ON, it does full ownership tracking, discovery, and orphan
  detection, and requires the metadata grant on
  `secret/metadata/vault-access-operator/managed/*`. On a `VaultConnection`
  becoming `Active` it runs a one-time preflight and emits a `Warning` event
  `ManagedMarkersPreflightFailed` if that grant is missing. See
  [ADR 0007](docs/adr/0007-hierarchical-metadata-only-managed-markers.md) and
  [docs/configuration.md](docs/configuration.md#managed-markers).
- **Per-cluster ACL scoping for markers.** Because markers now live under a
  hierarchical path, multi-tenant operators (one per cluster, sharing one Vault
  CE server) can scope the operator token's grant to their own subtree,
  `secret/metadata/vault-access-operator/managed/{cluster}/*`.
- **"Used but not activated" enforcement.** When `--managed-markers` is OFF and a
  CR sets `conflictPolicy: Adopt` (or annotation `vault.platform.io/adopt=true`),
  the controller emits a `Warning` event `ManagedMarkersDisabled` (reconcile
  still proceeds) and — when `--enable-webhooks` is set — the validating webhook
  **rejects the create at admission**. A plain or defaulted
  `conflictPolicy: Fail` is allowed silently.

### Changed

- **BREAKING — managed-marker path + storage moved to KV v2 `custom_metadata`.**
  Markers moved from KV v2 **data** at the old flat path
  `secret/data/vault-access-operator/managed/{policies,roles}/{cluster}-{ns}-{name}`
  to KV v2 **`custom_metadata` (never `secret/data`)** at a hierarchical path:
  `secret/metadata/vault-access-operator/managed/{cluster}/roles/{mount}/{ns}/{name}`
  and `secret/metadata/vault-access-operator/managed/{cluster}/policies/{ns}/{name}`
  (`{cluster}` omitted when `--cluster-name` is unset; cluster-scoped CRs use the
  sentinel `_cluster` in the `{ns}` slot; `{mount}` is roles-only). This enables
  per-segment ACL scoping. **Migration:** when a deployment sets
  `--managed-markers=true` after upgrade, the new metadata path is empty, so
  existing managed resources read as *unmanaged* and conflict under the default
  `Fail` policy. The Vault policies/roles themselves are untouched (no data loss);
  only ownership tracking resets. Remedy: enable with `ConflictPolicy: Adopt`
  (or annotate `vault.platform.io/adopt=true`), let resources re-mark, then
  revert. Old inert markers under `secret/data/vault-access-operator/managed/*`
  can be deleted manually.
- **BREAKING — managed markers are now OFF by default.** Marker tracking was
  previously always on; it is now gated behind `--managed-markers` (default
  `false`, see Added above). Deployments that relied on always-on markers
  **silently lose** ownership tracking, discovery, and orphan detection after
  upgrade unless they set `--managed-markers=true`.
- **Operator managed-marker Vault grant is now metadata-only.** The required
  grant changes from `data: create/read/update/delete` +
  `metadata: list/read/delete` on
  `secret/{data,metadata}/vault-access-operator/managed/*` to **metadata-only**:
  path `secret/metadata/vault-access-operator/managed/*` with capabilities
  `create, read, update, list, delete` and **no `data` capability at all**. This
  grant is required **only when `--managed-markers=true`**; multi-tenant
  operators can scope it per cluster.

## [0.7.0] - 2026-06-30

## [0.6.1] - 2026-06-30

## [0.7.0] - 2026-06-29

### Added

- **`--cluster-name` — share one Vault CE server across clusters.** Optional
  per-cluster prefix (`--cluster-name` flag / `CLUSTER_NAME` env / `clusterName`
  Helm value) applied to every derived Vault resource name (policies, roles, and
  managed markers). Lets multiple operators — one per Kubernetes cluster —
  coexist on a single Vault Community Edition server, whose ACL policy store is
  global because CE has no namespaces. Empty (default) disables prefixing, so
  existing single-cluster installs are unaffected. Role→policy bindings
  (`token_policies`) are prefixed consistently. See
  [ADR 0006](docs/adr/0006-cluster-name-prefix.md) and
  [docs/configuration.md](docs/configuration.md#sharing-one-vault-across-clusters).

## [0.6.0] - 2026-06-23

### Added

- **`spec.authType` override for custom-named auth mounts (VaultRole / VaultClusterRole).**
  - New optional `spec.authType` field (`kubernetes` | `jwt`) declares the auth
    backend family explicitly, overriding inference from the mount-path name. This
    lets a role target a JWT/OIDC (or Kubernetes) auth method mounted at an
    **arbitrary path** — e.g. `authPath: auth/custom-oidc`, `authType: jwt` —
    instead of requiring the path to start with `kubernetes`/`jwt`.
  - When `authType` is unset, behavior is unchanged (family inferred from the path).
  - When `authType: jwt`, `spec.jwt` is accepted on the custom path and a non-empty
    `authPath` is required. Honored consistently at admission (webhook) and reconcile
    (`pkg/vault.ResolveAuthBackend`). Resolves the role-write half of
    [IMPROVEMENTS.md §7](docs/internal/IMPROVEMENTS.md).

- **New `VaultKVSecret` CRD — seed Vault KV v2 paths for External Secrets
  Operator (ESO).** A namespaced CRD (shortName `vks`) that pre-creates
  ("seeds") a KV v2 secret path so ESO's first sync resolves instead of 404-ing
  on a fresh deployment. The operator only ever CREATES the path — it never
  overwrites or reads the values stored there, so real data written later by ESO
  or a human is preserved.
  - **Create-only-if-absent.** On every reconcile, an existing path is skipped
    (`status.seeded=false`) and never overwritten; only an absent path is seeded
    (`status.seeded=true`, `status.seededVersion=1`). The write uses KV v2
    check-and-set (`cas=0`) as a race backstop.
  - **Delete-if-untouched.** On CR deletion with `deletionPolicy: Delete`
    (default), the seeded secret is removed only if it is still operator-owned
    (`custom_metadata.managed-by == vault-access-operator`) AND unmodified since
    seeding (`current_version == status.seededVersion`). A secret written to
    since seeding, or owned by someone else, is retained. `deletionPolicy:
    Retain` never deletes.
  - `spec.path` is the full KV v2 data path (must contain a `/data/` segment)
    and is **immutable** after creation, enforced by a CEL
    `x-kubernetes-validations` rule — the first CRD in the repo to validate via
    CEL rather than the admission webhook.
  - `spec.data` (`map[string]string`, default `{}`) is initial placeholder
    content written only when the path is absent. Seed explicit empty-string
    placeholder keys (`data: {username: "", password: ""}`) for ESO
    `remoteRef.property` references — a literally empty `{}` secret unblocks
    whole-secret (`dataFrom`) reads but a `.property` ref against a zero-key
    secret still reports a missing property.
  - **Dry-run support.** The `vault.platform.io/dry-run=true` annotation skips
    the Vault write and surfaces a `DryRun` status condition.
  - **New operator Vault policy requirement.** To seed, the operator's Vault
    policy needs **`create`-ONLY** on the target `secret/data/*` (NOT `update`,
    `read`, or `delete`) plus `create`/`read`/`update`/`patch`/`delete`/`list`
    on `secret/metadata/*`. This is deliberate least-privilege — the operator
    only ever creates secrets and reads metadata, so Vault itself enforces the
    never-clobber guarantee. Notably it needs **no `read` on `secret/data/*`**.
    Scope the `secret/data/*` prefix to the paths you actually seed (e.g.
    `secret/data/apps/*`) in production. The fixtures
    `test/e2e/fixtures/policies/operator-bootstrap.hcl` and
    `e2e-operator-bootstrap.hcl` carry the updated grants.
  - Implemented as a trimmed reconcile on `base.BaseReconciler` (not the shared
    `SyncWorkflow`), since create-only-if-absent deliberately abandons drift
    management. See [FLOW_KVSECRET.md](docs/internal/FLOW_KVSECRET.md) and the
    PRD [prd/vaultkvsecret.md](docs/internal/prd/vaultkvsecret.md).
- **Multi-value and glob claim matching for JWT VaultRoles.**
  - New `spec.jwt.boundClaimsList` (`map[string][]string`) allows binding a
    single claim to multiple values — e.g. `ref: ["main", "develop"]` — and
    is the recommended field for new specs.
  - New `spec.jwt.boundClaimsType` (`string` | `glob`, default `string`) maps
    to Vault's `bound_claims_type` and enables shell-style wildcard matching
    on claim values. The mode applies to every key in the role's bound_claims
    — Vault does not support per-claim modes.
  - The handler always emits `bound_claims_type` whenever any bound_claims is
    set so toggling `glob → unset` writes the new value rather than leaving a
    stale `glob` in Vault.
  - The admission webhook surfaces non-blocking warnings when a role binds
    `ref` without `ref_type` (tag-spoof guard) or `ref_protected` (unprotected
    branch-namesake guard), when `boundClaimsType` is set with no claims, and
    when a key appears in both `boundClaims` and `boundClaimsList`.
  - New runbook [JWT Authentication: GitLab CI](docs/auth-methods/jwt-gitlab.md)
    documents end-to-end setup against gitlab.com and self-hosted GitLab.
  - End-to-end coverage in `test/e2e/tc_auth_jwt_bound_claims_test.go`
    (`TC-AU08-01..06`): exercises the full `VaultRole` → Vault round-trip
    against a dedicated `auth/jwt-gitlab` mount backed by Dex — list-valued
    matches, glob matching, scalar-vs-list merge precedence, and no-false-
    drift on reconcile.
- **JWT VaultRole support.** `VaultRole` and `VaultClusterRole` now produce a
  Vault JWT-auth role payload when `spec.authPath` targets a JWT mount
  (e.g. `auth/jwt`). Previously the operator always sent a Kubernetes-auth
  payload regardless of `authPath` and Vault rejected JWT mounts with
  `a user claim must be defined on the role`.
  - Defaults are derived from `spec.serviceAccounts` and the referenced
    `VaultConnection`: `role_type=jwt`, `user_claim=sub`,
    `bound_subject=system:serviceaccount:<ns>:<sa>`, and
    `bound_audiences` from the connection's `spec.auth.jwt.audiences`
    (falling back to `["https://kubernetes.default.svc.cluster.local"]`).
  - New optional `spec.jwt` sub-object lets users override `userClaim`,
    `boundAudiences`, `boundSubject`, `boundClaims`, and `roleType`.
  - Admission webhook rejects JWT `VaultRole`s with multiple
    `serviceAccounts` unless `spec.jwt.boundSubject` or
    `spec.jwt.boundClaims` is set explicitly — `bound_subject` accepts a
    single value, so the derivation is ambiguous otherwise.
  - Admission webhook rejects `spec.jwt` on non-JWT auth paths.
  - Drift comparator branches on the auth backend so k8s-auth and JWT
    roles compare only the fields they actually set.
- Exported helper `vault.AuthBackendForPath(path)` that resolves an auth
  path to a backend family (`kubernetes`, `jwt`, or `unknown`).
- **Automatic `token_reviewer_jwt` rotation.** The Kubernetes-auth token
  reviewer controller is now registered with the manager (leader-gated) and
  enrolled per `VaultConnection`, so the JWT Vault uses to call the Kubernetes
  TokenReview API is refreshed before it expires. Previously the controller was
  implemented but never wired, so the reviewer JWT could expire (~24h after
  bootstrap configures it) and silently break Kubernetes auth on long-running
  operators. Opt out with `spec.auth.kubernetes.tokenReviewerRotation: false`.

### Deprecated

- **`spec.jwt.boundClaims` (`map[string]string`)** is superseded by
  `spec.jwt.boundClaimsList` (`map[string][]string`). The deprecated field is
  still accepted and merged into the new field at apply time (lists win on
  key collision). Plan to remove `boundClaims` when the API graduates to
  `v1beta1`.

### Changed

- **VaultPolicy / VaultClusterPolicy `spec.connectionRef` is no longer
  strictly immutable.** The webhook now allows a change when the old and
  new `VaultConnection`s resolve to the same `spec.address`. Different
  addresses are still rejected to prevent silent migrations between Vault
  instances. This unblocks switching a policy between two `VaultConnection`
  CRs that authenticate to the same Vault via different auth methods.
- `VaultRoleSpec.AuthPath` / `VaultClusterRoleSpec.AuthPath` doc comment
  updated to reflect that any `auth/<backend>` mount is supported now
  (was previously documented as Kubernetes-only).

### Fixed

- **Partial bootstrap failures now record progress.** When `VaultConnection`
  bootstrap fails midway, `status.authStatus.bootstrapSteps` now reflects the
  steps that completed before the failure (previously the map was left empty on
  the error path), making partial failures diagnosable via
  `kubectl get vaultconnection <name> -o yaml`.

### Backward compatibility

Existing `VaultRole` / `VaultClusterRole` resources that target
`auth/kubernetes` (the default) behave identically. No migration is
required.
