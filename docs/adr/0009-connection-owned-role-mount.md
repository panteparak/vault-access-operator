# ADR 0009: The VaultConnection Owns the Role Auth Mount

- **Status:** Accepted
- **Date:** 2026-07-08
- **Deciders:** @panteparak
- **Related:** [`docs/internal/FLOW_ROLE.md`](../internal/FLOW_ROLE.md), [`docs/internal/FLOW_CONNECTION.md`](../internal/FLOW_CONNECTION.md), [ADR 0006](0006-cluster-name-prefix.md), [ADR 0008](0008-in-band-ownership-markers.md)

## Context

`VaultRole`/`VaultClusterRole` carried their own `spec.authPath`/`spec.authType`,
silently defaulting to `auth/kubernetes` when unset. The auth mount was therefore
declared in two places with different owners: the connection (platform team) and
every role CR (app teams). A production incident made the cost concrete: a
VaultRole with no `authPath`, riding a JWT-login connection (`ep-digital-pe`),
defaulted to `auth/kubernetes` — a mount the operator's Vault token had no grant
for — and hot-looped on 403s. Discovery already read the mount from
`spec.defaults.authPath` while role sync read it from the role spec: two sources
of truth for one infrastructure fact.

The CRDs have distinct audiences: VaultConnection belongs to the platform team;
VaultRole/VaultPolicy/VaultKVSecret belong to app teams. Which Vault auth mount
a cluster's workloads authenticate through is infrastructure knowledge that app
teams should never declare, and the one-cluster-per-auth-mount invariant
(ADR 0006/0008) already *assumed* roles only ever live on "the connection's own
mount" — the role-level fields made that assumption violable.

## Decision

The referenced VaultConnection is the **sole** source of the auth mount and
backend family for role writes. `VaultRole`/`VaultClusterRole` lose
`spec.authPath` and `spec.authType` entirely (hard removal, v1alpha1).

- One canonical resolution rule, `VaultConnection.RoleMount()`
  ([`api/v1alpha1/vaultconnection_rolemount.go`](../../api/v1alpha1/vaultconnection_rolemount.go)):
  1. `spec.defaults.authPath` if set — family from the new optional
     `spec.defaults.authType`, else the `kubernetes*`/`jwt*` name heuristic
     (exact or `-`/`_`-separated); unclassifiable names are an admission error.
  2. Otherwise the connection's own login mount: `auth.kubernetes` →
     kubernetes family; `auth.jwt`/`auth.oidc` → jwt family (Vault's OIDC
     method IS the jwt backend).
  3. Token/appRole/aws/gcp/bootstrap-only logins without `defaults.authPath`
     have **no role-capable mount**: the webhook denies dependent roles at
     admission; reconcile parks them at `ValidationFailed` as backstop.
- `defaults.authPath` no longer carries a baked `auth/kubernetes` default —
  absent means "follow the login mount". The dead `defaults.secretEnginePath`
  and `defaults.transitPath` fields are removed.
- Cleanup deletes resolve the mount **binding-first**: `status.binding.authMount`
  recorded at last sync wins over the connection's current mount, so a
  platform-team mount migration never re-targets an existing role's delete.
  Changing the resolved mount under dependent roles emits an admission warning.
- Discovery and orphan scanning map role CRs to mounts via the set of
  connections resolving to the scanned mount (two connections sharing a mount
  both count), not per-role spec fields.
- Boundary: policy rules and KV paths still embed raw Vault paths (mount
  included) by design — this decision covers only auth-role mounts.

## Consequences

### Positive

- The persona boundary is structural: app-team CRDs cannot express
  infrastructure decisions, so a missing/wrong mount is fixed once, on the
  connection, by the team that owns it.
- The one-cluster-per-auth-mount invariant is true by construction for roles —
  a role literally cannot target a foreign mount.
- The 403 failure mode that motivated this becomes an explicit, admission-time
  error (`no role-capable auth mount`) instead of a silent wrong-mount default.
- Deletes one public API surface (`authType`), one heuristic
  (`pkg/vault.ResolveAuthBackend`/`AuthBackendForPath`), and the webhook's
  authPath immutability machinery.

### Negative

- **Breaking change.** Existing role manifests with `authPath`/`authType` are
  silently pruned by the API server on apply; roles that relied on the implicit
  `auth/kubernetes` default under a non-kubernetes-login connection now follow
  the connection. Migration: declare the mount once via `defaults.authPath`.
- Roles on N different mounts of one Vault now require N connections (each
  connection resolves exactly one role mount). This is deliberate — it mirrors
  the one-cluster-per-auth-mount invariant — and connections are cheap.

### Neutral

- The role webhook now fetches the referenced connection (one GET per
  admission). Missing connection admits with a warning (GitOps ordering);
  the reconcile backstop re-derives everything.
- `AuthBackendType` survives as the `defaults.authType` enum.

## Alternatives considered

### Alternative A: keep role-level fields as optional overrides

Default to the connection's mount but let roles override. Rejected: it keeps
the infrastructure leak on app-team CRDs — the explicit requirement was a sole
declaration point with no flexibility on the role side.

### Alternative B: strict login-mount inheritance (no defaults.authPath)

Roles always land on the login mount, period. Rejected: token-auth connections
(the local e2e stack, break-glass setups) could never manage roles, and a
platform whose operator logs in via one mount (e.g. JWT/IRSA) while workloads
authenticate via another couldn't express that split.

### Alternative C: new dedicated `spec.roleMount` block

Honest naming, but breaks the connection schema and discovery for zero
functional gain over redefining `defaults.authPath`, which discovery already
read as "the connection's mount".

## References

- Source: [`api/v1alpha1/vaultconnection_rolemount.go`](../../api/v1alpha1/vaultconnection_rolemount.go),
  [`features/role/controller/handler.go`](../../features/role/controller/handler.go) (`resolveRoleTarget`),
  [`internal/webhook/vaultrole_webhook.go`](../../internal/webhook/vaultrole_webhook.go)
- Related ADRs: [0006](0006-cluster-name-prefix.md) (cluster-name prefix),
  [0008](0008-in-band-ownership-markers.md) (roles have no in-band ownership record)
