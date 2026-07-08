# ADR 0010: Structured Vault names and recorded-name authority

- **Status:** Accepted
- **Date:** 2026-07-08
- **Supersedes:** [ADR 0006](0006-cluster-name-prefix.md) (cluster-name prefix)
- **Amends:** [ADR 0008](0008-in-band-ownership-markers.md) (roles now carry an in-band record)
- **Related:** [ADR 0005](0005-cleanup-failure-configmap-queue.md) (stale-delete retry queue), [`docs/configuration.md`](../configuration.md#sharing-one-vault-across-clusters)

## Context

ADR 0006 derived Vault-side names as `{cluster}-{namespace}-{name}`, dash-joined. Three
problems surfaced once real multi-cluster deployments were planned:

1. **Ambiguity.** Dashes are legal inside every component, so cluster `pe` + namespace
   `prod-app` produces the same string as cluster `pe-prod` + namespace `app`. Names
   could not be parsed back and did not reveal they were operator-managed.
2. **Soft identity.** The prefix is an optional, free-typed flag. The *enforced*
   per-cluster identity — the auth mount, one cluster per mount — lived only in the
   policy comment header, invisible in Vault UI listings and absent for roles entirely.
3. **Renames orphaned objects.** Cleanup and drift re-derived names on every pass, so
   enabling or changing `--cluster-name` orphaned every previously-written Vault object
   (documented as ADR 0006's main negative).

Prior art consulted: KubeVault names policies `k8s.{cluster}.{ns}.{name}`; Crossplane
records every external resource's name on the resource (`crossplane.io/external-name`)
and treats the record — never a re-derivation — as authoritative.

## Decision

### 1. Fixed 4-segment dotted names

Every Vault object the operator writes is named:

```
vao.{identity}.{namespace}.{name}
```

- `vao` — fixed marker: operator-managed at a glance in Vault listings, and a cheap
  pre-filter for orphan/discovery scans.
- `{identity}` — `--cluster-name` when set; **else the connection's login auth mount**
  (sanitized), which is already unique per cluster (one-cluster-per-mount, ADR 0008);
  else the placeholder `_`. The mount fallback removes the "two clusters typo the same
  prefix" failure class: colliding identities would require sharing an auth mount,
  which the deployment model already forbids.
- `{namespace}` — the CR namespace; `_` for cluster-scoped CRs.
- `{name}` — the CR name, **last** because it may contain dots (RFC 1123 subdomain).

**Injectivity.** The arity is fixed and segments 1–3 are dot-free by construction
(`--cluster-name` charset is `^[a-zA-Z0-9-]+$`; mounts are sanitized to `[A-Za-z0-9_-]`;
namespaces are RFC 1123 labels), so splitting on the first three dots losslessly
recovers `(identity, namespace, name)` and two distinct CRs can never produce the same
string. Variable arity was rejected: `vao.{id}.{name}` ≡ `vao.{ns}.{name}` whenever
`id == ns`, and a dotted cluster-scoped CR name could impersonate a namespaced pair.
`_` is reserved: it is an invalid namespace label, rejected as `--cluster-name`, and
the mount sanitizer maps a literal `_` mount to `-`. A fuzz test
(`FuzzVaultName`) pins the property.

Dots are legal in Vault policy names (only `,` is not, being the token_policies list
separator) and in role names (single URL path segment).

### 2. Recorded names are authoritative (Crossplane external-name pattern)

`status.vaultName` / `status.vaultRoleName` — already recorded on every sync — now
*drive* cleanup and rename detection. The sync workflow binds the name only after the
Vault client resolves (the identity needs the mount), then compares:

- **recorded == derived** → normal sync.
- **recorded ≠ derived** (naming config changed) → **rename**: conflict-check and write
  the new name, verify readback, then ownership-checked delete of the old name. A
  failed old-name delete never fails the sync — the item is queued on the ADR 0005
  cleanup queue (event `StaleVaultNameQueued`) and replayed. The unchanged-spec early
  return explicitly yields to a pending rename (a naming change alone doesn't move the
  spec hash). Dry-run binds the recorded name and never deletes — a preview must not
  initiate a rename.
- **CR deletion** removes the *recorded* name (what was actually written), regardless
  of what today's config would derive; a never-synced CR deletes and enqueues nothing.

This makes any future convention change an ordinary reconcile instead of a fleet-wide
orphaning event — the migration mechanism for this very ADR.

### 3. Role→policy bindings resolve by lookup, not re-derivation

A role's `token_policies` must name the *policy's* Vault object, whose identity depends
on the *policy's* connection — which the role cannot re-derive. `resolvePolicyNames`
now fetches the referenced policy CR and reads its recorded `status.vaultName`. A
missing or not-yet-synced policy yields an unresolved binding (`PoliciesResolved=False`
→ `Ready=False`); the role syncs with the resolved subset and converges via the
existing policy watch when the record lands. This also fixes the latent
cross-connection re-derivation bug.

### 4. Role ownership rides in `alias_metadata` (amends ADR 0008)

Research against the Vault 1.21 CE API: ACL policies accept only `name`+`policy`
(no metadata surface, any edition — the comment header stays), but **both kubernetes
and jwt auth roles support `alias_metadata`** (map<string,string>, stored on the role,
echoed on read; Vault ≥ 1.21 — older Vaults, verified on 1.17, silently drop the
parameter). Every role write now stamps the same ownership
vocabulary as the policy header (`managed-by`, `auth-mount`, `cluster`,
`k8s-resource`, `k8s-kind`) into `alias_metadata`:

- Role **conflict detection** becomes real: a live role whose record names another
  operator/CR is a hard conflict; one naming us is ours even without status memory.
- The **stale-rename delete** for roles gains the same `SameOwner` gate policies have.
- Orphan/discovery use recorded status names, with the `vao.` prefix as a fast filter
  (hand-created roles are never orphan candidates) and `alias_metadata` as authority.

## Consequences

### Positive

- Names are collision-free, parseable, and self-identifying; misconfiguration can no
  longer silently cross cluster boundaries (mount fallback).
- Renames migrate instead of orphaning; the recorded name is the single truth for
  every destructive operation.
- Roles get in-band ownership for the first time; orphan scans stop flagging
  hand-created roles.

### Negative

- **Clean break**: existing installs' objects are renamed on the first sync after
  upgrade (old names are cleaned up by the rename flow because the recorded names are
  still in status). External consumers referencing policies by name must be repointed.
- Identity is the **login** mount, not the role's target mount: a connection logging in
  via `kubernetes` but writing roles to `jwt-gitlab` names those roles
  `vao.kubernetes....` — consistent with policy headers, but may surprise.
- `alias_metadata` propagates to workload entity aliases at login (documented Vault
  behavior). The keys are non-secret (ns/name/kind) and could even serve policy
  templating later. Vaults older than 1.21 silently drop the parameter (verified
  empirically on 1.17), degrading roles to pre-ADR-0010 ownership (status memory +
  mount invariant).
- The operator owns the whole `alias_metadata` map; if a user-facing
  `spec.aliasMetadata` is ever added, operator keys must win on merge.

### Neutral

- Mount sanitizer collisions (`a.b` vs `a-b` → same identity) are theoretical — mounts
  are operator-chosen infrastructure; two clusters would have to deliberately choose
  colliding mount names.
- `alias_metadata` is not part of role drift comparison (field-by-field compare);
  ownership is re-stamped on every write, and an identity change renames the role
  anyway.

## Alternatives considered

- **Keep `{cluster}-{ns}-{name}` with a safer separator.** Fixes ambiguity only; the
  prefix stays optional/soft and renames still orphan.
- **Variable-arity dotted names** (`vao.{id}.{name}` for cluster-scoped). Rejected —
  see injectivity argument.
- **`spec.vaultName` explicit override.** Deferred (YAGNI): `vault.platform.io/adopt`
  covers takeover of existing objects; an override can be added later without breaking
  the recorded-name machinery.
- **Ownership in a marker subtree / out-of-band store.** Already rejected by ADR 0008.
