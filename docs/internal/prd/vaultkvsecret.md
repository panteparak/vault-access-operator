# Seed Vault KV v2 paths for External Secrets Operator (`VaultKVSecret`)

- **Author:** panteparak
- **Date:** 2026-06-19
- **Status:** Implemented
- **Tracking:** —

## Problem statement

In a GitOps deployment, External Secrets Operator (ESO) reads a secret from a Vault KV v2 path (e.g. `secret/data/apps/myapp/config`). On a fresh stack that path does not exist yet, so ESO's first sync 404s and the `ExternalSecret` goes `SecretSyncedError`. There is a chicken-and-egg gap: nobody has populated the path, but ESO needs it to exist before it can sync. Operators today work around this by hand-creating placeholder secrets out-of-band — undocumented, un-GitOps'd, and easy to forget on the next environment.

## Goals

What does success look like? Bullet list, each item testable.

- [x] G1: A `VaultKVSecret` CR pre-creates ("seeds") its Vault KV v2 path so ESO's first sync resolves instead of 404-ing.
- [x] G2: The operator never overwrites or reads the real values stored at that path — real data written later by ESO or a human is preserved.
- [x] G3: On CR delete, an untouched seed is cleaned up; a modified secret or one owned by someone else is retained (never destroy real data).

## Non-goals

What this requirement explicitly does **not** cover. Use this to fend off scope creep.

- N1: NOT a general secret manager — no value updates, rotation, templating, or syncing. The model is strictly create-only-if-absent.
- N2: No cluster-scoped `VaultClusterKVSecret` in v1 (and therefore no adapter pattern — there is a single concrete type). Possible follow-up.
- N3: The CR does not gate ESO ordering. There is no hard Kubernetes ordering between a `VaultKVSecret` seed and ESO's sync; ESO's `refreshInterval` retries cover the gap.

## Acceptance criteria

Concrete, testable bullets. Each maps to at least one test (unit, integration, or e2e).

- [x] AC1: When the path is absent, the operator seeds it → the path exists in Vault and `status.seeded=true`, `status.seededVersion=1`. (`TestSyncKVSecret_SeedWhenAbsent`, `INT-KVS01`)
- [x] AC2: When the path already exists, the operator skips it → never overwrites, `status.seeded=false`. (`TestSyncKVSecret_SkipWhenPresent`, `INT-KVS02`)
- [x] AC3: On CR delete with `deletionPolicy: Delete`, an untouched operator-owned secret is deleted; a secret written-to since seeding, foreign-owned, or `deletionPolicy: Retain` is retained. (`TestCleanupKVSecret_*`, `INT-KVS03`, `INT-KVS04`)
- [x] AC4: A literally empty `data: {}` seed writes an empty secret (sufficient for ESO whole-secret `dataFrom` reads). (`INT-KVS05`)
- [x] AC5: With the `vault.platform.io/dry-run=true` annotation, no write hits Vault and a `DryRun` status condition is surfaced. (`TestSyncKVSecret_DryRun_NoWrite`, `INT-KVS06`)
- [x] **AC6: The operator's data-path capability is `create`-only — `read` / `update` / `delete` on `<mount>/data/*` are NOT required.** Existence and untouched checks read `<mount>/metadata/*`; deletion uses `DeleteMetadata`. The originally-assumed `read` "to see the secret" is dropped by the metadata-driven design. A create-only data-path token can complete the full seed→stamp→untouched-check→delete lifecycle, and a forced overwrite under that token is denied `403`. (`INT-KVS07`)
- [x] AC7: All existing tests still pass; `make verify-templates` reports no drift.

## Affected CRDs / API surface

A **new namespaced CRD** is introduced — this is additive, net-new, no migration.

- **NEW CRD `VaultKVSecret`** (group `vault.platform.io/v1alpha1`, namespaced, shortName `vks`).
- `VaultKVSecret.spec.connectionRef` — new required string (name of the `VaultConnection`).
- `VaultKVSecret.spec.path` — new required string, full KV v2 data path (must contain a `/data/` segment); **immutable** after creation, enforced by a CEL `x-kubernetes-validations` rule.
- `VaultKVSecret.spec.data` — new optional `map[string]string`, default `{}`.
- `VaultKVSecret.spec.deletionPolicy` — reuses the existing `DeletionPolicy` enum (`Delete` | `Retain`, default `Delete`).
- `VaultKVSecret.status.vaultPath` — new string (resolved seeded path).
- `VaultKVSecret.status.seeded` — new bool (operator created it vs. pre-existing).
- `VaultKVSecret.status.seededVersion` — new int (KV v2 version baseline for the untouched check).
- Plus inline `ReconcileStatus` + `SyncStatus` (phase, message, conditions, etc.).

> ⚠️ This is the first CRD in the repo to use CEL validation (`x-kubernetes-validations`) instead of an admission webhook.

## Affected docs

- `docs/api-reference.md` — new `## VaultKVSecret` section (create-only + delete-if-untouched semantics, ESO `.property` caveat).
- `docs/internal/FLOW_KVSECRET.md` — new flow doc (reconcile + cleanup sequences, trimmed-reconcile rationale).
- `docs/internal/CONTEXT.md` — new domain terms (Secret seeding, VaultKVSecret).
- `docs/auth-methods/bootstrap.md`, `docs/configuration.md` — the new operator Vault capability (create-only on `secret/data/*`, `read`/`patch`/`delete` on `secret/metadata/*`).
- `CHANGELOG.md` — `### Added` entry under `[Unreleased]`.

## Compatibility & migration

- **Backward compatibility:** Net-new CRD; no existing CR is affected. Pre-existing resources continue to reconcile unchanged. `spec.data` defaults to `{}` and `spec.deletionPolicy` defaults to `Delete`.
- **Version skew:** None within the operator's own CRs. The new CRD must be applied before any `VaultKVSecret` is created (standard `make manifests` / `helm-update-crds` flow). The operator's Vault **policy** must gain the create-only `secret/data/*` + `read`/`patch`/`delete` `secret/metadata/*` grants before seeding works — see Security considerations.
- **Webhook validation:** None. Validation (path immutability + `/data/` segment) uses CEL `x-kubernetes-validations`, so no `--enable-webhooks` dependency and no cert wiring.

## Security considerations

This touches the operator's Vault RBAC/policy — an RBAC / service-account boundary change.

- [ ] Changes auth path (login, token issuance, token rotation) — **No.** The operator's Kubernetes auth-role binding (`auth/kubernetes/role/vault-access-operator`) is unchanged; it inherits the new capabilities automatically. This is a Vault **policy** change, not an auth-role change.
- [ ] Changes webhook input/output handling — **No.** CEL validation only.
- [x] Changes RBAC or service-account boundaries — **Yes.** The operator's Vault policy gains KV grants (details below).
- [x] Introduces a new user-controlled string that ends up in a Vault path — **Yes.** `spec.path` is written to a Vault KV v2 path. Constrained by CEL (`^[^/]+/data/.+`) and bounded in production by scoping the `secret/data/*` prefix.

**Least-privilege grant (the key design point).** To seed, the operator's own Vault policy needs **`create`-ONLY** on the target `secret/data/*` — **NOT `update`, `read`, or `delete`** — plus `read`/`patch`/`delete` on `secret/metadata/*` (no `list` needed):

```hcl
path "secret/data/*"     { capabilities = ["create"] }
path "secret/metadata/*" { capabilities = ["read", "patch", "delete"] }
```

**The operator needs NO `read` on `secret/data/*`.** The original assumption was that `read` would be required "to see" the seeded secret. With the create-only + KV-v2-metadata design that requirement was **dropped**: existence checks and the untouched-check read `secret/metadata/*` (never secret data values), the ownership stamp is `custom_metadata`, and deletion uses `DeleteMetadata`. The net effect is that the operator can CREATE empty secrets but can never read or overwrite the real values users/ESO store — **Vault itself enforces the never-clobber guarantee** (defense-in-depth above the `cas=0` code). In production, scope the `secret/data/*` prefix to the paths you actually seed (e.g. `secret/data/apps/*`).

> ⚠️ KV v2's create-vs-update ACL evaluation is version-dependent. `INT-KVS07` pins the create-only decision against the test Vault image. If a Vault version rejects the `cas=0` first write under create-only, fall back to `["create","update"]` on `secret/data/*` only — the `cas=0` code still guarantees never-overwrite, just without the Vault-layer backstop.

Policy fixtures: `test/e2e/fixtures/policies/operator-bootstrap.hcl` (production baseline, with least-privilege note) and `test/e2e/fixtures/policies/e2e-operator-bootstrap.hcl` (e2e dev stack).

## Open questions

- Q1: Should a cluster-scoped `VaultClusterKVSecret` variant be added for platform-team-owned shared paths? — Deferred (N2); revisit if demand appears.
- Q2: Should the seed support a non-default mount declared explicitly rather than parsed from `path`? — Currently inferred via `SplitKVv2Path` on the first `/data/` segment, which covers non-default mounts (`kv/data/x`). Revisit only if a mount has no `/data/` segment.

## Implementation sketch

1. Add the CRD type (`api/v1alpha1/vaultkvsecret_types.go`) with CEL + printcolumn markers; `init()` self-registers with the scheme.
2. Add the KV v2 client surface (`pkg/vault/kvsecret.go`): `SplitKVv2Path`, `CreateKVSecretIfAbsent` (atomic `cas=0`), `ReadKVMetadata`, `StampKVOwnership`, `IsOwnedBy`, `DeleteKVSecret`. Do NOT extend the `VaultOpsClient` interface.
3. Add a thin feature (`features/kvsecret/`): a `base.BaseReconciler[*VaultKVSecret]` plus a `Handler` implementing `Sync`/`Cleanup` directly — **a trimmed reconcile, NOT the shared `SyncWorkflow`** (create-only-if-absent deliberately abandons drift management).
4. Grant the operator's Vault policy `create`-only on `secret/data/*` and `read`/`patch`/`delete` on `secret/metadata/*` (HCL fixtures + docs).
5. Tests: unit (`TestSyncKVSecret_*`, `TestCleanupKVSecret_*`, `pkg/vault` cases), integration (`INT-KVS01..07`), e2e (`TC-KVS01..02`).
6. Docs: this PRD, `FLOW_KVSECRET.md`, `api-reference.md`, `CONTEXT.md`, `CHANGELOG.md`, bootstrap/configuration capability note.

## References

- Related ADRs: [ADR 0001](../../adr/0001-adapter-pattern-for-cluster-scoped-types.md) (adapter pattern — explicitly *not* used here), [ADR 0002](../../adr/0002-template-method-base-reconciler.md) (BaseReconciler this feature builds on), [ADR 0003](../../adr/0003-two-level-drift-and-conflict-config.md) (drift/conflict config the trimmed reconcile bypasses).
- Related FLOW docs: [FLOW_KVSECRET.md](../FLOW_KVSECRET.md), [FLOW_POLICY.md](../FLOW_POLICY.md) (the canonical `SyncWorkflow` this feature diverges from), [FLOW_OVERVIEW.md](../FLOW_OVERVIEW.md).
- Domain terms: [CONTEXT.md → Secret seeding / Managed marker / KV v2](../CONTEXT.md).
- Code: `api/v1alpha1/vaultkvsecret_types.go`, `pkg/vault/kvsecret.go`, `features/kvsecret/`.
- External: [External Secrets Operator](https://external-secrets.io/), Vault [KV v2 check-and-set](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2), Vault [policies / capabilities](https://developer.hashicorp.com/vault/docs/concepts/policies).
