# ADR 0006: Per-cluster name prefix for Vault resources (CE multi-tenancy)

- **Status:** Accepted
- **Date:** 2026-06-29
- **Related:** [`docs/configuration.md`](../configuration.md#sharing-one-vault-across-clusters), [`CONTEXT.md`](../internal/CONTEXT.md#managed-marker), [`IMPROVEMENTS.md §D`](../internal/IMPROVEMENTS.md), [ADR 0003](0003-two-level-drift-and-conflict-config.md)

## Context

Operators may run **one instance per Kubernetes cluster against a single shared Vault server**. Vault Community Edition has no [namespaces](https://developer.hashicorp.com/vault/docs/enterprise/namespaces) (Enterprise-only), so:

- **ACL policies are global.** `WritePolicy` targets `sys/policies/acl/{name}` — one store for the whole Vault, not scoped by mount or namespace.
- **Managed markers are global.** The marker KV path is hardcoded under the `secret` mount (`secret/data/vault-access-operator/managed/...`).

Per-cluster *mounts* (which CE supports) isolate secrets engines and auth methods — and therefore KV secrets and auth **roles** — but they cannot isolate the policy store or the marker path. The operator derives a Vault name as `{namespace}-{name}` (or `{name}` for cluster-scoped CRs), which is **identical across clusters**. Two clusters that each define `VaultPolicy default/admin` would write the same global policy and the same marker, silently overwriting each other — and conflict detection cannot see it, because the owner identifier (`VaultPolicy/default/admin`) is byte-identical across clusters.

HashiCorp's sanctioned CE multi-tenancy lever is **naming conventions**, not a Vault feature.

## Decision

Introduce an optional, operator-wide **cluster-name prefix** applied to every derived Vault resource name.

- Configured via `--cluster-name` flag / `CLUSTER_NAME` env / `clusterName` Helm value. **Empty (default) disables prefixing**, preserving single-cluster behavior.
- A single helper, [`shared/naming`](../../shared/naming/naming.go), holds the prefix (set once at startup) and exposes `Vault(base) = "{cluster}-{base}"`. Every name derivation routes through it: the policy/role adapters (`GetVaultPolicyName` / `GetVaultRoleName`), the role→policy binding (`binding.VaultPolicyName`, which keeps a role's `token_policies` consistent with the policies themselves), and the managed-marker restore handler.
- The prefix lands on the marker **leaf name**, not a new path segment or schema field. Because each cluster's markers sit at a distinct leaf (`…/policies/{cluster}-{ns}-{name}`), they no longer collide — so **no marker-schema or conflict-logic change is needed**. The owner identifier (`GetK8sResourceIdentifier`) is unchanged.

The prefix is **operator-level**, not per-`VaultConnection`: one Kubernetes cluster has one identity for all the connections it manages.

## Consequences

### Positive

- **Coexistence on one CE Vault.** Multiple clusters manage their own `{cluster}-*` policies/roles with zero collisions and zero silent overwrites.
- **Tiny, low-risk change.** One naming helper plus six derivation sites; the empty default is a perfect no-op, so existing installs and their tests are unaffected.
- **Role bindings stay correct for free** — `token_policies` derive from the same prefixed helper as the policies.

### Negative

- **Renames Vault objects.** Enabling the prefix on an existing install orphans the old unprefixed policies/roles/markers; operators must plan a cutover and repoint any external consumers that reference policies by name.
- **Soft, not enforced.** Two clusters misconfigured with the same prefix collide again — the prefix is a naming convention, not a Vault-enforced boundary (CE offers none).

### Neutral

- The prefix is carried as a process-wide value in `shared/naming` (set once before the manager starts) rather than threaded through every adapter constructor — a deliberate trade for a far smaller diff. Upgrade path: thread an explicit value if per-connection prefixes are ever needed.
- Admission webhooks are intentionally **not** prefixed: their collision checks are purely intra-cluster (K8s-side) comparisons where a uniform prefix cancels on both sides.

## Alternatives considered

- **Cluster-id in the marker payload (fail-loud only).** Keep names shared; add cluster identity so a second cluster touching the same policy gets a blocking `ConflictError` instead of a silent overwrite. Rejected as the primary approach: it gives *safety* but not *coexistence* (one cluster is locked out of any shared name), and both were wanted.
- **Cluster in the marker *path*** (`…/managed/policies/{cluster}/{name}`). Rejected: it isolates each cluster's markers so neither sees the other, which *hides* the still-shared global policy collision instead of solving it.
- **Vault namespaces.** Not available in CE.
- **Separate Vault server per cluster.** Fully isolates everything with no operator change, but the target topology shares one server.
