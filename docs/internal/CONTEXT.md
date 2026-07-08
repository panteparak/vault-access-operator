# Domain Context — Vault Access Operator

This document is the **shared vocabulary** for the operator. When a term in code, FLOW docs, ADRs, or a PR review feels jargon-heavy, it should be defined here.

Terms are grouped by domain (Vault, Operator, Kubernetes). Within each group they're alphabetical. Each entry: definition → why it matters → cross-references.

If you find a term used in the repo that isn't here, **add it** — that's the point.

---

## Vault domain

### Auth method

A backend Vault plugin that authenticates clients. The operator's `VaultConnection` selects exactly one of: `kubernetes`, `jwt`, `oidc`, `aws`, `gcp`, `approle`, `token`, or `bootstrap`. Each has its own config schema. The operator authenticates *to* Vault using one of these — separate from the auth methods that the operator manages *inside* Vault via `VaultRole`.

> See [`FLOW_AUTH.md`](FLOW_AUTH.md), [`docs/auth-methods/`](../auth-methods/) (8 public guides).

### Bootstrap auth

A startup-only auth method where the operator uses a pre-provisioned token to authenticate, then optionally rotates to a different mechanism (typically Kubernetes auth). Used in environments where the K8s SA token isn't usable directly at boot.

> Code: [`pkg/vault/auth/`](../../pkg/vault/auth/) (search for `Bootstrap`).

### HCL (HashiCorp Configuration Language)

The text format Vault policies are written in. The operator generates HCL from the CR's `rules[]` via [`pkg/vault/hcl.go`](../../pkg/vault/hcl.go) (`GeneratePolicyHCL`). User-provided strings are escaped to prevent HCL injection — see the relevant security-test entries in `test/integration/security/`.

### KV v2

The Vault key-value engine, version 2. Supports versioned secrets and **metadata** alongside data. The operator uses KV v2 `custom_metadata` for the in-band ownership stamp on seeded secrets (see Managed marker).

### Managed marker

The operator's **in-band ownership record**, stored ON the managed Vault object itself — there is no separate marker path and no marker-specific grant ([ADR 0008](../adr/0008-in-band-ownership-markers.md)):

- **Policies** — a structured comment header at the top of the policy document (`# managed-by: vault-access-operator`, `# auth-mount: <mount>`, `# cluster: <name>` when set, `# k8s-resource: <ns/name>`, `# k8s-kind: <Kind>`). Vault stores HCL verbatim, so the header round-trips; drift comparison strips comments, so it is drift-neutral. Read back via `vault.ParseOwnership`.
- **KV secrets** — `custom_metadata` on the secret's own metadata path (`managed-by`, `k8s-resource`, `auth-mount`, `cluster`, `managed-at`, `last-updated`).
- **Roles** — none: Vault auth roles have no metadata surface. Ownership memory is the owning CR's status plus the [Operator identity](#operator-identity) mount invariant — which is **true by construction** for roles: they carry no mount fields, so they can only ever land on their connection's [Role mount](#role-mount) ([ADR 0009](../adr/0009-connection-owned-role-mount.md)).

Ownership = the `managed-by` sentinel **+ the same [Operator identity](#operator-identity) + the same owning CR** (`Ownership.SameOwner`). A record naming another identity is *foreign*: conflicts are reported, adoption is blocked, cleanup refuses to delete, and discovery never offers it for adoption.

The **entire mechanism is gated by the `--managed-markers` flag (default OFF)**. When off, the operator skips conflict/ownership detection (write-and-forget) and does not run the discovery or orphan controllers. Enabling it requires **no additional Vault grant**. See [`configuration.md`](../configuration.md#managed-markers).

> See [`FLOW_DELETION.md`](FLOW_DELETION.md), [ADR 0008](../adr/0008-in-band-ownership-markers.md).

### Operator identity

The **auth mount path** the operator's `VaultConnection` logged in through (e.g. `kubernetes`, `k8s-prod-eu`), recorded on the Vault client at login (`Client.AuthMount`). **Hard requirement for shared Vaults: one cluster per auth mount** — mount paths are global on a Vault server, so the mount uniquely identifies the owning operator instance. For roles the invariant is true by construction: a role CR cannot name a mount, only follow its connection's [Role mount](#role-mount) ([ADR 0009](../adr/0009-connection-owned-role-mount.md)). Static-token connections have no mount → no identity (Warning `OwnershipIdentityUnavailable`; unsupported for multi-operator Vaults). See [ADR 0008](../adr/0008-in-band-ownership-markers.md).

### Cluster name

An optional operator-wide prefix (`--cluster-name` / `CLUSTER_NAME` / `clusterName` Helm value) applied to every derived Vault resource name. Lets multiple operators share one Vault CE server (no namespaces → a single global ACL policy store) without colliding on policy/role names. Orthogonal to the [Operator identity](#operator-identity): the prefix *prevents* collisions, the identity *detects and blocks* fights when names do collide. Empty (default) means no prefix. See [`shared/naming/`](../../shared/naming/naming.go), [ADR 0006](../adr/0006-cluster-name-prefix.md), [`configuration.md`](../configuration.md#sharing-one-vault-across-clusters).

### Policy (Vault)

An HCL document granting capabilities (`read`, `write`, `list`, etc.) on Vault paths. Maps to `sys/policies/acl/{name}`. The operator manages policies through `VaultPolicy` (namespaced, Vault name = `<ns>-<name>`) and `VaultClusterPolicy` (cluster-scoped, Vault name = `<name>`).

> See [`FLOW_POLICY.md`](FLOW_POLICY.md), [ADR 0001](../adr/0001-adapter-pattern-for-cluster-scoped-types.md).

### Role (Vault auth method)

A binding inside a Vault auth backend (e.g., `auth/kubernetes/role/<name>`) that ties identities (K8s service accounts, AWS IAM principals, etc.) to Vault policies. The operator manages these through `VaultRole` / `VaultClusterRole`. Which mount a role lands on is connection-owned — see [Role mount](#role-mount).

> See [`FLOW_ROLE.md`](FLOW_ROLE.md).

### Role mount

The auth mount that `VaultRole` / `VaultClusterRole` resources referencing a connection are written to, plus its backend family (kubernetes or jwt). Resolved **solely** from the `VaultConnection` via `RoleMount()` — the role CRDs carry no mount fields ([ADR 0009](../adr/0009-connection-owned-role-mount.md)). Order: `spec.defaults.authPath` (family from `defaults.authType` or the mount-name heuristic) → the connection's own login mount (`kubernetes` → kubernetes; `jwt`/`oidc` → jwt) → **none** for token/appRole/aws/gcp/bootstrap-only logins, where the webhook denies dependent roles and the reconciler parks them at `ValidationFailed`. Deletes resolve **binding-first**: `status.binding.authMount` recorded at last sync wins over the connection's current mount, so a mount migration never re-targets an existing role's delete.

> Code: [`api/v1alpha1/vaultconnection_rolemount.go`](../../api/v1alpha1/vaultconnection_rolemount.go). See [`FLOW_ROLE.md`](FLOW_ROLE.md), [`FLOW_CONNECTION.md`](FLOW_CONNECTION.md).

### Secret seeding

Pre-creating ("seeding") a Vault KV v2 secret path so a consumer — typically External Secrets Operator (ESO) — doesn't 404 when the source path is missing on a fresh deployment. Managed through `VaultKVSecret`. The model is strictly **create-only-if-absent**: the operator writes the path only when absent and **never overwrites or reads** the values stored there, so real data written later by ESO or a human is never clobbered. When it seeds, the operator stamps the secret's KV v2 `custom_metadata` (`managed-by: vault-access-operator`, `k8s-resource: <ns>/<name>`) as the ownership marker. On CR deletion it runs **delete-if-untouched** — removing the secret only if still operator-owned and at the same KV v2 version it seeded (`status.seededVersion`), otherwise retaining it. This stamp is the *same intent* as the [Managed marker](#managed-marker) but uses the seeded secret's own native KV v2 metadata rather than a separate marker path. Seeding requires `create`-only on `secret/data/*` and full caps on `secret/metadata/*` in the operator's Vault policy — notably **no `read` on `secret/data/*`**.

> See [`FLOW_KVSECRET.md`](FLOW_KVSECRET.md), [`prd/vaultkvsecret.md`](prd/vaultkvsecret.md). Code: [`pkg/vault/kvsecret.go`](../../pkg/vault/kvsecret.go), [`features/kvsecret/`](../../features/kvsecret/).

### Token

A short-lived Vault credential. The operator issues tokens via its configured auth method and caches them; expiry triggers re-auth. Tokens are never persisted to K8s. See `FLOW_AUTH.md` for the lease/refresh logic.

---

## Operator domain

### Adapter

A small interface (`PolicyAdapter`, `RoleAdapter`) that hides the difference between namespaced and cluster-scoped CRD variants. The `Handler` operates on the adapter; the reconciler wraps the concrete type. Lets one handler serve both `VaultPolicy` + `VaultClusterPolicy`, and `VaultRole` + `VaultClusterRole`.

> See [ADR 0001](../adr/0001-adapter-pattern-for-cluster-scoped-types.md).

### BaseReconciler

Generic Template Method reconciler in [`shared/controller/base/`](../../shared/controller/base/). Provides fetch → finalizer-add → cleanup-on-deletion → delegate-to-handler → status-update → requeue, parameterized by the CR type. Feature reconcilers register a `FeatureHandler` and delegate.

> See [ADR 0002](../adr/0002-template-method-base-reconciler.md).

### Cleanup queue

A ConfigMap (`operator-cleanup-queue` in the operator's namespace) that holds pending Vault-side deletes that the operator couldn't complete during the K8s deletion flow. A leader-gated `CleanupRetryController` retries them.

> See [ADR 0005](../adr/0005-cleanup-failure-configmap-queue.md), [`FLOW_DELETION.md`](FLOW_DELETION.md).

### Condition

A status field on a CR following the Kubernetes `metav1.Condition` convention. The operator emits conditions like `Ready`, `VaultConnected`, `Synced`, `Drift`. The `shared/controller/conditions` package preserves `LastTransitionTime` when status doesn't change.

> See [`shared/controller/conditions/`](../../shared/controller/conditions/).

### Conflict policy

What to do when a Vault resource with the operator's managed-marker prefix already exists but isn't owned by the current CR. Values: `Fail` (default) — refuse to take over; `Adopt` — take ownership. Also overridable via the `vault.platform.io/adopt=true` annotation, which takes precedence.

> See [ADR 0003](../adr/0003-two-level-drift-and-conflict-config.md).

### Deletion policy

What to do with the Vault-side resource when the K8s CR is deleted. Values: `Delete` (default) — remove the Vault resource; `Orphan` — leave it in Vault. Useful for migration scenarios where the CR is being recreated under a new name.

### Drift

When the in-Vault state of a managed resource has diverged from the K8s CR spec (typically because someone edited Vault directly). Detection uses a SHA256 hash of the canonical spec form, stored in the CR's status and re-computed on each reconcile.

> See [`shared/controller/drift/`](../../shared/controller/drift/), [`shared/controller/hash/`](../../shared/controller/hash/).

### Drift mode

What the operator does when drift is detected. Values: `Ignore` — log and continue; `Detect` (default) — set `Drift` condition and emit event; `Correct` — re-apply spec, overwriting Vault state. Resolved per-resource via the two-level hierarchy (resource override → connection default).

> See [ADR 0003](../adr/0003-two-level-drift-and-conflict-config.md).

### Event bus

In-process pub-sub (`shared/events/`) for cross-feature signaling. Type-safe via generics; type assertion is captured at `Subscribe` time, so dispatch is a plain function call. Used for connection-ready signals, policy-synced events, token issuance audits.

> See [ADR 0004](../adr/0004-event-bus-closure-capture.md), [`FLOW_EVENTS.md`](FLOW_EVENTS.md).

### Feature

A self-contained domain area under `features/<name>/`. Current features: `connection`, `policy`, `role`, `discovery`, `kvsecret`. Each owns its controllers, handler, ops, and domain types. Features depend on `shared/` and `api/`, not on each other. (`kvsecret` is the exception that uses a trimmed reconcile with no `ResourceOps` — see [`FLOW_KVSECRET.md`](FLOW_KVSECRET.md).)

### Finalizer

A K8s metadata field that blocks deletion of an object until cleared. The operator adds finalizers to `VaultPolicy`/`VaultRole`/`VaultClusterPolicy`/`VaultClusterRole`/`VaultKVSecret` so it can clean up Vault state before K8s removes the object (for `VaultKVSecret`, the finalizer runs the delete-if-untouched check). Finalizer string is `vault.platform.io/finalizer`.

### Handler

A feature-level type ([`features/<name>/controller/handler.go`](../../features/)) that implements the `FeatureHandler[T]` interface from `shared/controller/base`. Has `Sync` and `Cleanup` methods. The Handler operates on an Adapter, not directly on the K8s type.

### Managed marker

(Vault-domain term, but the operator-side equivalent is the metadata write at the Vault path.) See `Managed marker` above.

### Observed generation

The `status.observedGeneration` field. Conventionally equals `metadata.generation` after a successful reconcile; lagging means a recent spec update hasn't been processed yet. Used by webhooks and the `vaultclient.Resolve` health gate.

### Reconcile

The core operator loop — a function that takes the current state of the world (CR + Vault) and converges them toward the desired state (CR spec). controller-runtime fires `Reconcile()` on watch events; the BaseReconciler delegates to feature handlers.

### Reconcile ID

A per-reconcile correlation ID logged at every step. Used to trace a single sync attempt across the handler/workflow/ops/Vault layers. Stored in `status.reconcileStatus.lastReconcileID`.

### Resource ops

A feature-specific implementation of `workflow.ResourceOps` (e.g., `PolicyOps`, `RoleOps`). Provides the Vault-side primitives (`Create`, `Read`, `Update`, `Delete`, `Exists`, `GetManagedBy`, `MarkManaged`) that the shared workflow calls.

### Sync workflow

The 9-step state machine in [`shared/controller/workflow/sync.go`](../../shared/controller/workflow/sync.go) that drives every feature's sync: resolve connection → resolve drift/conflict policy → existence check → managed-by check → conflict resolution → write (or skip if hash unchanged) → mark managed → drift-correct (if `Correct`) → emit event.

### Workflow

(Operator-domain) The two state machines in `shared/controller/workflow/`: `SyncWorkflow` and `CleanupWorkflow`. Both are shared by all features (via the Handler delegating into the workflow with feature-specific ResourceOps). Not to be confused with "workflow" in the colloquial sense (process), or with the GitHub Actions workflows in `.github/workflows/`.

---

## Kubernetes / controller-runtime domain

### CRD (Custom Resource Definition)

The schema for a custom K8s resource. This operator owns 6: `VaultConnection`, `VaultPolicy`, `VaultClusterPolicy`, `VaultRole`, `VaultClusterRole`, `VaultKVSecret`. Generated from kubebuilder markers in `api/v1alpha1/*_types.go` → `make manifests` → `config/crd/bases/`. `VaultKVSecret` is the first to validate via CEL (`x-kubernetes-validations`) rather than the admission webhook.

### Generation vs ObservedGeneration

`metadata.generation` increments on every spec change. `status.observedGeneration` is set by the operator after a successful reconcile. When they're equal, the latest spec has been processed.

### Indexer

A cache index keyed by a non-default field (e.g., "list all VaultPolicies that reference VaultConnection X"). Set up in `SetupWithManager`. Used by watch predicates that need reverse-lookup (see [ADR 0001](../adr/0001-adapter-pattern-for-cluster-scoped-types.md) — adapters use indexers for cluster→namespaced enqueue).

### Owner reference

Metadata field linking a child resource to its owner. Garbage collection follows owner refs. The operator does NOT set K8s owner refs from `VaultPolicy` → `VaultConnection` (they're loosely coupled); instead, watches drive re-reconciles.

### Predicate

A `controller-runtime` filter that decides whether a watch event triggers a reconcile. The operator uses `GenerationChangedPredicate` for spec changes and custom predicates for connection-phase transitions.

### SetupWithManager

The function that registers a reconciler with the controller-runtime manager. Wires up the watch, predicates, indexers, and concurrency. One per reconciler.

### Status subresource

A separate update path for `status`. Tests using `fake.NewClientBuilder()` must call `.WithStatusSubresource(...)` for any type the operator updates status on, or `Status().Update(...)` will silently no-op.

### Watch

A long-lived stream of events from the K8s API server for a given resource type. controller-runtime sets one up per `For()` or `Watches()` call in `SetupWithManager`.

### Webhook

An admission-time HTTP endpoint (the operator's `internal/webhook/`) that validates incoming requests. Disabled by default via the `--enable-webhooks` flag; requires cert-manager when enabled.

---

## Cross-references

- The 11 [`FLOW_*.md`](.) files are the runtime-behavior source of truth. CONTEXT.md is the vocabulary they share.
- The [`docs/adr/`](../adr/) directory holds the *why* for non-obvious decisions.
- [`IMPROVEMENTS.md`](IMPROVEMENTS.md) tracks known gaps; ADRs reference its sections where relevant.

If you add or rename a term in code, **add it here in the same PR**. The `/docs-drift` skill will flag missing entries on PRs that introduce new exported names.
