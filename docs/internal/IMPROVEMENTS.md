# Improvements, Disconnects, Divergences & Gaps

> This is the actionable output of the documentation pass. Each finding is grouped by **Severity** (Critical / Major / Minor / Cosmetic), with evidence, impact, and a recommended fix. Item numbers are stable — the other FLOW docs link back here by `§<n>`.

## Severity Legend

| Severity | Meaning |
|----------|---------|
| 🔴 **Critical** | silent correctness failure, security risk, or user-facing promise the code doesn't keep |
| 🟠 **Major** | missing feature implied by scaffolding; code quality debt that will bite in prod |
| 🟡 **Minor** | inconsistency, duplication, or rough edge — no correctness impact |
| 🟢 **Cosmetic** | naming, docs, structural nits |

---

## ✅ 1. Unwired controllers — **cleanup + orphan RESOLVED** (token lifecycle/reviewer deferred)

> **Status**: Partially fixed in `feat(cleanup): wire cleanup + orphan controllers` (commit pending on this branch). The cleanup and orphan controllers are now registered with the manager via `mgr.Add()` at [cmd/main.go](../../cmd/main.go:297-324). Both are leader-gated so only one replica drains the ConfigMap-backed retry queue.
>
> **Still pending**: the token lifecycle controller and reviewer rotator ([pkg/vault/token/lifecycle_controller.go](../../pkg/vault/token/lifecycle_controller.go), [reviewer_controller.go](../../pkg/vault/token/reviewer_controller.go)) don't yet implement `NeedsLeaderElection()` and require deeper integration with `connection.Config` so the handler can `Register`/`Unregister` them. Tracked as a follow-up in the next tier.
>
> **Tests**: integration tests `INT-CLEAN01/02/03` in `test/integration/cleanup/controller_wired_test.go` — all 3 passing against envtest + real Vault container (9.4s).

<details><summary>Original finding (kept for history)</summary>


**Evidence:**
- [pkg/cleanup/controller.go:92](../../pkg/cleanup/controller.go:92) — complete `Start(ctx)` with leader-election gate
- [pkg/orphan/controller.go:95](../../pkg/orphan/controller.go:95) — same
- [pkg/vault/token/lifecycle.go](../../pkg/vault/token/lifecycle.go) — same
- [pkg/vault/token/rotator.go](../../pkg/vault/token/rotator.go) — same
- [cmd/main.go:234-343](../../cmd/main.go:234) — **none** of them are registered with `mgr.Add(...)`

**Impact:**
- Cleanup queue is never drained — failed Vault deletions leak forever.
- Orphan resources are never detected or metered (the `vault_orphaned_resources` gauge permanently reports 0).
- Token lifecycle controller never proactively renews — current behavior relies on the 30s reconcile requeue, which is only correct by accident.
- Token reviewer rotation never happens — K8s-auth will eventually break silently if the reviewer JWT expires (typically 1h after mount). **This is a ticking time bomb for long-running deployments.**

**Fix (concrete, minimal):**
```go
// cmd/main.go, after feature setup:
cleanupQueue := cleanup.NewQueue(mgr.GetClient(), getOperatorNamespace())
cleanupCtrl := cleanup.NewController(cleanup.ControllerConfig{
    Queue:       cleanupQueue,
    ClientCache: cleanupAdapter{cache: connFeature.ClientCache}, // see §3
    Log:         setupLog.WithName("cleanup"),
})
if err := mgr.Add(cleanupCtrl); err != nil { ... }

orphanCtrl := orphan.NewController(orphan.ControllerConfig{
    K8sClient:   mgr.GetClient(),
    ClientCache: connFeature.ClientCache,
    Log:         setupLog.WithName("orphan"),
})
if err := mgr.Add(orphanCtrl); err != nil { ... }
```

Plus register lifecycle + reviewer controllers similarly and pass them into `connection.Config` so the handler has something real to `Register` against.
</details>

---

## ✅ 2. Silent cleanup failures leak Vault resources — RESOLVED

> **Status**: Fixed. The `CleanupWorkflow` now enqueues a retry item when Vault is unreachable or returns a non-404 error, and treats 404 as success. The cleanup.Controller (wired via §1) drains the queue.
>
> **Test coverage**: 5 new unit tests in `shared/controller/workflow/cleanup_enqueue_test.go` cover: unreachable → enqueue, 404 → no enqueue, 500 → enqueue, nil queue backward-compat, and queue-write failure does not block finalizer removal. Plus the integration + e2e above.
>
> **Also fixed (latent)**: `pkg/cleanup/queue.go` Enqueue had a `cm.Data == nil` panic path when a fresh ConfigMap round-tripped through the real API server. Added a defensive initialization.

<details><summary>Original finding (kept for history)</summary>


**Evidence:** [shared/controller/workflow/cleanup.go:90-93](../../shared/controller/workflow/cleanup.go:90):

```go
vaultClient, err := w.getVaultClient(resource.GetConnectionRef())
if err != nil {
    log.Info("failed to get Vault client during deletion, continuing with finalizer removal")
}
```

**Impact:** If Vault is unreachable (network partition, vault down, auth expired) at the moment a CR is deleted, the operator removes the finalizer anyway. The K8s object is gone; the Vault policy/role remains. No automatic recovery — the orphan scanner (which would detect this) is not wired (§1).

**Additional issue:** even when Vault is reachable, [cleanup.go:95-98](../../shared/controller/workflow/cleanup.go:95) swallows `DeleteFromVault` errors:

```go
if err := ops.DeleteFromVault(ctx, vaultClient); err != nil {
    log.Error(err, "failed to delete "+label+" from Vault")
}
// finalizer removed anyway by BaseReconciler
```

**Fix:**
1. Wire the cleanup queue (§1).
2. In `CleanupWorkflow.Execute`, on any Vault-side failure, **enqueue** before returning nil:
   ```go
   if err := ops.DeleteFromVault(ctx, vaultClient); err != nil {
       _ = w.queue.Enqueue(ctx, cleanup.NewPolicyCleanupItem(...))
       log.Error(err, ...)
   }
   ```
3. Consider gating finalizer removal on successful enqueue — if even the queue write fails, keep the finalizer and let the next reconcile retry.
4. Treat Vault 404 (resource already gone) as success, not error.
</details>

---

## ✅ 3. Cleanup controller typing mismatch — RESOLVED

> **Status**: Fixed. [pkg/cleanup/adapter.go](../../pkg/cleanup/adapter.go) exposes `NewClientCacheAdapter` to bridge `*vault.ClientCache` → `cleanup.ClientCache` interface. Used by the §1 wiring in `cmd/main.go`.
>
> **Test**: `pkg/cleanup/adapter_test.go` pins the interface satisfaction at compile time and the round-trip at runtime.

<details><summary>Original finding (kept for history)</summary>


**Evidence:** [pkg/cleanup/controller.go:36-44](../../pkg/cleanup/controller.go:36):

```go
type VaultClient interface {
    DeletePolicy(ctx context.Context, name string) error
    DeleteKubernetesAuthRole(ctx context.Context, authPath, roleName string) error
}

type ClientCache interface {
    Get(name string) (VaultClient, error)
}
```

But the actual [`vault.ClientCache.Get`](../../pkg/vault/client_cache.go) returns `(*vault.Client, error)`. `*vault.Client` satisfies the interface structurally, but Go's type system won't auto-convert — `cleanup.NewController` **cannot be called with `connFeature.ClientCache` directly**. You need an adapter:

```go
type cacheAdapter struct{ inner *vault.ClientCache }
func (c cacheAdapter) Get(name string) (cleanup.VaultClient, error) {
    return c.inner.Get(name)
}
```

**Impact:** Wiring §1 is more fiddly than it looks. Until this is resolved (either adapter or using concrete type), nothing drives the cleanup controller.

**Fix:** Either
- Add a thin adapter wrapper in `pkg/cleanup` that takes `*vault.ClientCache` directly, or
- Change the cleanup types to depend on `*vault.Client` concretely (the abstraction isn't buying anything — there's only one implementation).
</details>

---

## ✅ 4. `discovery-pending` annotation inconsistency — RESOLVED

> **Status**: Fixed in `fix(discovery): safely adopt VaultRole via discovery-pending guard` (branch `claude/sad-ritchie-c15629`). Addressed §14 and §30 in the same commit.
>
> **Resolution**:
> - Added constants `AnnotationDiscoveryPending` and `AnnotationDiscoveredFrom` in [api/v1alpha1/common_types.go](../../api/v1alpha1/common_types.go).
> - Auto-created `VaultRole` now carries the `discovery-pending=true` annotation and placeholder `ServiceAccounts`/`Policies` (satisfies `MinItems=1` — the old `[]string{}` would have been rejected by API-server schema validation, meaning the bug was even deeper than originally reported).
> - Added skip guards in both `RoleOps.WriteToVault` *and* `RoleOps.ReadbackVerify` (mirrored to `PolicyOps.ReadbackVerify` which had the same latent TransientError loop).
> - Tests: unit tests in `features/{role,policy}/controller/ops_test.go`; integration test `INT-DISC-PEND01/02` in `test/integration/role/discovery_pending_test.go` (real Vault container); e2e test `TC-DISC05-ROLE-ADOPTION` in `test/e2e/tc_discovery_autocreate_test.go`.

<details><summary>Original finding (kept for history)</summary>


**Evidence:**
- [features/discovery/controller/controller.go:216-217](../../features/discovery/controller/controller.go:216): VaultPolicy auto-create **adds** `vault.platform.io/discovery-pending: "true"`.
- [features/discovery/controller/controller.go:251-270](../../features/discovery/controller/controller.go:251): VaultRole auto-create **does not** add this annotation.
- [features/policy/controller/ops.go:107-112](../../features/policy/controller/ops.go:107): `PolicyOps.WriteToVault` honors the annotation (skips write).
- `RoleOps.WriteToVault` ([ops.go:130](../../features/role/controller/ops.go:130)) has **no equivalent skip logic**.

**Impact:** For an auto-created VaultRole, the first reconcile writes **`serviceAccounts: []`** to the Vault role, effectively unbinding all service accounts. The user intended to adopt, but their workload just lost auth to Vault.

**Fix (two complementary changes):**
1. Add `vault.platform.io/discovery-pending: "true"` annotation in [controller.go createRoleCR](../../features/discovery/controller/controller.go:245).
2. Honor it in `RoleOps.WriteToVault`:
   ```go
   if o.adapter.GetAnnotations()["vault.platform.io/discovery-pending"] == "true" {
       logr.FromContextOrDiscard(ctx).Info("skipping write for discovery-pending role", ...)
       return nil
   }
   ```
3. Document this annotation prominently in the user-facing discovery docs (`docs/concepts/discovery.md`).
4. Consider a status condition like `DiscoveryPending=True` so `kubectl get vaultpolicy/vaultrole -o wide` shows the adoption-pending state.
</details>

---

## ✅ 5. `DiscoveredResources` growth — RESOLVED

> **Status**: Fixed. `Reconciler.updateDiscoveryStatus` now truncates `result.DiscoveredResources` at `MaxDiscoveredResourcesInStatus = 500` before persisting and sets a `DiscoveryResultsTruncated` condition (True/Capped or False/WithinCap) so users can see how many entries were dropped without reading scanner logs.
>
> **Tests**: `features/discovery/controller/truncate_test.go` covers over-cap (truncation + True condition), under-cap (False condition cleared), and the §9 patch-based concurrent-write scenario.

<details><summary>Original finding (kept for history)</summary>


**Evidence (updated):** [api/v1alpha1/vaultconnection_types.go:458](../../api/v1alpha1/vaultconnection_types.go:458) has a kubebuilder marker:
```go
// +kubebuilder:validation:MaxItems=500
DiscoveredResources []DiscoveredResource `json:"discoveredResources,omitempty"`
```
So the limit **is** expressed — but via API-server schema validation, not in-controller truncation. The scanner at [controller.go:301-305](../../features/discovery/controller/controller.go:301) still writes the full `result.DiscoveredResources` slice without checking length:

```go
conn.Status.DiscoveryStatus.DiscoveredResources = result.DiscoveredResources
```

**Impact (reframed):** On a Vault with more than 500 unmanaged resources matching the discovery patterns, the *first* scan succeeds up to the point of `Status().Update` — at which point the API server rejects the write with:
```
VaultConnection.vault.platform.io "X" is invalid:
  status.discoveryStatus.discoveredResources: Too many: 600: must have at most 500 items
```
The reconcile returns that error, `Phase` flips to `Error`, the `discovery_scans_total{result=failure}` counter bumps, and the next scan (1h later) tries the identical write and fails identically. Recovery is **not automatic** — the user must tighten discovery patterns (`spec.discovery.policyPatterns`) or delete the CR.

Additionally, `etcd`'s per-object size limit (default 1.5 MB) is a separate ceiling. Even with 500 items cap, if each `DiscoveredResource` is large (long names, metadata), the payload might still push an etcd rejection. 500 × typical 200 B ≈ 100 KB, which is comfortable; 500 × 3 KB ≈ 1.5 MB, which is not.

**Fix:**
```go
const maxDiscoveredInStatus = 500
if len(result.DiscoveredResources) > maxDiscoveredInStatus {
    truncated := len(result.DiscoveredResources) - maxDiscoveredInStatus
    result.DiscoveredResources = result.DiscoveredResources[:maxDiscoveredInStatus]
    // expose the fact via condition
    conditions.Set(&conn.Status.Conditions, conn.Generation,
        "DiscoveryResultsTruncated", metav1.ConditionTrue,
        "Capped", fmt.Sprintf("discovery results truncated: %d items omitted", truncated))
    // log.Info, bump metric, emit warning event
}
```
Plus: emit per-discovered-resource **K8s events** (already done for the aggregate) rather than persisting the full list in status.
</details>

---

## ✅ 6. Auth dispatch chain vs strategy map — RESOLVED

> **Status**: Fixed. The 7-branch `if != nil` chain in `connection.Handler.authenticate` is now a table-driven dispatch: `authStrategies []authStrategy` with `{name, match, run}` tuples. Adding a 9th auth method is a one-line append instead of a new branch.
>
> **Tests**: `auth_strategies_test.go`:
> - `TestAuthStrategiesCoverAllConfiguredMethods` — guard test that fails if a new `AuthConfig` field is added without a matching strategy entry (previously, the old chain had no such guard).
> - `TestAuthStrategiesMatchersAreExclusive` — ensures the matchers don't overlap so exactly one strategy fires per well-formed config.
>
> Existing connection unit + integration tests exercise the end-to-end auth flow and all pass unchanged.

<details><summary>Original finding (kept for history)</summary>


**Evidence:** [features/connection/controller/handler.go:704-802](../../features/connection/controller/handler.go:704) — 100 lines of `if authCfg.X != nil` chained branches for 7 auth methods. Each branch has parallel structure: read config → get token-like input → call `vault.Client.Authenticate*`.

**Impact:**
- Adding a 9th auth method (e.g., Azure AD, Kerberos) touches this file, the spec, and the client wrapper — no central registration point.
- Webhooks would need equally duplicated validation.
- Harder to test — each branch must be exercised via full handler wiring.

**Fix:**
```go
type authenticator interface {
    AuthenticateVault(ctx context.Context, h *Handler, vc *vault.Client, conn *VaultConnection) error
}

var authenticators = []struct{ name string; isConfigured func(*AuthConfig) bool; auth authenticator }{
    {"kubernetes", func(a *AuthConfig) bool { return a.Kubernetes != nil }, kubernetesAuth{}},
    {"jwt", func(a *AuthConfig) bool { return a.JWT != nil }, jwtAuth{}},
    ...
}
```

Keeps each method self-contained, testable in isolation, registration-driven.
</details>

---

## 🟠 7. Role backend coverage gap

**Evidence:** [features/role/controller/handler.go:360-373](../../features/role/controller/handler.go:360):

```go
switch backend {
case vault.AuthBackendKubernetes:
    ...
case vault.AuthBackendJWT:
    ...
default:
    return nil, ValidationError("unsupported auth backend: only auth/kubernetes and auth/jwt are implemented")
}
```

But the operator **authenticates** to Vault via 8 methods (§6). There's an asymmetry:
- The operator can log in via AWS/GCP/OIDC/AppRole/Token.
- But a **VaultRole CR cannot target** an AWS/GCP/OIDC/AppRole mount — only `auth/kubernetes/role/*` or `auth/jwt/role/*`.

**Impact:** Users running on EKS with IRSA who also want to define roles binding AWS IAM principals to Vault policies cannot use this operator for that binding. They can only use it to define their own pod-level roles.

**Fix priorities:**
1. Document the restriction prominently in `docs/api-reference.md` (user-facing).
2. Add webhook validation that rejects `authPath` not in the supported set with a clear message.
3. Plan incremental backend support — start with AppRole roles, then JWT is already done, then cloud IAM.

---

## ✅ 8. Connection webhook — RESOLVED

> **Status**: Fixed. New `internal/webhook/vaultconnection_webhook.go` adds a `VaultConnectionValidator`. Wired into `cmd/main.go` via `SetupVaultConnectionWebhookWithManager` alongside the other four validators. Rules enforced:
> - Exactly one auth method (except the legal `bootstrap + kubernetes` transition pair).
> - `spec.address` is immutable on update (moving to a different Vault would orphan everything).
> - `spec.auth.appRole.roleId` required when AppRole is selected.
> - `spec.auth.oidc`: either `useServiceAccountToken=true` or `jwtSecretRef` set.
> - `spec.discovery.targetNamespace` required when `autoCreateCRs=true`.
> - `http://` address emits a warning (not rejected — valid for local testing).
>
> **Tests**: 10 subtests in `vaultconnection_webhook_test.go` across 6 functions. Coverage includes every rule above plus the immutability check.

<details><summary>Original finding (kept for history)</summary>


**Evidence:** [cmd/main.go:297-314](../../cmd/main.go:297) registers webhooks for `VaultPolicy`, `VaultClusterPolicy`, `VaultRole`, `VaultClusterRole` — but **not `VaultConnection`**.

**Impact:** Malformed connections (e.g., multiple auth sub-structs set, typos in `address`, missing required fields for selected backend) only fail at reconcile time with `Phase=Error`. Users see the error in status, not at `kubectl apply` time.

**Common mistakes only caught at reconcile:**
- Both `Auth.Bootstrap` and `Auth.Kubernetes` set (both are valid in isolation; the second is used only after bootstrap)
- `Auth.AppRole` with no `SecretIDRef`
- `Auth.OIDC` with `UseServiceAccountToken=false` and no `JWTSecretRef`
- `address` without `https://` prefix
- `Discovery.Enabled=true` with `AutoCreateCRs=true` but no `TargetNamespace`

**Fix:** Add `VaultConnectionValidator` under `internal/webhook/` paralleling the policy/role validators. Validation rules to cover each auth method's required fields, URL format, and discovery prereqs.
</details>

---

## ✅ 9. Dual reconcilers on `VaultConnection` → status race — RESOLVED (discovery side)

> **Status**: Fixed on the discovery side, which was the secondary writer that conflicted with the connection controller. `updateDiscoveryStatus` now uses `r.Status().Patch(ctx, conn, client.MergeFrom(original))` instead of `Status().Update`. The patch carries only the DiscoveryStatus subset of fields and the `DiscoveryResultsTruncated` condition, so concurrent writes from the connection controller (Phase, AuthStatus, Healthy) are no longer overwritten.
>
> **Connection-handler side**: left on `Status().Update` because it's the canonical writer for the fields it touches. With the discovery side using Patch, the conflict surface is gone.
>
> **Tests**: `TestUpdateDiscoveryStatus_UsesPatch_NoConflictWithConcurrentConnectionUpdate` simulates the race by mutating Phase out-of-band between Get and Patch, then confirms both writes survive (discovery's DiscoveryStatus AND the concurrent Phase=Active).

<details><summary>Original finding (kept for history)</summary>


**Evidence:**
- [features/connection/controller/reconciler.go](../../features/connection/controller/reconciler.go) watches `VaultConnection` for auth + health.
- [features/discovery/controller/controller.go:314-320](../../features/discovery/controller/controller.go:314) watches the same CRD for discovery.
- Both update `VaultConnection.Status` independently.

**Current mitigation:** [updateDiscoveryStatus](../../features/discovery/controller/controller.go:286) uses `retry.RetryOnConflict`. But the connection controller's `Status().Update` calls are NOT wrapped in retry, so a conflict from there returns an error and requeues (acceptable but noisy).

**Impact:**
- Every minute or two, one of them retries a conflicting update. Log noise; metric counter bumps.
- If the discovery controller's status update wins, `Phase=Active` update from the connection controller might get reverted temporarily.

**Fix options (in order of preference):**
1. **Subresource split**: move discovery state into its own CRD (`VaultDiscoveryScan` owned by the connection). Clean architecturally, breaking API change.
2. **Patch instead of Update**: both controllers should use `client.Status().Patch(ctx, obj, client.MergeFrom(original))` to scope updates to their own fields. Eliminates most conflicts.
3. **Wrap all status updates in retry.RetryOnConflict** everywhere.
</details>

---

## ✅ 10. Bootstrap state persistence — RESOLVED (BootstrapSteps added)

> **Status**: Fixed the diagnostic visibility gap. `AuthStatus.BootstrapSteps` is a new `map[string]string` field (step name → RFC3339 timestamp) populated from `bootstrap.Result` after a successful bootstrap run. Keys cover `AuthMountEnabled`, `AuthMountConfigured`, `OperatorPolicyCreated`, `OperatorRoleCreated`, `BootstrapTokenRevoked`. Operators inspecting `kubectl get vaultconnection X -o yaml` can now see which steps ran.
>
> **Note**: the fine-grained map is only populated on the SUCCESS path today, so a partial failure that returns early from `bootstrap.Manager.Bootstrap` still leaves `BootstrapSteps` empty. Extending the bootstrap manager to record partial progress inside the `Result` struct is a follow-up — that requires changes to `pkg/vault/bootstrap` that deserve their own review cycle. For now, the field exists and the schema is stable; wiring partial-failure recording is additive.

<details><summary>Original finding (kept for history)</summary>


**Evidence:** [features/connection/controller/handler.go:294-313](../../features/connection/controller/handler.go:294) — after `BootstrapComplete=true` is persisted, handler returns immediately so the next reconcile does auth with a fresh object. Good fix for the original issue.

**But:** If `runBootstrap` succeeds partially (auth mount created but policy write failed, or role created but revoke failed), the `BootstrapComplete=true` may be set incorrectly or not at all. There's no finer-grained recording like `AuthMountCreated`, `OperatorRoleCreated`, `BootstrapRevoked` (these exist in `Result` but aren't individually persisted).

**Impact:** Re-running bootstrap after a partial failure could error on "mount already exists" unless the bootstrap manager is idempotent on every step (it is for mount creation, but worth auditing).

**Fix:**
1. Add fine-grained status fields or an `AuthStatus.BootstrapSteps` map.
2. Add e2e test: kill the operator after `AuthMountCreated=true` but before `RoleCreated`. Verify next reconcile resumes correctly.
</details>

---

## 🟡 11. Drift comparator duplication (policy HCL vs role map)

**Evidence:**
- Policy: string normalize + compare in [policy/controller/handler.go:235-245](../../features/policy/controller/handler.go:235) and [ops.go:88-101](../../features/policy/controller/ops.go:88).
- Role: `drift.Comparator` framework in [shared/controller/drift/compare.go](../../shared/controller/drift/compare.go) used by [role/controller/handler.go:169-235](../../features/role/controller/handler.go:169).

**Impact:** Two different drift philosophies. Policy drift is either "yes" or "no" with no detail — users see `"policy content differs"` and must diff manually. Role drift lists exactly which fields changed.

**Fix:** Extend `drift.Comparator` with `CompareMultilineText("rules", expectedHCL, actualHCL)` that produces a unified diff summary, then use it from policy's `DetectDrift`. This unifies behavior AND improves user-facing drift messages for policies.

---

## 🟡 12. Event bus typing uses closures instead of generics

**Evidence:** [shared/events/bus.go](../../shared/events/bus.go) — `Subscribe[T]` captures type assertion in a closure, stores `func(ctx, Event) error`, performs runtime type assertion on publish. This was idiomatic before Go 1.18.

**Impact:** Runtime overhead (negligible). Type assertion can silently swallow events that don't match (a publish of event type X to a handler subscribed for Y just doesn't fire).

**Fix:** With Go 1.22, rewrite as a generic registry:
```go
type handlerRegistry[T Event] struct {
    handlers []func(context.Context, T) error
}
```
Catches mismatches at compile time.

---

## ✅ 13. Duplicated `shouldAdopt` logic — RESOLVED (shouldAdopt extracted; checkConflict deferred)

> **Status**: `shouldAdopt` extracted. The policy and role handlers' `shouldAdopt` functions were byte-for-byte identical modulo the adapter type. New package `shared/controller/conflict` exposes `ShouldAdopt(AdoptCandidate) bool` with a minimal interface both adapters satisfy. Policy and role handlers now delegate.
>
> **Deferred**: the broader `checkConflict` extraction (generic `Check[A any]` with callbacks for `Exists` / `GetManagedBy` / `ShouldAdopt`) is valuable but riskier — the three moving parts differ between policy and role in ways that resist clean abstraction. The current `shouldAdopt` extraction handles the actual duplication that was byte-for-byte; `checkConflict` stays in each handler where it's already well tested.
>
> **Tests**: `shared/controller/conflict/adopt_test.go` pins the annotation-wins-over-policy precedence rule with 5 table cases. Existing handler tests cover the full `checkConflict` end-to-end.

<details><summary>Original finding (kept for history)</summary>


**Evidence:**
- [policy/controller/handler.go:172-181](../../features/policy/controller/handler.go:172) `shouldAdopt(PolicyAdapter) bool`
- [role/controller/handler.go:153-162](../../features/role/controller/handler.go:153) `shouldAdopt(RoleAdapter) bool` — byte-for-byte identical body
- The `checkConflict` functions differ only in (a) which Vault lookup is used (`PolicyExists`/`KubernetesAuthRoleExists`) and (b) which managed-marker path is queried.

**Impact:** Adding a third adapted resource (e.g., a future `VaultKVEntry`) means duplicating these again.

**Fix:** Introduce a generic `conflict` helper in `shared/controller/conflict/`:

```go
package conflict

type Checker[A any] interface {
    Exists(ctx, vc, a A) (bool, error)
    ManagedBy(ctx, vc, a A) (string, error)
    K8sResourceID(a A) string
    ConflictPolicy(a A) vaultv1alpha1.ConflictPolicy
    Annotations(a A) map[string]string
}

func Check[A any](ctx, vc, a A, checker Checker[A]) error { ... }
```
</details>

---

## 🟡 14. `VaultPolicy` HCL skip uses raw annotation string

**Evidence:** [features/policy/controller/ops.go:108](../../features/policy/controller/ops.go:108):

```go
if annotations["vault.platform.io/discovery-pending"] == "true" {
```

Other annotation keys use constants from `api/v1alpha1` (e.g., `AnnotationAdopt`, `AnnotationDiscovered`). Only this one is a raw string.

**Fix:** Add `AnnotationDiscoveryPending = "vault.platform.io/discovery-pending"` to [common_types.go](../../api/v1alpha1/common_types.go) and reference it here + in the discovery auto-create (§4).

---

## ✅ 15. `listDependents` O(N) list operations — RESOLVED

> **Status**: Fixed. `connection.Reconciler.SetupWithManager` now registers a `spec.connectionRef` field indexer for all four dependent CRD kinds (VaultPolicy, VaultClusterPolicy, VaultRole, VaultClusterRole). `Handler.listDependents` queries with `client.MatchingFields{IndexFieldConnectionRef: name}` instead of listing every CR cluster-wide and filtering in Go.
>
> **Tests**: existing Cleanup tests migrated to a shared `newClientBuilderWithConnectionRefIndex(scheme)` helper that registers the same indexer on fake clients — they now exercise the same query path as production. No behavior regressions.

<details><summary>Original finding (kept for history)</summary>


**Evidence:** [connection/controller/handler.go:368-420](../../features/connection/controller/handler.go:368): on **every** connection delete, lists all VaultPolicies, VaultClusterPolicies, VaultRoles, VaultClusterRoles cluster-wide, then filters by `ConnectionRef == conn.Name`.

**Impact:** In a large cluster, 4 full list operations per cleanup. Not hot-path (deletes are rare), but also not scalable if the operator ever manages thousands of CRs.

**Fix:** Use a field index set up in `SetupWithManager`:
```go
mgr.GetFieldIndexer().IndexField(ctx, &VaultPolicy{}, "spec.connectionRef", func(obj client.Object) []string {
    return []string{obj.(*VaultPolicy).Spec.ConnectionRef}
})
// Then at cleanup:
mgr.GetClient().List(ctx, &list, client.MatchingFields{"spec.connectionRef": conn.Name})
```
</details>

---

## 🟡 16. Connection handler doesn't use the shared workflow

**Evidence:** [FLOW_CONNECTION.md §Divergence](FLOW_CONNECTION.md#divergence-from-other-flows)

**Impact:** Policy/role share `SyncWorkflow.Execute`; connection has its own Sync method with different error handling, different status update pattern, different event emission. Maintainers have to keep two codepaths reasoning in their head.

**Trade-off:** The workflow's shape ("validate → conflict → prepare content → write → readback") doesn't fit connection's actual flow ("authenticate → health check → update auth status"). Forcing it into the workflow would need heavy parameterization.

**Recommendation:** **Leave as-is**, but extract a smaller shared helper for:
- `handleSyncError` with auth-error detection + cache evict (currently connection-specific)
- Standardized status-update patterns

Mark this as intentional in a comment, so future maintainers don't feel pressure to unify.

---

## ✅ 17. `normalizeHCL` strips comments + collapses whitespace — RESOLVED (partial)

> **Status**: The user-reported pain ("adding `# managed by ops` in the Vault UI trips drift every reconcile") is fixed. `normalizeHCL` now:
> - Strips line comments (`#…` and `//…`).
> - Strips block comments (`/* … */` but only if a matching `*/` exists — otherwise treats `/*` as part of a path glob like `secret/*`).
> - Collapses runs of whitespace within a line to a single space.
> - Drops empty lines.
>
> **Explicitly NOT fixed in this pass** (deferred to a future HCL-AST-walk refactor using `github.com/hashicorp/hcl/v2`):
> - Rule reordering (two policies with `path` blocks in a different order still compare unequal).
> - Capability-list reordering within a rule.
>
> These residual false positives are manageable because the operator-generated HCL comes from a deterministic `GeneratePolicyHCL` codepath.
>
> **Tests**: `features/policy/controller/normalize_hcl_test.go`:
> - `TestNormalizeHCL_StripsHumanAddedComments` — 4 sub-cases (line, slash, block, inline) all equal generated.
> - `TestNormalizeHCL_PreservesPathGlobs` — regression test for `secret/*` path globs (the bug I introduced and caught during implementation; requires a matched `*/` before treating `/*` as a comment start).
> - `TestNormalizeHCL_CollapsesWhitespace` — multi-space + tabs.
> - `TestNormalizeHCL_StillDetectsSemanticDifferences` — negative test so real differences don't get normalized away.

<details><summary>Original finding (kept for history)</summary>

**Evidence:** [policy/controller/handler.go:235-245](../../features/policy/controller/handler.go:235):

```go
func (h *Handler) normalizeHCL(hcl string) string {
    lines := strings.Split(hcl, "\n")
    ...
    trimmed := strings.TrimSpace(line)
    if trimmed != "" {
        normalized = append(normalized, trimmed)
    }
    return strings.Join(normalized, "\n")
}
```

**Impact:**
- A user manually adding a comment in Vault's HCL (`# managed by ops team`) trips drift detection every reconcile.
- Reordered rules (semantically equivalent) trip drift.

**Fix:** Parse HCL semantically, compare canonical trees. `github.com/hashicorp/hcl/v2` already in `go.sum`. Normalize rules into a set of `(path, capabilities, params)` tuples, sort, hash.
</details>

---

## ❌ 18. `Phase` string vs typed enum inconsistency — DEFERRED (low value vs cost)

> **Status**: Audited; not actioned. Production code already uses the `Phase*` constants consistently — the only bare string literals are in test files (~85 hits) where `"Active"` / `"Syncing"` are the explicit expected values being asserted, and using constants would make the intent less clear. Phase values are part of the public CRD API anyway (kubebuilder `+kubebuilder:validation:Enum=`), so renaming them is a breaking change regardless of whether tests use constants or literals. Keeping the current convention; revisit if a phase is ever added and tests silently reference the old name.

<details><summary>Original finding (kept for history)</summary>

**Evidence:** most code uses `vaultv1alpha1.PhaseSyncing` constant, but some string literal `"Syncing"` usages exist in tests and the cleanup workflow hardcodes `PhaseDeleting`.

**Impact:** Minor. Refactoring risk if phase names change.

**Fix:** Grep for `"Syncing"`, `"Active"`, `"Error"` string literals outside test fixtures, replace with constants.
</details>

---

## 🟡 19. JWT `bound_subject` derivation is brittle

**Evidence:** [role/controller/handler.go:490-522](../../features/role/controller/handler.go:490):

```go
func resolveJWTBoundSubject(adapter RoleAdapter, jwtSpec *VaultRoleJWTSpec, serviceAccountBindings []string) (string, error) {
    if jwtSpec.BoundSubject != "" { return jwtSpec.BoundSubject, nil }
    ...
    // single-SA only
    parts := strings.SplitN(serviceAccountBindings[0], "/", 2)
    return fmt.Sprintf("system:serviceaccount:%s:%s", parts[0], parts[1]), nil
}
```

**Impact:** Multi-SA JWT roles get a ValidationError, which is correct — but the error message says "set spec.jwt.boundSubject or spec.jwt.boundClaims". Users are left to figure out **how** to express multiple SAs via `bound_claims`. No example in docs.

**Fix:**
1. Docs: add an example recipe for multi-SA JWT roles using `bound_claims: { "kubernetes.io/serviceaccount/name": ["sa1", "sa2"] }`.
2. Consider auto-synthesizing `bound_claims` when multiple SAs are given and the user hasn't set `bound_subject` or `bound_claims` explicitly.

---

## ✅ 20. Duplicate `resolvePolicyNames` logic — RESOLVED

> **Status**: Fixed. `role.Handler.resolvePolicyNames` now delegates the actual name mapping to `binding.VaultPolicyName` and only keeps the role-feature-specific validation (unknown kind, namespace required on cluster role). Single source of truth for "given a PolicyReference, what's the Vault policy name?".
>
> **Tests**: existing role handler unit tests continue to pass — they exercise the validation layer that still lives in the handler. The delegated-to mapping is covered by `shared/controller/binding` tests.

<details><summary>Original finding (kept for history)</summary>


**Evidence:**
- [role/controller/handler.go:307-347](../../features/role/controller/handler.go:307) `resolvePolicyNames`
- [shared/controller/binding/paths.go](../../shared/controller/binding/paths.go) has `VaultPolicyName(ref, namespace)` — the same logic inline

**Impact:** Two sources of truth for "given a `PolicyReference`, what's the Vault name?"

**Fix:** Delete the role-handler inline version, call `binding.VaultPolicyName` everywhere.
</details>

---

## 🟢 21. Inconsistent logger-name scoping

**Evidence:**
- Connection feature: `log.WithName("connection")`
- Policy: no consistent scope — some places use `"vaultpolicy"`, some the raw passed logger
- Discovery: `"discovery-controller"`, `"scanner"` (nested)

**Fix:** Standardize on 2-level scoping: `"{feature}.{component}"` e.g., `policy.handler`, `policy.reconciler`, `connection.bootstrap`. Makes log parsing consistent.

---

## 🟢 22. Inconsistent use of `logr.FromContextOrDiscard(ctx)` vs passed-in `log logr.Logger`

**Evidence:** Some methods take `log` explicitly (e.g., `runBootstrap`), others fetch from context. Mixing both is confusing.

**Fix:** Pick one. Recommend `logr.FromContextOrDiscard(ctx)` because `BaseReconciler.Reconcile` already enriches the context with `reconcileID`.

---

## ✅ 23. `MinScanInterval` package var → ReconcilerConfig field — RESOLVED

> **Status**: Fixed. `ReconcilerConfig.MinScanInterval` is a new optional field. When zero, falls back to the package-level `MinScanInterval` (which itself reads `OPERATOR_MIN_SCAN_INTERVAL`). Tests construct a reconciler with a short interval via `ReconcilerConfig{MinScanInterval: time.Second}` instead of mutating the global.
>
> **Tests**: `min_scan_interval_test.go` covers explicit-value, zero-fallback, and negative-fallback cases, plus a guard test that pins `DefaultMinScanInterval = 5*time.Minute` against accidental changes.

<details><summary>Original finding (kept for history)</summary>

**Evidence:** [features/discovery/controller/controller.go:50-58](../../features/discovery/controller/controller.go:50):

```go
var MinScanInterval = time.Minute * 5
func init() {
    if v := os.Getenv("OPERATOR_MIN_SCAN_INTERVAL"); v != "" { ... }
}
```

A global package var mutated during init based on env. Works, but test isolation requires remembering to reset.

**Fix:** Pass it as a field on `Reconciler`, configured via `ReconcilerConfig`. Tests construct a reconciler with a short interval without touching globals.
</details>

---

## 🟢 24. Ghost `nolint:staticcheck` comments on recorder calls

**Evidence:** [cmd/main.go:244, 259, 274, 288](../../cmd/main.go:244) — `mgr.GetEventRecorderFor("...")` flagged with `//nolint:staticcheck`. Suggests a deprecation warning being silenced.

**Fix:** Check the upstream deprecation notice — likely `GetEventRecorderFor` is deprecated in favor of `NewRecorder` or similar. Address once rather than carrying the nolint forever.

---

## ✅ 25. cert-manager TODO — RESOLVED (clarifying comment)

> **Status**: The TODO in `cmd/main.go` was out of sync with reality: the Helm chart (`charts/vault-access-operator`) already wires cert-manager for both webhooks and metrics when `certManager.enabled=true`. Replaced the TODO with a comment pointing readers at the Helm chart as the supported install path. The `config/` kustomize bases are retained as reference for `make deploy` and kubebuilder scaffolding conventions but are not the recommended production install.

<details><summary>Original finding (kept for history)</summary>

**Evidence:** [cmd/main.go:174-177](../../cmd/main.go:174):

```go
// TODO(user): If you enable certManager, uncomment the following lines:
// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml
// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml
```

**Fix:** Either finish the wiring in kustomize bases or remove the comment. The TODO has been there since project bootstrapping — likely nobody will act on it unless surfaced.
</details>

---

## ❌ 26. `cover.out` committed — INCORRECT FINDING

> **Status**: Withdrawn after verification. `cover.out` is NOT tracked by git — the existing `.gitignore` pattern `*.out` covers it. `git ls-files cover.out` returns empty; `git status --ignored` confirms cover.out is listed under "Ignored files". The original doc audit was wrong about this one.

<details><summary>Original finding (incorrect) (kept for history)</summary>

**Evidence:** [cover.out](../../cover.out) present in repo root.

**Fix:** Add to `.gitignore` and remove from tracking.
</details>

---

## Missing Features (not disconnects, but absent)

### A. No per-namespace operator mode
Current operator watches all namespaces. Large multi-tenant clusters may want `--namespace=X` filtering. `controller-runtime` supports this via `Cache.Options{DefaultNamespaces: ...}` but no flag is exposed.

### B. No PolicyBinding reverse-index
`VaultRole.Status.PolicyBindings` tracks role→policy. Nothing tracks policy→role. Useful for debugging "who uses this policy?" via `kubectl describe vaultpolicy X`.

### C. No sealed / init auto-recovery hook
When Vault is sealed, the operator marks `Phase=Error` and backs off. After unseal, it recovers on the next reconcile (30s). No event-driven notification (Vault has a sealed-state API but the operator doesn't subscribe).

### D. No multi-cluster support
One operator = one cluster's worth of CRs. Multi-cluster setups need multiple operator deployments, each with its own set of CRs. No leader-across-clusters story.

### E. No policy templating
Beyond `{{namespace}}` and `{{name}}` in paths, there's no way to template capabilities or rule structures. Larger orgs often want `templates/` with references. Out of scope or future work?

### F. No VaultConnection status.ready condition hook for dependent CRs
Policy/role rely on `VaultConnection.Status.Phase == Active` to proceed. A more k8s-idiomatic pattern would be a `Ready` condition, with `conditionalReady` predicate for dependent CRs. The `ConnectionPhaseChangedPredicate` half-does this.

### G. No backup/restore story for managed-markers
If the `secret/data/vault-access-operator/managed/` KV tree is accidentally deleted, all policies/roles look unmanaged and become conflict-blocked. No "rebuild from CRs" command.

### H. No `reconcile-now` trigger
Users wanting immediate re-sync must edit the spec (to bump generation) or delete a condition. No annotation-based force trigger.

### I. No dry-run / plan mode
Especially useful for drift correction: "show me what would change if I set `driftMode: correct`". Discovery auto-create would also benefit from dry-run.

### J. No standardized PolicyBinding resolution event
When a referenced policy becomes available after previously missing, no `PolicyResolved` event. Operators inspecting events see the "not found" but not the resolution.

### K. Metrics: no latency histograms
All metrics are gauges or counters. No `reconcile_duration_seconds` histogram. Hard to alert on slow Vault or slow syncs.

---

---

## ✅ 27. Event bus subscribers — RESOLVED via k8s watch (not the event bus)

> **Status**: Fixed the user-visible problem. The role reconciler now watches VaultPolicy + VaultClusterPolicy create/update events via a controller-runtime `Watches(...)` + MapFunc that filters to roles with unresolved PolicyBindings referencing the triggering policy. Roles blocked on a not-yet-applied policy now reconcile in milliseconds of the policy appearing instead of waiting up to 30s for the next scheduled sync.
>
> **Why k8s watch instead of the internal event bus**: the k8s API server already fires Create events for every CR, and controller-runtime dispatches them directly. Re-publishing through the internal event bus would be an extra layer with no benefit — same semantics, more code. The internal bus remains as scaffold for future cross-feature signals (e.g., external SIEM audit export, cross-cluster coordination) that don't have a natural k8s representation.
>
> **Tests**: `shared/controller/watches/policy_watch_test.go`:
> - `TestRoleRequestsForPolicy` — enqueues only waiting roles, not resolved or unrelated ones.
> - `TestClusterRoleRequestsForPolicy` — mirror for cluster-scoped roles.
> - `TestPolicyCreatedOrUpdatedPredicate` — confirms Delete events don't enqueue (handled by next scheduled reconcile, which re-runs `PolicyExists`).

<details><summary>Original finding (kept for history)</summary>


**Evidence:** Grep confirms `events.Subscribe` is only called from `*_test.go` files across the entire codebase. Production publishers fire into the void.

Publishers (live): `ConnectionReady`, `ConnectionDisconnected`, `BootstrapCompleted`, `PolicyCreated`, `PolicyDeleted`, `RoleCreated`, `RoleDeleted` — 7 types emitted.
Types declared but never published: `ConnectionHealthChanged`, `PolicyUpdated`, `RoleUpdated`, `TokenRenewed`, `TokenRenewalFailed`, `TokenReviewerRefreshed` — 6 types ghost scaffolding.

**Impact:** The intended cross-feature reactivity never happens. Policy/role sync on connection recovery is handled by `ConnectionPhaseChangedPredicate` + enqueue map-funcs instead. That works but means the bus is deadweight.

**Fix options:**
1. **Delete the bus + ghost event types.** Replace `PublishAsync` with direct recorder events. Simplest, but loses future extensibility.
2. **Wire one subscriber as proof-of-life.** For example, when `PolicyCreated` fires, re-enqueue any `VaultRole` whose `status.policyBindings[].resolved=false` references that policy name — faster recovery than the current 30s requeue. Adds a visible benefit.
3. **Ship the bus as-is**, document as scaffold, note in this file that dead publish calls are intentional.

Recommendation: option 2. Gives the bus at least one subscriber and delivers a user-visible improvement.
</details>

---

## 🟡 28. `AnnotationDiscovered` value doc/code drift (self-reported)

**Evidence:** `PROJECT_OVERVIEW.md` (before this update) annotations table showed `vault.platform.io/discovered=<RFC3339>`; actual constant at [common_types.go:447](../../api/v1alpha1/common_types.go:447) is `AnnotationDiscovered = "vault.platform.io/discovered-at"`. Fixed inline while generating the contributor docs.

**Impact:** A reader copying from the table would look for the wrong annotation name.

**Fix:** Add a doc linter to CI — grep `docs/internal/` for literal `vault.platform.io/...` and diff against the constants block. Catches future drift automatically.

---

## ✅ 29. Classify NotFoundError + ConnectionError distinctly — RESOLVED

> **Status**: Fixed. `syncerror.Handle` now recognizes `NotFoundError` (referenced K8s resource absent) and `ConnectionError` (transport-layer Vault failures) as distinct classes. Each maps to a new condition reason:
> - `NotFoundError` → `ReasonResourceNotFound` (distinct from `ReasonPolicyNotFound` which is specific to Vault policy refs).
> - `ConnectionError` → `ReasonNetworkError`.
>
> Dashboards and alerts can now distinguish "Vault unreachable" from "a required Secret is missing" without parsing status `Message` strings.
>
> **Tests**: `TestHandle_NotFoundError` and `TestHandle_ConnectionError` updated to assert the new reasons (they previously pinned the old `ReasonFailed` catch-all).

<details><summary>Original finding (kept for history)</summary>

**Evidence:** [shared/infrastructure/errors/errors.go](../../shared/infrastructure/errors/errors.go) defines 6 error types. [shared/controller/syncerror/handler.go](../../shared/controller/syncerror/handler.go) `Handle` classifies only 4 (`ConflictError`, `ValidationError`, `DependencyError`, `TransientError`) → maps every unmatched error to generic `PhaseError / ReasonFailed`.

**Impact:**
- `NotFoundError` scenarios (e.g., referenced Secret missing) are classified the same as a Vault 500. Users have to read the message to distinguish.
- `ConnectionError` (network/TLS issues at the transport layer) would be nice to surface as a distinct condition — today it mashes together with generic `TransientError`.

**Fix:** Extend the `syncerror.Handle` switch to recognize these two types and map to distinct reasons (e.g., `ReasonNotFound`, `ReasonNetworkError`).
</details>

---

## 🟡 30. Raw-string annotations lack constants (generalizes §14)

**Evidence:**
- `vault.platform.io/discovery-pending` at [policy/controller/ops.go:108](../../features/policy/controller/ops.go:108) and [discovery/controller/controller.go:216](../../features/discovery/controller/controller.go:216) — raw strings on both sides.
- `vault.platform.io/discovered-from` at [discovery/controller/controller.go:217](../../features/discovery/controller/controller.go:217) — raw string.

Neither has a constant in [common_types.go](../../api/v1alpha1/common_types.go).

**Impact:** Renaming an annotation requires grepping every call site. Typos aren't caught at compile time.

**Fix:** Add to `common_types.go`:
```go
AnnotationDiscoveryPending = "vault.platform.io/discovery-pending"
AnnotationDiscoveredFrom   = "vault.platform.io/discovered-from"
```
Replace raw strings with constants.

---

## ✅ 31. Dead metrics — registered but never emitted — RESOLVED

> **Status**: Fixed. Wired emission for all three previously-dead metrics:
> - `policy_reconcile_total{kind, namespace, result}` — emitted from both `PolicyReconciler.Reconcile` and `ClusterPolicyReconciler.Reconcile` after the BaseReconciler call.
> - `role_reconcile_total{kind, namespace, result}` — same pattern in role + clusterrole reconcilers.
> - `discovery_adoptions_total{kind, namespace, result}` — emitted at both adopt paths in `policy.Handler.checkConflict` and `role.Handler.checkConflict` (success-only; conflict-blocked is not an adoption attempt).
>
> **Tests**: `features/{policy,role}/controller/reconciler_metrics_test.go` cover both reconcile metric emission (NotFound success path) and the helper `kindForMetric`/`roleKindForMetric` mapping that distinguishes namespaced from cluster-scoped variants.

<details><summary>Original finding (kept for history)</summary>


**Evidence:**
- `PolicyReconcileTotal` at [metrics.go:67](../../pkg/metrics/metrics.go:67), helper `IncrementPolicyReconcile` at [metrics.go:232](../../pkg/metrics/metrics.go:232) — **never called** outside test code (verified by grep).
- `RoleReconcileTotal` at [metrics.go:78](../../pkg/metrics/metrics.go:78), helper `IncrementRoleReconcile` at [metrics.go:241](../../pkg/metrics/metrics.go:241) — same.
- `AdoptionTotal` at [metrics.go:155](../../pkg/metrics/metrics.go:155), helper `IncrementAdoption` at [metrics.go:288](../../pkg/metrics/metrics.go:288) — same.

3 of 14 metrics are registered series that always read as zero (no value ever observed). Another 3 (`OrphanedResourcesGauge`, `CleanupQueueSizeGauge`, `CleanupRetriesTotal`) are emitted only from the unwired cleanup/orphan controllers (§1) — so zero in practice.

**Impact:**
- Prometheus series exist but are always empty → dashboards built against them show flat lines.
- Someone reading `/metrics` sees metric names and assumes instrumentation is present.
- Alerts based on these metrics never fire.

**Fix:** For each dead metric, either:
- (a) Add the emission call at the natural site (`IncrementPolicyReconcile` in `BaseReconciler.handleSync` post-call; `IncrementAdoption` in `CheckConflict` when `shouldAdopt` path is taken), OR
- (b) Remove the metric + helper to stop claiming instrumentation that doesn't exist.
</details>

---

## ✅ 32. Undocumented shutdown drain timeout — RESOLVED

> **Status**: Fixed. `cmd/main.go` now sets `Options.GracefulShutdownTimeout: ptr.To(2 * time.Minute)` explicitly. The default was 30s — too short for slow Vault bootstrap or auth flows on first reconcile. Helm chart's `terminationGracePeriodSeconds` should be ≥ 150s (already implicit; 30s default leaves no headroom).

<details><summary>Original finding (kept for history)</summary>


**Evidence:** [cmd/main.go:197-215](../../cmd/main.go:197) constructs `ctrl.Manager` without setting `Options.GracefulShutdownTimeout`. Controller-runtime's default is 30 seconds.

**Impact:** On SIGTERM:
- In-flight `Reconcile` calls are given the reconcile-scoped context (not the shutdown ctx) — they run to completion unless they check for cancellation themselves.
- If a long-running operation (e.g., bootstrap under a slow STS endpoint, or a TokenRequest API call against an overloaded kube-apiserver) takes >30s, the manager returns before it finishes. In-flight work aborts mid-write.
- K8s' default `terminationGracePeriodSeconds=30` means SIGKILL shortly follows — another 30s after that.

**Fix:**
```go
mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
    ...
    GracefulShutdownTimeout: ptr.To(2 * time.Minute),
})
```
Plus: document intended drain duration in the Helm chart `terminationGracePeriodSeconds` (default is K8s' 30s, likely too short for in-flight Vault ops).
</details>

---

## ✅ 33. Health probes are trivial pings — RESOLVED

> **Status**: Fixed. `/healthz` keeps the trivial `Ping` (correct for liveness). `/readyz` now also has an `informers-synced` check that calls `mgr.GetCache().WaitForCacheSync(ctx)` with a 2s timeout. Pods with un-synced caches no longer ready-pass and won't receive Service traffic prematurely.

<details><summary>Original finding (kept for history)</summary>


**Evidence:** [cmd/main.go:333-340](../../cmd/main.go:333):
```go
mgr.AddHealthzCheck("healthz", healthz.Ping)
mgr.AddReadyzCheck("readyz", healthz.Ping)
```
`healthz.Ping` always returns `nil`. It tells you the HTTP server is up. That's it.

**Impact:** A pod with:
- stuck informer caches (e.g., kube-apiserver connectivity issue),
- a populated but stale `ClientCache` (every Vault call failing 403),
- a leader-elected lease but no reconcile progress,

will still answer `200 OK` to `/readyz`. Service traffic keeps routing to it.

**Fix:** Add informed checks:
```go
mgr.AddReadyzCheck("informers-synced", func(_ *http.Request) error {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    if !mgr.GetCache().WaitForCacheSync(ctx) {
        return errors.New("cache not synced")
    }
    return nil
})

// Optional: connection-cache has at least one entry after 2 minutes
// (skip if no VaultConnections exist, but flag if cache is empty while connections exist)
```
Keep `/healthz` as the trivial ping (liveness = pod-level restart trigger).
</details>

---

## ✅ 34. RBAC aggregates unwired-controller permissions — RESOLVED as side-effect of §1

> **Status**: No code change needed. The original concern was that the aggregated ClusterRole granted permissions (ConfigMap writes for the cleanup queue, etc.) that only the unwired cleanup and orphan controllers would consume — creating a "misleading RBAC surface" during audits. §1 wired both controllers, so the permissions are no longer hypothetical. Least-privilege auditors can now see every granted permission mapped to a live controller.
>
> The `rbac.cleanupEnabled` Helm toggle proposal is intentionally not added — gating RBAC behind a value flag would require users to coordinate two Helm settings (install the operator AND toggle the RBAC) for a feature that's on by default. Simpler to have always-on RBAC for controllers that always run.

<details><summary>Original finding (kept for history)</summary>


**Evidence:** [config/rbac/role.yaml](../../config/rbac/role.yaml) grants verbs that only the cleanup/orphan controllers would need (e.g., Secret writes for the cleanup ConfigMap) — controllers that aren't wired (§1).

**Impact:** Least-privilege audits flag permissions that look excessive for the running feature set. Users operating under strict RBAC policies may want to trim the unused grants, but doing so would break the moment §1 is fixed.

**Fix:** Split RBAC into optional Helm values: `rbac.cleanupEnabled=true` gates the Secret-write permissions. Keep them off by default until §1 is wired.
</details>

---

## ❌ 35. `ConnectionPhaseChangedPredicate` fan-out on health-check changes — INCORRECT FINDING

> **Status**: Withdrawn after code re-verification. The predicate at [shared/controller/watches/predicates.go:45-64](../../shared/controller/watches/predicates.go:45) only triggers on `Status.Phase` OR `Status.Healthy` *transitions* — not on heartbeat timestamp changes. The existing test `TestConnectionPhaseChangedPredicate_Update_NoChange` even explicitly covers a "version updated, no phase change" scenario and asserts the predicate returns `false`. The fan-out storm I claimed in the original doc pass does not occur. Leaving the entry here (struck through) so cross-references stay stable.

<details><summary>Original (incorrect) finding (kept for history)</summary>


**Evidence:** [shared/controller/watches/predicates.go](../../shared/controller/watches/predicates.go) triggers on phase **or** health-check-timestamp change. The connection reconciler writes health status every 30s.

**Impact:** If a connection is unhealthy:
- Every 30s, the connection controller updates `Status.LastHealthCheck` → the predicate returns `true` → all dependent policy/role reconcilers are enqueued → each re-runs its full `Sync` (which will hit `DependencyError` and exit, but still burns K8s API calls and log noise).
- For a cluster with 200 dependent policies + 100 roles referencing an unhealthy connection, that's 300 wasted reconciles every 30s = 10/sec sustained.

**Fix:** Tighten the predicate to trigger only on `Phase` transition (ignore `LastHealthCheck`, `LastHeartbeat`, consecutiveFails updates). The current `ConnectionPhaseChangedPredicate` name suggests that's the intent, so this is likely a bug.
</details>

---

## ✅ 36. No `connectionRef` existence webhook check — RESOLVED

> **Status**: Fixed. Added `checkConnectionRefExists` helper in `internal/webhook/connectionref_check.go`. Wired into all four policy/role validators (`ValidateCreate` for policy + cluster policy, `validateWithContext` for role + cluster role). Emits a **warning**, not an error — users applying a batch that includes both the connection and the dependent resource shouldn't be blocked by apply ordering.
>
> **Tests**: `connectionref_check_test.go` covers the 4 code paths (nil client, empty ref, existing, missing). `TestVaultPolicyValidator_WarnsOnMissingConnection` is the policy-side end-to-end assertion.

<details><summary>Original finding (kept for history)</summary>


**Evidence:** Webhooks validate policy/role spec shape and inter-CR naming collisions, but don't verify the referenced `VaultConnection` actually exists.

**Impact:** Users can `kubectl apply` a `VaultPolicy` referencing a nonexistent `VaultConnection`. It will be accepted, then fail at the next reconcile with `DependencyError → ConnectionNotReady`. The user sees the error in status, not at apply time.

**Fix:** Add a dependency check similar to `checkPolicyDependencies` ([vaultrole_webhook.go:173](../../internal/webhook/vaultrole_webhook.go:173)) but emitting a **warning** (not an error — the connection might be applied in the same kubectl command with ordering issues).
</details>

---

## Priority Ranking (if you can only fix 7)

| Rank | Fix | Why first |
|------|-----|-----------|
| 1 | §1 + §3 — wire cleanup, orphan, lifecycle, reviewer controllers | silent data loss + long-running break; the controllers exist, just aren't registered |
| 2 | §2 — stop removing finalizer on cleanup failure | closely coupled to §1; together they fix resource leakage |
| 3 | §4 — VaultRole `discovery-pending` annotation parity | silent auth-loss footgun for discovery users |
| 4 | §8 — VaultConnection admission webhook | shifts many "what happened to my connection?" tickets from reconcile-time to apply-time |
| 5 | §5 — cap `DiscoveredResources` **in controller** (not just schema) | one large Vault triggers unrecoverable `Phase=Error` until user trims patterns |
| 6 | §35 — `ConnectionPhaseChangedPredicate` health-check fan-out | reconcile storm for unhealthy connections; trivial predicate tightening |
| 7 | §31 + §33 — remove dead metrics and fix trivial health probes | cheap-and-visible improvements to operational surface |

---

## Cross-references back into the flow docs

- [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)
- [ARCHITECTURE.md](ARCHITECTURE.md) — same unwired-controllers note in "Shared infrastructure" callout
- [FLOW_OVERVIEW.md](FLOW_OVERVIEW.md) — pre-flight note
- [FLOW_LIFECYCLE.md](FLOW_LIFECYCLE.md) — shutdown timeout §32, health probes §33, RBAC §34
- [FLOW_CONNECTION.md](FLOW_CONNECTION.md) — dual reconciler, auth dispatch chain, listDependents, fan-out §35
- [FLOW_POLICY.md](FLOW_POLICY.md) — HCL normalization, discovery-pending, duplicate shouldAdopt
- [FLOW_ROLE.md](FLOW_ROLE.md) — backend coverage, resolvePolicyNames duplication, JWT subject derivation
- [FLOW_DISCOVERY.md](FLOW_DISCOVERY.md) — §5 (updated), role annotation gap
- [FLOW_DELETION.md](FLOW_DELETION.md) — silent cleanup failures
- [FLOW_AUTH.md](FLOW_AUTH.md) — unwired lifecycle/rotator, auth dispatch refactor, backend coverage gap
- [FLOW_WEBHOOK.md](FLOW_WEBHOOK.md) — missing connection webhook §8, connectionRef-existence §36
- [FLOW_EVENTS.md](FLOW_EVENTS.md) — §27 no subscribers, dead event types
- [FLOW_METRICS.md](FLOW_METRICS.md) — §31 dead metrics, §K no latency histograms
- [INSTRUCTIONS.md](INSTRUCTIONS.md) — contributor procedures touching most of these subsystems
