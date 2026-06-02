# Improvements, Disconnects, Divergences & Gaps

> This is the actionable output of the documentation pass. Each finding is grouped by **Severity** (Critical / Major / Minor / Cosmetic), with evidence, impact, and a recommended fix. Item numbers are stable — the other FLOW docs link back here by `§<n>`.

## Resolution Status (last updated 2026-05-28)

All findings up to §36 have been worked through. §§37–42 added 2026-05-28 from the [AUDIT-2026-05](AUDIT-2026-05.md) pass. A follow-up pass (also 2026-05-28) resolved §§37, 38, 41, completed §10's partial-failure recording, and wired the §1 reviewer rotator (lifecycle controller deferred — see §1). Tally:

| Status | Count | Items |
|--------|-------|-------|
| ✅ Resolved | 37 | §§1–6, 8–11, 13–17, 19–25, 27, 29–34, 36, 37, 38, 41 |
| ✅ Resolved (missing features) | 9 | A, B, C, F, G, H, I, J, K |
| 🟠 Partially resolved | 2 | §1 (reviewer wired; lifecycle deferred), §7 (validation + doc shipped; backend expansion deferred) |
| ❌ Withdrawn | 4 | §12 (design sound), §18 (low ROI), §26 (already gitignored), §35 (predicate already correct) |
| 🕰️ Deferred with rationale | 2 | D (multi-cluster, OOS), E (policy templating, Helm-level concern) |
| 🆕 New (open) | 2 | §§39–40 (workflow integration tests, cluster/role update e2e) |

Each section below lists its current status inline. Items marked `✅ RESOLVED` keep the original finding in a collapsed `<details>` block for historical context and to make future drift easy to spot.

Tests added across this effort: ~170 new unit tests, ~8 new integration tests, plus 2 new e2e tests. Zero regressions in existing suites.

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
> **Reviewer rotator — RESOLVED (2026-05-28)**: [reviewer_controller.go](../../pkg/vault/token/reviewer_controller.go) now implements `NeedsLeaderElection()`, is constructed by the connection feature and registered with the manager in [cmd/main.go](../../cmd/main.go) via `connFeature.ReviewerController`, and is driven per-connection by the handler (`registerTokenReviewer`: `Register` + `SetVaultClient` + an initial priming `Refresh`, guarded so the every-30s reconcile doesn't reset the refresh schedule — `Register` replaces per-connection state). Opt out via `spec.auth.kubernetes.tokenReviewerRotation: false`. A thin `eventBusPublisher` adapter bridges the bus's typed `Publish(Event)` to the token package's `Publish(interface{})`.
>
> **e2e-found fix**: verifying through `make e2e-local-test-auth` surfaced that `vault.Client.UpdateKubernetesAuthConfig` wrote *only* `token_reviewer_jwt`, and Vault's `auth/<mount>/config` endpoint rejects that with `400 no host provided` (it is **not** a merge-update, contrary to the old comment). Fixed to read the current config and re-write it preserving `kubernetes_host`/`kubernetes_ca_cert`/issuer settings. This bug was latent because the method was only ever called by the (previously unwired) reviewer; the mock-based unit tests couldn't catch it. The e2e operator logs now show `refreshed token_reviewer_jwt` succeeding for every connection (regression-guarded by the rewritten `TestUpdateKubernetesAuthConfig`).
>
> **Token lifecycle controller — still deferred**: wiring it for multi-connection requires a signature change to the `token.VaultAuthenticator` interface — its `AuthenticateKubernetes`/`RenewSelf` methods omit the connection identity, so a single shared instance can't address the right per-connection cached client. Deferred because the reconcile loop already renews each connection's token reactively every 30s (`getOrRenewClient`), so the marginal value (proactive vs reactive renewal) is low relative to the interface churn + the double-renewal race it introduces. `NeedsLeaderElection()` + a testable `checkInterval` option were added to [lifecycle_controller.go](../../pkg/vault/token/lifecycle_controller.go) as prep. Tracked as a follow-up.
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

## 🟠 7. Role backend coverage gap — PARTIALLY RESOLVED (validation + doc; backend impl deferred)

> **Status**: Items 1 and 2 of the original fix plan are done. Item 3 (actual backend support for AWS/GCP/OIDC/AppRole) is genuine feature work and remains deferred as Tier 5.
>
> **Item 1 — user-facing doc**: [docs/api-reference.md](../api-reference.md) under the `VaultRole` section now has a prominent admonition listing the supported (`auth/kubernetes/*`, `auth/jwt/*`) and unsupported (AWS/GCP/AppRole/OIDC/LDAP) backends, with a link back to this finding for the roadmap.
>
> **Item 2 — admission webhook rejection**: [internal/webhook/vaultrole_webhook.go](../../internal/webhook/vaultrole_webhook.go) gained `validateAuthPathSupported(authPath)` which rejects unsupported backends at admission time for both `VaultRole` and `VaultClusterRole`. Users get immediate `kubectl apply` feedback ("spec.authPath X targets an unsupported Vault auth backend...") instead of a silent accept → status-level ValidationError after the next reconcile.
>
> Accepts both forms that appear in user-facing docs and fixtures:
>   - Full: `auth/kubernetes`, `auth/jwt`, `auth/kubernetes-prod`, `auth/jwt/gitlab`
>   - Bare: `kubernetes`, `jwt` (shorthand seen in many examples)
>
> Rejects: `auth/aws`, `auth/gcp`, `auth/approle`, `auth/ldap`, bare `aws`/`gcp`/etc.
>
> **Tests**: `TestValidateAuthPathSupported` covers 14 cases across supported/unsupported forms + a dedicated check that the error message cites IMPROVEMENTS §7.
>
> **Not done — Item 3 (backend expansion)**: implementing AWS/GCP/OIDC/AppRole `buildRoleData` branches requires CRD additions (e.g., `spec.aws.boundIamPrincipalArns`, `spec.gcp.boundServiceAccounts`) and per-backend drift comparison. Sized as one Tier-5 PR per backend once product prioritization signals which is highest-value. JWT is already done.

<details><summary>Original finding (kept for history)</summary>

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
</details>

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
> **Partial-failure recording — RESOLVED (2026-05-28)**: `bootstrap.Manager.Bootstrap` now returns the partially-populated `*Result` (instead of `nil`) on every fatal early-exit, and the connection handler records `BootstrapSteps` from it before surfacing the error (shared `bootstrapSteps` helper used by both the success and failure paths). A new `Result.AuthConfigured` flag distinguishes "mount enabled" from "mount enabled AND configured" so the recorded steps are accurate when bootstrap fails at the configure step. Tests: `manager_impl_test.go` (`TestBootstrap_PartialFailure_{ConfigStep,RoleStep}_ReturnsProgress`) + `handler_bootstrap_test.go::TestRunBootstrap_PartialFailure_RecordsSteps`.

<details><summary>Original finding (kept for history)</summary>


**Evidence:** [features/connection/controller/handler.go:294-313](../../features/connection/controller/handler.go:294) — after `BootstrapComplete=true` is persisted, handler returns immediately so the next reconcile does auth with a fresh object. Good fix for the original issue.

**But:** If `runBootstrap` succeeds partially (auth mount created but policy write failed, or role created but revoke failed), the `BootstrapComplete=true` may be set incorrectly or not at all. There's no finer-grained recording like `AuthMountCreated`, `OperatorRoleCreated`, `BootstrapRevoked` (these exist in `Result` but aren't individually persisted).

**Impact:** Re-running bootstrap after a partial failure could error on "mount already exists" unless the bootstrap manager is idempotent on every step (it is for mount creation, but worth auditing).

**Fix:**
1. Add fine-grained status fields or an `AuthStatus.BootstrapSteps` map.
2. Add e2e test: kill the operator after `AuthMountCreated=true` but before `RoleCreated`. Verify next reconcile resumes correctly.
</details>

---

## ✅ 11. Drift comparator duplication (policy HCL vs role map) — RESOLVED

> **Status**: Fixed. `drift.Comparator` gained `CompareMultilineText(fieldName, expected, actual)` which stores a per-field line-level preview in `Result.Summary`. Policy `DetectDrift` delegates to the comparator instead of returning the generic `"policy content differs"` message, so the `PolicyDrifted` condition now surfaces what changed with `- ` (Vault side) and `+ ` (expected side) markers.
>
> Preview is capped at `multilineDiffMaxLines` (6) and overflow is summarized as `... (N more)` so a wildly divergent blob doesn't flood the condition field.
>
> **Tests**:
> - `shared/controller/drift/compare_test.go` — 5 new tests: identical, single-line change, max-lines cap, combined with scalar fields, Reset() clears details.
> - `features/policy/controller/ops_test.go` — 2 new integration tests that hit the harness's httptest Vault: `TestPolicyOps_DetectDrift_ProducesDiffPreview` asserts the summary has both markers; `TestPolicyOps_DetectDrift_NoDriftOnMatch` keeps the happy path pinned.
>
> **Not in scope for §11**: full LCS-based diff (the current implementation is set-difference on unique lines — sufficient for deterministic operator-generated HCL, but won't produce ideal output for reordered lines). Deferred to a future iteration if real-world drift messages show that limitation.

<details><summary>Original finding (kept for history)</summary>

**Evidence:**
- Policy: string normalize + compare in [policy/controller/handler.go:235-245](../../features/policy/controller/handler.go:235) and [ops.go:88-101](../../features/policy/controller/ops.go:88).
- Role: `drift.Comparator` framework in [shared/controller/drift/compare.go](../../shared/controller/drift/compare.go) used by [role/controller/handler.go:169-235](../../features/role/controller/handler.go:169).

**Impact:** Two different drift philosophies. Policy drift is either "yes" or "no" with no detail — users see `"policy content differs"` and must diff manually. Role drift lists exactly which fields changed.

**Fix:** Extend `drift.Comparator` with `CompareMultilineText("rules", expectedHCL, actualHCL)` that produces a unified diff summary, then use it from policy's `DetectDrift`. This unifies behavior AND improves user-facing drift messages for policies.
</details>

---

## ❌ 12. Event bus typing uses closures instead of generics — WITHDRAWN (current design is sound)

> **Status**: Re-examined. The original finding's "silently swallow" concern does not match the actual code behavior.
>
> The event bus dispatches by `event.Type()` (a string returned by each event type), and `Subscribe[T]` captures the type assertion at subscribe time inside a closure wrapper. A publish of event type X retrieves handlers registered for X's `Type()` string — handlers subscribed to a different type are never invoked, regardless of generics vs closures. This is correct behavior, not a bug.
>
> The closure-captured type assertion `event.(T)` in `Subscribe[T]` is always safe because the handler is only invoked for events whose `.Type()` matches T's `.Type()` — a collision would be a programmer error (two distinct event types returning the same string) that generics couldn't prevent either.
>
> **What generics would actually buy**: compile-time guarantee that `Publish[T](event T)` is called with the right type. But our API already separates subscribe-by-type from publish-by-event-instance, and the current `event.Type()` key lookup achieves the same dispatch correctness at runtime cost measurable in nanoseconds. A rewrite would add abstraction without fixing a real bug.
>
> **Not done** (and rationale): the generic-registry refactor is deferred indefinitely. If a future change surfaces an actual dispatch correctness issue, reopen this finding with the specific scenario.

<details><summary>Original finding (kept for history)</summary>

**Evidence:** [shared/events/bus.go](../../shared/events/bus.go) — `Subscribe[T]` captures type assertion in a closure, stores `func(ctx, Event) error`, performs runtime type assertion on publish. This was idiomatic before Go 1.18.

**Impact:** Runtime overhead (negligible). Type assertion can silently swallow events that don't match (a publish of event type X to a handler subscribed for Y just doesn't fire).

**Fix:** With Go 1.22, rewrite as a generic registry:
```go
type handlerRegistry[T Event] struct {
    handlers []func(context.Context, T) error
}
```
Catches mismatches at compile time.
</details>

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

## ✅ 14. `VaultPolicy` HCL skip uses raw annotation string — RESOLVED (via §4)

> **Status**: Fixed as a side-effect of §4. The `AnnotationDiscoveryPending` constant was added to [api/v1alpha1/common_types.go](../../api/v1alpha1/common_types.go:470) in the same commit that introduced the discovery-pending guard, and the ops.go skip-check now references the constant (see [features/policy/controller/ops.go:116](../../features/policy/controller/ops.go:116)).
>
> Also fixes the same pattern in `features/role/controller/ops.go` (the skip guard there was added at the same time and uses the constant).

<details><summary>Original finding (kept for history)</summary>

**Evidence:** [features/policy/controller/ops.go:108](../../features/policy/controller/ops.go:108):

```go
if annotations["vault.platform.io/discovery-pending"] == "true" {
```

Other annotation keys use constants from `api/v1alpha1` (e.g., `AnnotationAdopt`, `AnnotationDiscovered`). Only this one is a raw string.

**Fix:** Add `AnnotationDiscoveryPending = "vault.platform.io/discovery-pending"` to [common_types.go](../../api/v1alpha1/common_types.go) and reference it here + in the discovery auto-create (§4).
</details>

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

## ✅ 16. Connection handler doesn't use the shared workflow — RESOLVED (as documentation)

> **Status**: Clarifying comment added to `connection.Handler.Sync` at [features/connection/controller/handler.go:104](../../features/connection/controller/handler.go:104). The comment names IMPROVEMENTS §16 explicitly so future maintainers who wonder "why doesn't this use SyncWorkflow like Policy/Role?" find the rationale without opening this file.
>
> **Recommendation stands**: leave the duplication as-is. The workflow's shape (`validate → conflict → prepare content → write → readback`) doesn't match connection's flow (`authenticate → health check → update auth status`). Unifying would require heavy per-step parameterization and still leave callers stepping around the connection-specific bootstrap state machine. The comment documents this judgment call.
>
> **Not in scope**: the recommendation also mentioned extracting `handleSyncError` with auth-error detection + cache evict. That's a genuine code-sharing opportunity but independent of the "should this use SyncWorkflow" question. Deferred as its own follow-up — would be sized as "extract one helper, test existing callers remain unchanged" without crossing the workflow boundary.

<details><summary>Original finding (kept for history)</summary>

**Evidence:** [FLOW_CONNECTION.md §Divergence](FLOW_CONNECTION.md#divergence-from-other-flows)

**Impact:** Policy/role share `SyncWorkflow.Execute`; connection has its own Sync method with different error handling, different status update pattern, different event emission. Maintainers have to keep two codepaths reasoning in their head.

**Trade-off:** The workflow's shape ("validate → conflict → prepare content → write → readback") doesn't fit connection's actual flow ("authenticate → health check → update auth status"). Forcing it into the workflow would need heavy parameterization.

**Recommendation:** **Leave as-is**, but extract a smaller shared helper for:
- `handleSyncError` with auth-error detection + cache evict (currently connection-specific)
- Standardized status-update patterns

Mark this as intentional in a comment, so future maintainers don't feel pressure to unify.
</details>

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

## ✅ 19. JWT `bound_subject` derivation is brittle — RESOLVED (multi-value claim binding now first-class)

> **Status (update 2026-06-02)**: The `map[string][]string` widening that was "tracked separately" is now done — `spec.jwt.boundClaimsList` (multi-value) and `spec.jwt.boundClaimsType` (`string` | `glob`) shipped as additive fields, with `boundClaims` (`map[string]string`) kept for backwards compatibility and merged into `boundClaimsList` at apply time. New runbook [`docs/auth-methods/jwt-gitlab.md`](../auth-methods/jwt-gitlab.md) walks through GitLab CI workload identity end-to-end (works for any OIDC issuer that emits ref/branch/project-style claims). Webhook gained non-blocking warnings for the GitLab-CI footguns: `ref` bound without `ref_type` (tag-spoof), `ref` bound without `ref_protected` (unprotected-branch namesake), and duplicate keys in `boundClaims`/`boundClaimsList`. Drift comparator emits and compares `bound_claims_type` (Vault treats it as sticky — once `glob`, it stays `glob` until the role write explicitly sets it back).
>
> **Original status**: Docs updated. `docs/examples.md` under "JWT-Backed Role" now includes three multi-SA patterns (one-role-per-SA, shared-boundSubject, boundClaims on stable claim) plus an explicit "known limitation" note that our CRD's `BoundClaims map[string]string` can't emit list-valued bound_claims the way Vault natively accepts them.
>
> **E2E coverage (2026-06-02)**: `TC-AU08-01..06` shipped in `test/e2e/tc_auth_jwt_bound_claims_test.go`. The test runs the full `VaultRole` → Vault round-trip against a dedicated `auth/jwt-gitlab` mount backed by Dex OIDC discovery (`bound_issuer` pinned). It exercises list-valued bound_claims, glob matching, the `BoundClaims`+`BoundClaimsList` merge precedence, and a no-false-drift check across a full reconcile cycle. Since Dex doesn't emit GitLab-shaped claim names (`project_id`/`ref`/etc.), the test binds on Dex's standard `email` claim instead — the wire format and matching semantics the operator emits are issuer-agnostic, so the test covers the same code path GitLab claims would.

<details><summary>Original finding (kept for history)</summary>

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
</details>

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

## ✅ 21. Inconsistent logger-name scoping — RESOLVED (audit confirmed consistent)

> **Status**: Audit completed. Logger-name scoping is already consistent across the codebase. The hierarchy is: top-level `setup` → per-feature (`setup.connection`, `setup.policy`, `setup.role`, `setup.discovery`) → per-component (`setup.connection.handler`, `setup.connection.reconciler`, `setup.role.vaultrole`, etc.). No inconsistencies found — finding was overstated in the original pass.
>
> **What's intentionally different** (not a bug):
> - `Handler` instances are shared between the VaultRole/VaultClusterRole (and VaultPolicy/VaultClusterPolicy) reconcilers, so they don't scope further than the feature level — the reconciler-level scope sits on the `BaseReconciler`'s logger instead.
> - `workflow.SyncWorkflow` and `workflow.CleanupWorkflow` inherit the handler's logger without adding their own scope — they rely on `ctx`-carried logger for Reconcile-time metadata.

<details><summary>Original finding (kept for history)</summary>

**Evidence:**
- Connection feature: `log.WithName("connection")`
- Policy: no consistent scope — some places use `"vaultpolicy"`, some the raw passed logger
- Discovery: `"discovery-controller"`, `"scanner"` (nested)

**Fix:** Standardize on 2-level scoping: `"{feature}.{component}"` e.g., `policy.handler`, `policy.reconciler`, `connection.bootstrap`. Makes log parsing consistent.
</details>

---

## ✅ 22. Inconsistent use of `logr.FromContextOrDiscard(ctx)` vs passed-in `log logr.Logger` — RESOLVED (documented intentional divergence)

> **Status**: Resolved by documentation. `shared/controller/watches/doc.go` was added to explain the intentional divergence: feature handlers (called from `Reconcile` with `BaseReconciler`-injected logger) use `logr.FromContextOrDiscard`; `watches` MapFuncs (which run in controller-runtime's event-dispatch loop, where context may not carry a request-scoped logger) use `sigs.k8s.io/controller-runtime/pkg/log.FromContext` so the fallback is the global logger rather than silent discard.
>
> **Why keep both**: forcing uniformity would either silently drop diagnostically-useful MapFunc output (if we picked `FromContextOrDiscard`) or pull the controller-runtime log package into every handler (if we picked `log.FromContext`). The divergence is small, well-localized by package, and now explained at the point of divergence.
>
> **Audit confirmed**: within each package the pattern is already uniform — `features/*/controller/` all use `logr.FromContextOrDiscard`, `shared/controller/workflow/` same, `shared/controller/watches/` uses `log.FromContext`.

<details><summary>Original finding (kept for history)</summary>

**Evidence:** Some methods take `log` explicitly (e.g., `runBootstrap`), others fetch from context. Mixing both is confusing.

**Fix:** Pick one. Recommend `logr.FromContextOrDiscard(ctx)` because `BaseReconciler.Reconcile` already enriches the context with `reconcileID`.
</details>

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

## ✅ 24. Ghost `nolint:staticcheck` comments on recorder calls — RESOLVED (documented rationale)

> **Status**: Investigated. The nolint pragmas suppress a genuine `SA1019` warning from staticcheck: `mgr.GetEventRecorderFor` is deprecated in controller-runtime ≥v0.23 in favor of `mgr.GetEventRecorder`. However, the replacement returns `events.EventRecorder` (v1beta1 API, from `k8s.io/client-go/tools/events`), which has a different method signature from `record.EventRecorder` (v1 API, from `k8s.io/client-go/tools/record`) — `Eventf` requires additional `regarding`, `related`, `action`, `note` parameters. Every handler call site uses the v1 API, so migrating is a cross-cutting API refactor affecting ~30 call sites, not a one-line change.
>
> **Resolution in this tier**: added a block comment at [cmd/main.go:252](../../cmd/main.go:252) documenting *why* the nolints exist (not just that they do). Future maintainers can see at a glance whether the migration is worth doing.
>
> **Worth noting**: controller-runtime's own `manager.go` and its test suite use the same `//nolint:staticcheck` workaround for the same reason — this is the idiomatic way to opt into the deprecated-but-not-removed API.
>
> **Not done**: the full migration to `events.EventRecorder`. Tracked as future Tier-5 work when feature-parity with the v1beta1 events API is confirmed across all recorder call sites (structured events with `action`/`note`).

<details><summary>Original finding (kept for history)</summary>

**Evidence:** [cmd/main.go:244, 259, 274, 288](../../cmd/main.go:244) — `mgr.GetEventRecorderFor("...")` flagged with `//nolint:staticcheck`. Suggests a deprecation warning being silenced.

**Fix:** Check the upstream deprecation notice — likely `GetEventRecorderFor` is deprecated in favor of `NewRecorder` or similar. Address once rather than carrying the nolint forever.
</details>

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

### ✅ A. `--watch-namespaces` flag — RESOLVED
Fixed. `cmd/main.go` exposes `--watch-namespaces=ns1,ns2,ns3` which threads through `ctrl.Options.Cache.DefaultNamespaces`. Empty value (default) retains the all-namespaces behavior. Cluster-scoped CRDs continue to be watched regardless.

### ✅ B. PolicyBinding reverse-index — RESOLVED
Fixed. `VaultPolicy.Status.UsedByRoles` and `VaultClusterPolicy.Status.UsedByRoles` are new `[]string` fields populated by the policy reconciler after each successful sync. The list contains K8s resource refs like `VaultRole/<ns>/<name>` or `VaultClusterRole/<name>`, sorted lexicographically for deterministic output and capped at `MaxUsedByRolesInStatus=200` (CRD `MaxItems` matches).

`shared/controller/watches/role_watch.go` adds `PoliciesReferencedByRole(kindFilter)` — a MapFunc wired into both policy reconcilers via `Watches(...)`. When a role is created, deleted, or has its `spec.policies` list mutated, every referenced policy is enqueued so its `UsedByRoles` recomputes within milliseconds of the role change.

`features/policy/controller/handler.go:refreshUsedByRoles` does the post-sync write via `Status().Patch(MergeFrom)` on a freshly re-fetched object — independent of the workflow's main status update so a transient reverse-index failure doesn't fail the whole reconcile, and a no-op-when-unchanged guard avoids reconcile churn on stable membership.

Tests:
- `shared/controller/watches/role_watch_test.go` — 5 MapFunc cases (defaulting, kind filter, cluster-role no-default, dedup, unknown-object).
- `features/policy/controller/used_by_roles_test.go` — 7 handler cases including both role kinds, ignores non-referencing roles, truncation at MaxItems, namespace defaulting helper, no-op-when-unchanged.

### ✅ C. Sealed / init recovery — RESOLVED (faster requeue + typed error + event)
Fixed via three coordinated changes — no per-connection background goroutine needed (Vault doesn't push seal events anyway; the choice was always "polling cadence", not "event vs poll"):

1. **Typed error**: `infraerrors.VaultSealedError` carries `ConnectionName`, `Address`, and `Initialized`. Wrapping via `errors.As` works, so handler chains preserve the type.
2. **Connection handler detection**: `pkg/vault.SealStatus(ctx)` returns `(initialized, sealed bool, err error)` separately. The connection handler calls it before the full health check; if sealed, returns a typed `VaultSealedError`. On the unseal transition (previous Ready reason was `ReasonVaultSealed`/`ReasonVaultNotInitialized` and the new check passes), emits a `VaultUnsealed` K8s event.
3. **Faster requeue**: `base.StatusManager.Error` shortens the requeue to `RequeueOnSealed=10s` when the error is a `*VaultSealedError`. Standard error interval (30s) for everything else. Combined with the distinct condition reasons (`ReasonVaultSealed`, `ReasonVaultNotInitialized`), dashboards can distinguish "Vault unseal pending" from "auth misconfigured" and alerts can suppress on the former.

The unseal-to-resume gap drops from ~30s (worst case) to ~10s. Each reconcile during the sealed window is cheap (one `/sys/health` request + status patch).

Tests:
- `pkg/vault/client_test.go::TestSealStatus` — 4 cases (healthy, sealed, uninitialized, server error).
- `shared/infrastructure/errors/sealed_test.go` — 7 cases on typed error message + `IsVaultSealedError` (including wrapped error chain).
- `shared/controller/syncerror/handler_test.go` — `TestHandle_VaultSealedError` + `TestHandle_VaultNotInitializedError` pin distinct condition reasons.
- `shared/controller/base/status_test.go` — `TestStatusManager_Error_VaultSealedShortRequeue` + control case pin the requeue override.
- `features/connection/controller/sealed_state_test.go::TestWasSealedReason` — 7 cases on the unseal-event-trigger helper.

### D. No multi-cluster support (out of scope)
One operator = one cluster's worth of CRs. Multi-cluster setups need multiple operator deployments, each with its own set of CRs. Explicitly out of scope for the single-operator architecture.

### E. No policy templating (still missing)
Beyond `{{namespace}}` and `{{name}}` in paths, there's no way to template capabilities or rule structures. **Deferred**: likely a Helm-chart-level concern (generate the VaultPolicy CR with capabilities rendered via Helm values), not an operator concern.

### ✅ F. `Ready` condition predicate for dependent CRs — RESOLVED
Fixed. `VaultConnection.Status.Conditions[Ready]` already existed; added `shared/controller/watches/ConnectionReadyChangedPredicate` which fires strictly on Ready True↔False transitions (vs. the broader `ConnectionPhaseChangedPredicate` that also fires on intermediate phase hops). Dependent CRs can now wire the stricter predicate if they want to react only to usability changes. The existing `ConnectionPhaseChangedPredicate` remains the default for today's consumers — no behavior change without opt-in.

### ✅ G. Managed-marker restore — RESOLVED (annotation-driven)
Fixed via annotation rather than CLI tool. `vault.platform.io/restore-managed-markers=true` on a VaultConnection triggers a one-shot mass re-adoption: the connection reconciler walks every dependent CR (VaultPolicy, VaultClusterPolicy, VaultRole, VaultClusterRole) using the existing `IndexFieldConnectionRef` field indexer (§15) and re-writes the managed-marker entry in Vault's KV store for each.

Why annotation instead of CLI:
- No new binary or Dockerfile target needed.
- Operator already has the right credentials, client cache, and indexer.
- Works through the normal reconcile loop — same delivery semantics, retry, leader-election as everything else.

Annotation auto-clears after a successful pass. Partial failures (one bad write) keep the annotation set so the next reconcile retries; aggregate error message + `ManagedMarkersPartiallyRestored` k8s event surface which resources failed.

Marker writes use the policy/role names directly (no rule descriptions for VaultPolicy markers — those are nice-to-have and re-populate on the next normal reconcile of each policy). This keeps the connection handler from depending on the policy feature's `buildRuleDescriptions` helper — single-direction dependency preserved.

Tests: 4 cases in `restore_markers_test.go`:
- `WritesMarkerForEveryDependent` — full coverage of all 4 CR kinds.
- `OnlyTouchesDependentsOfThisConnection` — pin the field-indexed query.
- `NoOpWhenNoDependents` — empty case is a non-error.
- `PartialFailureContinuesAndReports` — one bad write doesn't halt the loop and the aggregated error names every failure.

### ✅ H. `reconcile-now` annotation trigger — RESOLVED
Fixed. New `vault.platform.io/reconcile-now` annotation (constant at [common_types.go:486](../../api/v1alpha1/common_types.go:486)) + `ReconcileNowAnnotationPredicate` in the watches package. Wired into Policy/ClusterPolicy/Role/ClusterRole reconcilers via `predicate.Or(GenerationChangedPredicate, ReconcileNowAnnotationPredicate)`. `BaseReconciler.Reconcile` auto-clears the annotation via `client.RawPatch(MergePatchType, ...)` after a successful sync so the predicate is one-shot; failed syncs retain the annotation so the user's intent outlives a transient error.

Tests: 5 predicate tests covering add/update/clear/unrelated-change + 2 base-reconciler integration tests pinning the patch-clear (success) and no-clear (error) behaviors.

Usage: `kubectl annotate vaultpolicy foo vault.platform.io/reconcile-now="$(date -Iseconds)" --overwrite`.

### ✅ I. Dry-run / plan mode — RESOLVED
Fixed via annotation rather than DriftMode enum value. `vault.platform.io/dry-run=true` makes the operator SKIP all Vault writes (`WriteToVault`, `MarkManaged`, `DeleteFromVault`, `RemoveManaged`) for the annotated CR. The `ConditionTypeDryRun` status condition surfaces the suppressed operation so dashboards / `kubectl describe` make it obvious the policy/role isn't actually pushed to Vault.

Persistent (does NOT auto-clear, unlike `reconcile-now`) — users remove the annotation when ready to apply. Combines with `DriftMode: correct` to preview what a correction WOULD overwrite without overwriting it.

Why annotation instead of DriftMode value:
- DriftMode is per-resource policy ("how should drift be handled forever").
- Dry-run is per-deployment-attempt ("just for this apply, show me what would happen").
- Annotation is the natural fit for the latter.

Tests: 7 PolicyOps cases (write/delete/markManaged skip + positive controls + falsy-value strict equality + helper unit), 3 RoleOps cases (write/delete skip + positive control), 2 SyncWorkflow cases (DryRun condition True/False).

### ✅ J. `PolicyResolved` event — RESOLVED
Fixed. `features/role/controller/handler.go:emitPolicyResolvedEvents` detects the per-binding Resolved=false → Resolved=true transition between reconciles and emits a K8s event with reason `PolicyResolved`, message naming the K8sRef and Vault policy path. Steady-state reconciles don't re-emit. Fresh bindings that land already-resolved DO emit (first time the user sees the dependency satisfied). Called from `RoleOps.ApplyBindings` which is the single path where PolicyBindings are updated.

Tests: `policy_resolved_event_test.go` with 5 table cases covering transition, no-change, fresh-already-resolved, nil-recorder no-op, and still-unresolved no-op.

### ✅ K. Reconcile duration histogram — RESOLVED
Fixed. New `vault_access_operator_reconcile_duration_seconds` Prometheus histogram with labels `kind` (VaultPolicy/VaultRole/VaultConnection/VaultDiscovery/...) and `result` (success|failure). Buckets tuned for typical operator reconcile latency: 0.01s–60s, with breakpoints at 0.05/0.1/0.25/0.5/1/2.5/5/10/30s. Recorded unconditionally in `BaseReconciler.Reconcile` via deferred `metrics.ObserveReconcileDuration` so every CR kind benefits without per-feature wiring.

Enables alerts like `histogram_quantile(0.99, rate(vault_access_operator_reconcile_duration_seconds_bucket[5m])) > 10` for p99 regressions.

Tests: `pkg/metrics/metrics_test.go:TestObserveReconcileDuration` + histogram registration pinned in `TestMetricsRegistered`.

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

## ✅ 28. `AnnotationDiscovered` value doc/code drift (self-reported) — RESOLVED

> **Status**: Fixed. Two lingering stale references in [FLOW_DISCOVERY.md](FLOW_DISCOVERY.md) at lines 156 and 179 used the bare `vault.platform.io/discovered` (the pre-rename value). Both are now corrected to `vault.platform.io/discovered-at` matching the actual `AnnotationDiscovered` constant at [common_types.go:459](../../api/v1alpha1/common_types.go:459).
>
> **Doc linter in CI** (the original fix recommendation): deferred. A simple grep-and-compare check would catch future drift but adds CI complexity; punted to a separate follow-up since the current review caught all the known instances.

<details><summary>Original finding (kept for history)</summary>

**Evidence:** `PROJECT_OVERVIEW.md` (before this update) annotations table showed `vault.platform.io/discovered=<RFC3339>`; actual constant at [common_types.go:447](../../api/v1alpha1/common_types.go:447) is `AnnotationDiscovered = "vault.platform.io/discovered-at"`. Fixed inline while generating the contributor docs.

**Impact:** A reader copying from the table would look for the wrong annotation name.

**Fix:** Add a doc linter to CI — grep `docs/internal/` for literal `vault.platform.io/...` and diff against the constants block. Catches future drift automatically.
</details>

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

## ✅ 30. Raw-string annotations lack constants (generalizes §14) — RESOLVED (via §4)

> **Status**: Fixed. Both annotations named in this finding (`vault.platform.io/discovery-pending` and `vault.platform.io/discovered-from`) now have typed constants in [common_types.go](../../api/v1alpha1/common_types.go:463):
>
> ```go
> AnnotationDiscoveryPending = "vault.platform.io/discovery-pending"
> AnnotationDiscoveredFrom   = "vault.platform.io/discovered-from"
> ```
>
> Replaced raw strings at all call sites:
> - [features/policy/controller/ops.go:116, 130](../../features/policy/controller/ops.go:116) (WriteToVault + ReadbackVerify skip guards)
> - [features/role/controller/ops.go:141, 154](../../features/role/controller/ops.go:141)
> - [features/discovery/controller/controller.go:249, 292](../../features/discovery/controller/controller.go:249) (auto-create annotations)
>
> Renaming is now a rename-of-one-constant + go build, not a grep across the tree.

<details><summary>Original finding (kept for history)</summary>

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
</details>

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

## ✅ 37. INT-SYNC01 test cannot exercise its stated scenario — RESOLVED (2026-05-28)

> **Status**: Resolved. The integration suites run envtest + Vault **without a manager**, so they can't observe reconcile-time status — INT-SYNC01 was repurposed to assert the enforcement that *actually* fires for the empty-rules case: CRD schema rejection (`+kubebuilder:validation:MinItems=1` on `spec.rules`). It now asserts the create is rejected and cites the MinItems constraint, serving as a regression guard against that marker being dropped. Reconcile-time `ValidationError` classification remains covered by `features/policy/controller` + `shared/controller/syncerror` unit tests. 🟡 Minor.
>
> **Original finding (kept for history):**
>
> **Evidence**: [test/integration/syncerror/syncerror_test.go:37-66](../../test/integration/syncerror/syncerror_test.go:37) creates a `VaultPolicy` with `Rules: []vaultv1alpha1.PolicyRule{}` and asserts `Expect(err).NotTo(HaveOccurred())` on the K8s create. But the CRD has `+kubebuilder:validation:MinItems=1` on `Rules`, so the K8s API rejects the create with `spec.rules: Invalid value: 0: spec.rules in body should have at least 1 items` — the reconciler never sees the object.
>
> **Impact**: The test fails reliably on any environment where the CRD is correctly installed (i.e., always). It's been failing in CI's `test-integration` job since the MinItems marker was added.
>
> **Fix options**:
> 1. Replace the empty-rules trigger with a pattern that passes CRD validation but fails Vault validation (e.g., an unsupported capability for a sys path, or a path Vault rejects but the CRD allows).
> 2. Remove the test — the "operator classifies invalid HCL as ValidationError" scenario is already enforced at the CRD-schema layer, so the operator's classifier never has to handle it in practice. The actual reconciler-path validation should be tested via a pattern Vault rejects, not via empty rules.
>
> **Owner**: TBD

---

## ✅ 38. Conditional assertions in `input_validation_test.go` — RESOLVED (2026-05-28)

> **Status**: Resolved. The "passes regardless of outcome" pattern is gone — each block now either asserts unconditionally or skips with a documented reason. SEC-IV03/04/05 (shell metacharacters, HCL-injection payload, invalid capability) assert unconditionally because the bad input violates the CRD's `spec.rules[].path` Pattern or the capabilities Enum, which envtest's apiserver rejects regardless of webhook state. SEC-IV01/02/10/11 are `Skip`ped with precise reasons: the check is webhook/reconcile-only (not deployed in this envtest suite) or not enforced at any layer today (no rule-count or path-length cap — see follow-up note below). 🟡 Minor.
>
> **Follow-up surfaced**: there is no `MaxItems` on `VaultPolicySpec.Rules` and no `MaxLength` on `PolicyRule.Path`, so oversized policies are accepted at every layer. Adding caps is a small CRD hardening change tracked separately.
>
> **Original finding (kept for history):**
>
> **Evidence**: [test/integration/security/input_validation_test.go](../../test/integration/security/input_validation_test.go) (multiple sites) uses a pattern that passes regardless of webhook state:
> ```go
> err := testEnv.K8sClient.Create(ctx, policy)
> if err == nil {
>     // "if creation succeeded (webhook not running), verify it doesn't bypass"
>     defer func() { _ = testEnv.K8sClient.Delete(ctx, policy) }()
> }
> // "Note: With webhook enabled, this should fail validation"
> ```
> There are no `Expect(...)` calls on the observable outcome. The test passes whether the webhook accepts, rejects, or is absent.
>
> **Impact**: Zero signal from the suite. Security-input-validation regressions would not be caught here.
>
> **Fix**: Gate each `It(...)` block on webhook availability (skip with documented reason if absent), then assert unconditionally inside (`Expect(err).To(HaveOccurred())` plus a specific error-content check, OR verify the Vault side-effect that the rule should have prevented).

---

## 🆕 39. No direct unit tests for `SyncWorkflow.Execute` / `CleanupWorkflow.Execute` — OPEN

> **Status**: Open. Surfaced by [AUDIT-2026-05](AUDIT-2026-05.md). 🟡 Minor.
>
> **Evidence**: Both workflow state machines live in [shared/controller/workflow/sync.go](../../shared/controller/workflow/sync.go) and [shared/controller/workflow/cleanup.go](../../shared/controller/workflow/cleanup.go). They have **88.7% statement coverage** transitively (via the per-feature integration tests in `test/integration/{policy,role,connection,...}`), but no direct test exercises the 9-step orchestration in isolation.
>
> **Impact**: A regression in the workflow itself (e.g., a step-ordering bug, a state mutation that breaks an idempotency invariant) only surfaces via downstream feature tests. If those tests have gaps, the workflow bug ships.
>
> **Fix**: New `test/integration/workflow/` category with table-driven tests parameterized on `ResourceOps` stubs (no real Vault, no testenv). Cover: drift correction path, conflict-adopt path, dryrun short-circuit, cleanup-failure enqueue.

---

## 🆕 40. Missing CRD update-lifecycle e2e for cluster + role variants — OPEN

> **Status**: Open. Surfaced by [AUDIT-2026-05](AUDIT-2026-05.md). 🟡 Minor.
>
> **Evidence**: `test/e2e/` has explicit spec-mutation e2e only for `VaultPolicy` (TC-VP03). `VaultClusterPolicy`, `VaultRole`, `VaultClusterRole` have create+verify+delete coverage but no dedicated "modify spec, observe Vault converge" test.
>
> **Impact**: Drift-correction and adapter-path regressions on cluster + role variants only surface in unit/integration tests, not in the full reconcile-against-real-Vault loop.
>
> **Fix**: Add TC-CP-UPDATE, TC-VR-UPDATE, TC-CR-UPDATE analogous to TC-VP03 — same Vault-side verification, same generation/observedGeneration assertions.

---

## ✅ 41. `NewNotFoundError` + `NewConnectionError` constructors unused — RESOLVED (2026-05-28)

> **Status**: Resolved (2026-05-28). The two unused constructors were removed from `shared/infrastructure/errors/errors.go`; the `NotFoundError`/`ConnectionError` types and the `IsNotFoundError`/`IsConnectionError` checkers (used in production classifiers) are retained, and the test call sites now construct the structs directly. 🟢 Cosmetic. Different from §29 (which was about the *classifier* using `IsNotFoundError` / `IsConnectionError` — that's resolved). This is about the *constructors* (`NewNotFoundError`, `NewConnectionError`) being defined at [shared/infrastructure/errors/errors.go:141,175](../../shared/infrastructure/errors/errors.go:141) but never called from production code.
>
> **Evidence**: `grep -rn "NewNotFoundError\|NewConnectionError" --include='*.go' .` finds only the definitions themselves and a handful of test usages. No production call site.
>
> **Impact**: Mild. The types and `Is*` checkers are alive and used in classifier paths (`features/connection/controller/handler.go:932`, `shared/controller/syncerror/handler.go:141,146`). The checkers may be matching errors from other sources via `errors.As` — that needs verification before deletion. Worst case: dead constructor code that's 100% test-covered (per the `shared/infrastructure/errors` package's 100% coverage).
>
> **Fix options**:
> 1. Verify the checkers handle errors from non-custom sources (likely yes — they check for sentinel patterns from Vault SDK / K8s API). Then remove the unused constructors and their tests.
> 2. Wire the constructors at appropriate places (e.g., when the reconciler hits a 404 from Vault, wrap with `NewNotFoundError`). This adds richer typed error info but may not be needed if the checkers already work on wrapped sentinel errors.

---

## ✅ 42. JWT auth only ever tested via static JWKS, never OIDC discovery — RESOLVED (2026-05-28)

> **Status**: Resolved. Surfaced while validating the JWT/OIDC auth path for an external-Vault + EKS/self-managed scenario. 🟠 Major (auth correctness coverage).
>
> **Original gap**: The e2e JWT auth setup (`configureJWTAuthAtPath` in [e2e_suite_test.go](../../test/e2e/e2e_suite_test.go)) *preferred* `oidc_discovery_url` but silently fell back to static `jwt_validation_pubkeys` whenever Vault couldn't reach the issuer. Because the cluster issuer was `https://kubernetes.default.svc` (unresolvable from the external Vault container), **every** run took the static-JWKS fallback. The discovery-URL code path — the one real EKS/IRSA and self-managed clusters actually use — was therefore never exercised end-to-end, and no test asserted which path was active.
>
> **Resolution**:
> - The external Vault container now reaches the control plane by its in-cluster service name. A `k8s-svc-proxy` (alpine/socat) does a TLS passthrough `kubernetes.default.svc:443 → k3s:6443`, mirroring the real `kubernetes.default.svc` Service → apiserver hop. See [docker-compose.e2e.yaml](../../docker-compose.e2e.yaml).
> - k3s issuer set to the literal `https://kubernetes.default.svc` (`--service-account-issuer` + matching `--service-account-jwks-uri`), with `--api-audiences` pinned so the default token audience stays decoupled from the issuer (as on real EKS). The apiserver itself stays on 6443 — all API access, TokenReview (`kubernetes_host`), kubeconfig, and the operator's `6443` egress networkpolicy are untouched.
> - Anonymous discovery was already granted via the `system:service-account-issuer-discovery → system:unauthenticated` binding in [vault-rbac.yaml](../../test/e2e/fixtures/vault-rbac.yaml).
> - Vault `auth/jwt` is now configured with `oidc_discovery_url` + `oidc_discovery_ca_pem` (the k3s CA) instead of static keys ([Makefile](../../Makefile) `e2e-configure-vault`).
>
> **Tests**: new **TC-AU07** in [tc_auth_jwt_test.go](../../test/e2e/tc_auth_jwt_test.go) — TC-AU07-01 reads `auth/jwt/config` and *fails loudly* unless `oidc_discovery_url` is set and `jwt_validation_pubkeys` is empty (catches a silent fallback); TC-AU07-02 mints a real K8s SA token and logs in, proving Vault fetched JWKS from the issuer to verify the signature. Verified against **both** issuer styles: EKS-style reachable URL (`https://k3s:6443`) and self-managed literal (`https://kubernetes.default.svc`). Full `auth` label suite (35 specs) passes with zero regression — TokenReview/kubernetes (TC-AU01), JWT (TC-AU04/05/06), Dex OIDC (TC-AU-OIDC), AppRole all green.
>
> **Note (constraint)**: a cluster signs SA tokens with exactly one issuer, and Vault (go-oidc) requires `oidc_discovery_url == discovery-doc issuer == token iss`. So two issuer hostnames can't validate the *same* tokens simultaneously — "both styles" is proven sequentially by switching `--service-account-issuer`, not via two live mounts.

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

## See also

- [AUDIT-2026-05.md](AUDIT-2026-05.md) — source of §§37–41 with full test-execution context.

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
