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

## 🔴 1. Unwired controllers (cleanup + orphan + token lifecycle + reviewer rotation)

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

---

## 🔴 2. Silent cleanup failures leak Vault resources

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

---

## 🔴 3. Cleanup controller typing mismatch

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

---

## 🔴 4. `discovery-pending` annotation inconsistency

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

---

## 🟠 5. `DiscoveredResources` unbounded growth

**Evidence:** [features/discovery/controller/controller.go:301-305](../../features/discovery/controller/controller.go:301):

```go
conn.Status.DiscoveryStatus.DiscoveredResources = result.DiscoveredResources
```

No truncation. The auto-memory mentions 500 as an intended cap but it isn't enforced in code.

**Impact:** On a Vault with thousands of policies/roles, the first scan can push `VaultConnection.status` past etcd's per-object size limit (default 1.5 MB). Status update fails, whole reconciliation fails, gauge never updates.

**Fix:**
```go
const maxDiscoveredInStatus = 500
if len(result.DiscoveredResources) > maxDiscoveredInStatus {
    result.DiscoveredResources = result.DiscoveredResources[:maxDiscoveredInStatus]
    // set a condition: DiscoveryResultsTruncated with count
}
```
Plus: emit per-discovered-resource **K8s events** (already done for the aggregate) rather than persisting the full list in status.

---

## 🟠 6. Auth dispatch chain vs strategy map

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

## 🟠 8. Connection webhook missing

**Evidence:** [cmd/main.go:297-314](../../cmd/main.go:297) registers webhooks for `VaultPolicy`, `VaultClusterPolicy`, `VaultRole`, `VaultClusterRole` — but **not `VaultConnection`**.

**Impact:** Malformed connections (e.g., multiple auth sub-structs set, typos in `address`, missing required fields for selected backend) only fail at reconcile time with `Phase=Error`. Users see the error in status, not at `kubectl apply` time.

**Common mistakes only caught at reconcile:**
- Both `Auth.Bootstrap` and `Auth.Kubernetes` set (both are valid in isolation; the second is used only after bootstrap)
- `Auth.AppRole` with no `SecretIDRef`
- `Auth.OIDC` with `UseServiceAccountToken=false` and no `JWTSecretRef`
- `address` without `https://` prefix
- `Discovery.Enabled=true` with `AutoCreateCRs=true` but no `TargetNamespace`

**Fix:** Add `VaultConnectionValidator` under `internal/webhook/` paralleling the policy/role validators. Validation rules to cover each auth method's required fields, URL format, and discovery prereqs.

---

## 🟠 9. Dual reconcilers on `VaultConnection` → status race

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

---

## 🟠 10. Bootstrap state persistence is correct but untested for partial failures

**Evidence:** [features/connection/controller/handler.go:294-313](../../features/connection/controller/handler.go:294) — after `BootstrapComplete=true` is persisted, handler returns immediately so the next reconcile does auth with a fresh object. Good fix for the original issue.

**But:** If `runBootstrap` succeeds partially (auth mount created but policy write failed, or role created but revoke failed), the `BootstrapComplete=true` may be set incorrectly or not at all. There's no finer-grained recording like `AuthMountCreated`, `OperatorRoleCreated`, `BootstrapRevoked` (these exist in `Result` but aren't individually persisted).

**Impact:** Re-running bootstrap after a partial failure could error on "mount already exists" unless the bootstrap manager is idempotent on every step (it is for mount creation, but worth auditing).

**Fix:**
1. Add fine-grained status fields or an `AuthStatus.BootstrapSteps` map.
2. Add e2e test: kill the operator after `AuthMountCreated=true` but before `RoleCreated`. Verify next reconcile resumes correctly.

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

## 🟡 13. Duplicated `shouldAdopt` / `checkConflict` logic

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

---

## 🟡 14. `VaultPolicy` HCL skip uses raw annotation string

**Evidence:** [features/policy/controller/ops.go:108](../../features/policy/controller/ops.go:108):

```go
if annotations["vault.platform.io/discovery-pending"] == "true" {
```

Other annotation keys use constants from `api/v1alpha1` (e.g., `AnnotationAdopt`, `AnnotationDiscovered`). Only this one is a raw string.

**Fix:** Add `AnnotationDiscoveryPending = "vault.platform.io/discovery-pending"` to [common_types.go](../../api/v1alpha1/common_types.go) and reference it here + in the discovery auto-create (§4).

---

## 🟡 15. `listDependents` O(N) list operations, no indexing

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

## 🟡 17. `normalizeHCL` is whitespace-only, doesn't handle comments / reordering

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

---

## 🟡 18. `Phase` string vs typed enum inconsistency in status updates

**Evidence:** most code uses `vaultv1alpha1.PhaseSyncing` constant, but some string literal `"Syncing"` usages exist in tests and the cleanup workflow hardcodes `PhaseDeleting`.

**Impact:** Minor. Refactoring risk if phase names change.

**Fix:** Grep for `"Syncing"`, `"Active"`, `"Error"` string literals outside test fixtures, replace with constants.

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

## 🟡 20. Duplicate `resolvePolicyNames` logic between role handler and binding package

**Evidence:**
- [role/controller/handler.go:307-347](../../features/role/controller/handler.go:307) `resolvePolicyNames`
- [shared/controller/binding/paths.go](../../shared/controller/binding/paths.go) has `VaultPolicyName(ref, namespace)` — the same logic inline

**Impact:** Two sources of truth for "given a `PolicyReference`, what's the Vault name?"

**Fix:** Delete the role-handler inline version, call `binding.VaultPolicyName` everywhere.

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

## 🟢 23. `MinScanInterval` is a package var but overridable via env — weird pattern

**Evidence:** [features/discovery/controller/controller.go:50-58](../../features/discovery/controller/controller.go:50):

```go
var MinScanInterval = time.Minute * 5
func init() {
    if v := os.Getenv("OPERATOR_MIN_SCAN_INTERVAL"); v != "" { ... }
}
```

A global package var mutated during init based on env. Works, but test isolation requires remembering to reset.

**Fix:** Pass it as a field on `Reconciler`, configured via `ReconcilerConfig`. Tests construct a reconciler with a short interval without touching globals.

---

## 🟢 24. Ghost `nolint:staticcheck` comments on recorder calls

**Evidence:** [cmd/main.go:244, 259, 274, 288](../../cmd/main.go:244) — `mgr.GetEventRecorderFor("...")` flagged with `//nolint:staticcheck`. Suggests a deprecation warning being silenced.

**Fix:** Check the upstream deprecation notice — likely `GetEventRecorderFor` is deprecated in favor of `NewRecorder` or similar. Address once rather than carrying the nolint forever.

---

## 🟢 25. cert-manager integration only half-scaffolded

**Evidence:** [cmd/main.go:174-177](../../cmd/main.go:174):

```go
// TODO(user): If you enable certManager, uncomment the following lines:
// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml
// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml
```

**Fix:** Either finish the wiring in kustomize bases or remove the comment. The TODO has been there since project bootstrapping — likely nobody will act on it unless surfaced.

---

## 🟢 26. `cover.out` committed to worktree (~380 KB)

**Evidence:** [cover.out](../../cover.out) present in repo root.

**Fix:** Add to `.gitignore` and remove from tracking.

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

## Priority Ranking (if you can only fix 5)

| Rank | Fix | Why first |
|------|-----|-----------|
| 1 | §1 + §3 — wire cleanup, orphan, lifecycle, reviewer controllers | silent data loss + long-running break; the controllers exist, just aren't registered |
| 2 | §2 — stop removing finalizer on cleanup failure | closely coupled to §1; together they fix resource leakage |
| 3 | §4 — VaultRole `discovery-pending` annotation parity | silent auth-loss footgun for discovery users |
| 4 | §8 — VaultConnection admission webhook | shifts many "what happened to my connection?" tickets from reconcile-time to apply-time |
| 5 | §5 — cap `DiscoveredResources` in status | one large Vault triggers unrecoverable status failure |

---

## Cross-references back into the flow docs

- [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)
- [ARCHITECTURE.md](ARCHITECTURE.md) — same unwired-controllers note in "Shared infrastructure" callout
- [FLOW_OVERVIEW.md](FLOW_OVERVIEW.md) — pre-flight note
- [FLOW_CONNECTION.md](FLOW_CONNECTION.md) — dual reconciler, auth dispatch chain, listDependents
- [FLOW_POLICY.md](FLOW_POLICY.md) — HCL normalization, discovery-pending, duplicate shouldAdopt
- [FLOW_ROLE.md](FLOW_ROLE.md) — backend coverage, resolvePolicyNames duplication, JWT subject derivation
- [FLOW_DISCOVERY.md](FLOW_DISCOVERY.md) — unbounded list, role annotation gap
- [FLOW_DELETION.md](FLOW_DELETION.md) — silent cleanup failures
- [FLOW_AUTH.md](FLOW_AUTH.md) — unwired lifecycle/rotator, auth dispatch refactor, backend coverage gap
