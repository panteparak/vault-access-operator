# Contributor Instructions

> Step-by-step procedures for common operator-development tasks. Each section has **goal**, **when to use**, **steps**, **verification**, and **pitfalls**.

## Table of Contents

1. [Add a new Vault auth backend](#1-add-a-new-vault-auth-backend)
2. [Add a new CRD family](#2-add-a-new-crd-family)
3. [Add a new webhook validator](#3-add-a-new-webhook-validator)
4. [Add a new metric](#4-add-a-new-metric)
5. [Add a new domain event](#5-add-a-new-domain-event)
6. [Debug a stuck reconcile](#6-debug-a-stuck-reconcile)
7. [Run unit, integration, and e2e tests locally](#7-run-unit-integration-and-e2e-tests-locally)
8. [Regenerate CRDs and deepcopy](#8-regenerate-crds-and-deepcopy)
9. [Bump `controller-runtime`](#9-bump-controller-runtime)
10. [Build both documentation sites](#10-build-both-documentation-sites)

---

## 1. Add a new Vault auth backend

**Goal**: Support a new Vault login method (e.g., Azure AD, Kerberos, LDAP, CF) so `VaultConnection` specs can select it.

**When to use**: A user asks "Can the operator authenticate to Vault using X?" and X isn't in the 8 supported methods.

**Steps**:

1. **Design the spec shape.** Add a new `<Method>Auth` struct to [api/v1alpha1/vaultconnection_types.go](../../api/v1alpha1/vaultconnection_types.go), following the pattern of `AppRoleAuth` ([vaultconnection_types.go:176](../../api/v1alpha1/vaultconnection_types.go:176)):
   ```go
   type AzureAuth struct {
       Role       string                        `json:"role"`
       AuthPath   string                        `json:"authPath,omitempty"` // default "azure"
       ClientID   string                        `json:"clientId,omitempty"`
       // ... method-specific fields
   }
   ```
   Add the field to `AuthConfig`:
   ```go
   type AuthConfig struct {
       // ... existing fields
       Azure *AzureAuth `json:"azure,omitempty"`
   }
   ```
   Add kubebuilder validation markers (`+kubebuilder:default=`, `+kubebuilder:validation:Enum=`) as appropriate.

2. **Implement login-data generation** if the backend needs client-side signing (AWS, GCP do). Add a file under [pkg/vault/auth/](../../pkg/vault/auth/) analogous to [aws.go](../../pkg/vault/auth/aws.go) / [gcp.go](../../pkg/vault/auth/gcp.go).

3. **Add a `vault.Client.Authenticate<Method>` method** in [pkg/vault/client.go](../../pkg/vault/client.go) that POSTs to `/auth/{path}/login` and stores the returned token via `SetToken`.

4. **Wire into the auth dispatch chain**. Add a new `else if` branch in [features/connection/controller/handler.go:704](../../features/connection/controller/handler.go:704) following the existing pattern:
   ```go
   if conn.Spec.Auth.Azure != nil {
       return h.authenticateAzure(ctx, vc, conn)
   }
   ```
   (Strongly consider the refactor in [IMPROVEMENTS.md §6](IMPROVEMENTS.md#6-auth-dispatch-chain-vs-strategy-map) while you're here — each new branch makes the linear chain worse.)

5. **Update [internal/webhook/vaultconnection_webhook.go](../../internal/webhook/vaultconnection_webhook.go) if a connection webhook exists** (see [IMPROVEMENTS.md §8](IMPROVEMENTS.md#8-connection-webhook-missing) — today it doesn't, so skip).

6. **Update user docs** at [docs/auth-methods/](../../docs/auth-methods/): copy [kubernetes.md](../../docs/auth-methods/kubernetes.md) as a template. Add to [mkdocs.yml](../../mkdocs.yml) nav.

7. **Add tests**:
   - Unit test for login-data generator in `pkg/vault/auth/<method>_test.go` with fake signers.
   - Unit test for `Handler.authenticate` with `Auth.<Method>` set, in `features/connection/controller/handler_test.go`.
   - Integration test in `test/integration/connection/` if the backend can be exercised against Vault via testcontainers.

**Verify**:
```bash
make manifests generate       # regenerate CRDs + deepcopy
make test                     # unit
make test-integration         # integration (spins up Vault container)
```

**Pitfalls**:
- Forgetting `// +kubebuilder:object:generate=true` markers → DeepCopy codegen will miss the struct → runtime panic on .DeepCopy().
- Exactly-one-auth-method validation is currently only enforced by "first-non-nil wins" in the dispatch chain. If you want strict rejection of multi-auth specs, add the check to a future `VaultConnection` webhook.
- The operator must authenticate once to Vault **using** the new method. It also needs to be representable as a Vault auth mount that a `VaultRole` can target (for dependent role resources). These are two separate axes — see [IMPROVEMENTS.md §7](IMPROVEMENTS.md#7-role-backend-coverage-gap).

---

## 2. Add a new CRD family

**Goal**: Add a new Kubernetes resource kind (e.g., `VaultKVEntry`, `VaultTransitKey`) that the operator reconciles.

**When to use**: Expanding beyond the five existing CRDs (Connection, Policy, ClusterPolicy, Role, ClusterRole).

**Steps**:

1. **Scaffold with kubebuilder**:
   ```bash
   kubebuilder create api --group vault.platform.io --version v1alpha1 --kind VaultKVEntry --namespaced=true
   ```
   This generates `api/v1alpha1/vaultkventry_types.go` and registers it with the scheme.

2. **Design the spec + status**. Embed `ReconcileStatus` and `SyncStatus` from [api/v1alpha1/common_types.go](../../api/v1alpha1/common_types.go) so the new kind gets the standard `phase`, `lastReconcileID`, `lastAppliedHash`, `binding`, etc.

3. **Create the feature folder**: `features/kventry/{controller,domain}/`. Follow the policy feature as a template.

4. **Decide: use `SyncWorkflow` or bespoke handler?**
   - **Use `SyncWorkflow`** if your reconcile fits the pattern *validate → check conflict → prepare content → detect drift → write → verify → finalize*. Implement `ResourceOps` ([shared/controller/workflow/ops.go:31](../../shared/controller/workflow/ops.go:31)) for the new kind. This is what Policy and Role do.
   - **Bespoke handler** if the lifecycle diverges substantially. Connection does this because it has auth/health/bootstrap phases that don't map onto the workflow. Cost: duplicated error handling, status update, event emission.

5. **Build an Adapter** (`KVEntryAdapter` interface + `VaultKVEntryAdapter` struct). Mirrors [features/policy/domain/adapter.go](../../features/policy/domain/adapter.go). If you have both namespaced + cluster-scoped variants, two adapter implementations behind one interface.

6. **Build the Reconciler** (`features/kventry/controller/kventry_reconciler.go`):
   ```go
   r := &Reconciler{ ... }
   return ctrl.NewControllerManagedBy(mgr).
       For(&vaultv1alpha1.VaultKVEntry{}).
       WithEventFilter(predicate.GenerationChangedPredicate{}).
       Watches(&vaultv1alpha1.VaultConnection{},
           handler.EnqueueRequestsFromMapFunc(watches.KVEntryRequestsForConnection(mgr.GetClient())),
           builder.WithPredicates(watches.ConnectionPhaseChangedPredicate{})).
       Complete(r)
   ```

7. **Wire into [cmd/main.go](../../cmd/main.go)** — add after the role feature:
   ```go
   kvFeature := kventry.New(eventBus, connFeature.ClientCache, ...)
   if err := kvFeature.SetupWithManager(mgr); err != nil { ... }
   ```

8. **Add RBAC markers** to the reconciler file:
   ```go
   // +kubebuilder:rbac:groups=vault.platform.io,resources=vaultkventries,verbs=get;list;watch;create;update;patch;delete
   // +kubebuilder:rbac:groups=vault.platform.io,resources=vaultkventries/status,verbs=get;update;patch
   // +kubebuilder:rbac:groups=vault.platform.io,resources=vaultkventries/finalizers,verbs=update
   ```

9. **Regenerate** manifests + deepcopy: `make manifests generate`.

10. **Add tests** following the three-layer pattern (unit / integration / e2e).

**Verify**:
```bash
make manifests generate
make test
kubectl apply -f config/samples/vault_v1alpha1_vaultkventry.yaml
kubectl describe vaultkventry <name>
```

**Pitfalls**:
- Forgetting `// +kubebuilder:subresource:status` on the CRD type → `Status().Update` silently does nothing.
- `BaseReconciler[T]` uses Go generics; `T` must be a pointer to the concrete type and must satisfy `ReconcileTrackable`, `SyncableResource`, and `client.Object`. Missing one method yields compile-time errors but they're cryptic — read them carefully.
- Adding the feature before the Connection feature in `main.go` → gets a nil `ClientCache`. Always construct after connection.

---

## 3. Add a new webhook validator

**Goal**: Reject malformed `CREATE`/`UPDATE` requests at apply time instead of via status after reconciliation.

**When to use**: You've identified a common user error that's caught by the reconciler's `ValidationError` or `ConflictError` and would be better surfaced via `kubectl apply` feedback.

**Steps**:

1. **Create the validator file** at `internal/webhook/vault<kind>_webhook.go`. Follow [vaultpolicy_webhook.go](../../internal/webhook/vaultpolicy_webhook.go) as a template. Structure:
   ```go
   type Vault<Kind>Validator struct { client client.Client }
   var _ admission.Validator[*vaultv1alpha1.Vault<Kind>] = &Vault<Kind>Validator{}

   // +kubebuilder:webhook:path=/validate-vault-platform-io-v1alpha1-vault<kind>,mutating=false,failurePolicy=fail,sideEffects=None,groups=vault.platform.io,resources=vault<kind>s,verbs=create;update,versions=v1alpha1,name=vvault<kind>.kb.io,admissionReviewVersions=v1

   func SetupVault<Kind>WebhookWithManager(mgr ctrl.Manager) error {
       return ctrl.NewWebhookManagedBy(mgr, &vaultv1alpha1.Vault<Kind>{}).
           WithValidator(&Vault<Kind>Validator{client: mgr.GetClient()}).
           Complete()
   }

   func (v *Vault<Kind>Validator) ValidateCreate(ctx, obj) (admission.Warnings, error) { ... }
   func (v *Vault<Kind>Validator) ValidateUpdate(ctx, old, obj) (admission.Warnings, error) { ... }
   func (v *Vault<Kind>Validator) ValidateDelete(ctx, obj) (admission.Warnings, error) { return nil, nil }
   ```

2. **Wire registration** in [cmd/main.go](../../cmd/main.go) inside the `if enableWebhooks { ... }` block at [line 297](../../cmd/main.go:297):
   ```go
   if err := vaultwebhook.SetupVault<Kind>WebhookWithManager(mgr); err != nil {
       setupLog.Error(err, "unable to create webhook", "webhook", "Vault<Kind>")
       os.Exit(1)
   }
   ```

3. **Regenerate the ValidatingWebhookConfiguration**: `make manifests` — the `+kubebuilder:webhook:` marker flows into [config/webhook/manifests.yaml](../../config/webhook/manifests.yaml).

4. **Update Helm chart**: `make helm-update-crds` and verify [charts/vault-access-operator/templates/validatingwebhookconfiguration.yaml](../../charts/vault-access-operator/templates/validatingwebhookconfiguration.yaml) now includes the new webhook.

5. **Add unit tests** at `internal/webhook/vault<kind>_webhook_test.go`. Cover:
   - Valid spec passes.
   - Each validation rule rejects with the expected message.
   - `ValidateUpdate` against an immutable field rejects.
   - Warnings (non-fatal) populate the warnings slice.

6. **Add an integration test** under `test/integration/` if the webhook interacts with other resources (e.g., dependency existence checks).

**Verify**:
```bash
make manifests
make test                     # includes webhook unit tests
make e2e-local-up-with-webhooks # includes cert-manager for TLS
make e2e-local-test
```

**Pitfalls**:
- Kubebuilder generates webhook configs from the `+kubebuilder:webhook:` marker. **Multiple markers on the same validator overwrite each other** — put exactly one.
- `failurePolicy: fail` means webhook downtime blocks all CR writes. If that's not what you want, use `ignore` and document the tradeoff.
- Dependency checks (e.g., "does the referenced `VaultConnection` exist?") should be **warnings**, not errors — the referenced resource might be applied in the same kubectl invocation.
- Naming-collision checks need full-list queries; with thousands of resources this becomes slow. Use field indexers if scale is a concern.

---

## 4. Add a new metric

**Goal**: Expose a new Prometheus signal for observability/alerting.

**When to use**: After spotting a latency or rate that isn't captured today. Check [FLOW_METRICS.md](FLOW_METRICS.md) first to confirm the gap.

**Steps**:

1. **Register the metric** in [pkg/metrics/metrics.go](../../pkg/metrics/metrics.go):
   ```go
   ReconcileLatency = prometheus.NewHistogramVec(
       prometheus.HistogramOpts{
           Namespace: "vault_access_operator",
           Subsystem: "reconcile",
           Name:      "duration_seconds",
           Help:      "Reconcile duration in seconds",
           Buckets:   prometheus.ExponentialBuckets(0.01, 2, 10), // 10ms ... 10s
       },
       []string{"kind", "result"},
   )
   ```
   Append to the `metrics.Registry.MustRegister(...)` block in `init()`.

2. **Add a helper** (same file, Go convention: lowercase first letter is for private, uppercase is public; helpers are public):
   ```go
   func ObserveReconcileLatency(kind, result string, d time.Duration) {
       ReconcileLatency.WithLabelValues(kind, result).Observe(d.Seconds())
   }
   ```

3. **Emit at call sites**. For reconcile latency, wrap the reconciler body:
   ```go
   func (r *Reconciler) Reconcile(ctx, req) (ctrl.Result, error) {
       start := time.Now()
       result, err := r.doReconcile(ctx, req)
       metrics.ObserveReconcileLatency("VaultPolicy", resultLabel(err), time.Since(start))
       return result, err
   }
   ```

4. **Be careful with cardinality**. Rule of thumb: label cardinality < 100 per dimension, total series < 10k per metric. Avoid `name` labels (unbounded). `kind, namespace, result` is usually safe.

5. **Add tests** at [pkg/metrics/metrics_test.go](../../pkg/metrics/metrics_test.go) verifying `Inc`/`Observe` advances the counter.

6. **Update [FLOW_METRICS.md](FLOW_METRICS.md)** to document the new metric, its emission site, and its intended dashboard use.

**Verify**:
```bash
make test
curl -sk https://localhost:8443/metrics | grep vault_access_operator_reconcile_duration_seconds
```

**Pitfalls**:
- **Cardinality explosion**: I've seen operators crash Prometheus by labeling with `name` on a cluster with 10k CRs. Always prefer `kind, namespace` over `kind, namespace, name`.
- **Dead metrics**: register + define helper + never call the helper = dead metric. See [IMPROVEMENTS.md §31](IMPROVEMENTS.md#31-dead-metrics) for examples already in the codebase.
- **Forgot the `init()` register call** → metric is invisible to scrapers. No error at startup.

---

## 5. Add a new domain event

**Goal**: Publish an internal signal that other features can react to.

**When to use**: You want cross-feature coordination that isn't naturally expressed via K8s watches. Note: today the event bus has **no production subscribers** ([FLOW_EVENTS.md](FLOW_EVENTS.md), [IMPROVEMENTS.md §27](IMPROVEMENTS.md#27-event-bus-has-no-production-subscribers)); if you're adding a subscription too, this is a good first one.

**Steps**:

1. **Add event type** in `shared/events/<family>.go` (or create a new file):
   ```go
   const PolicyBindingResolvedType = "policy.binding_resolved"

   type PolicyBindingResolved struct {
       BaseEvent
       RoleName    string
       PolicyName  string
       Resource    ResourceInfo
   }

   func (e PolicyBindingResolved) Type() string { return PolicyBindingResolvedType }

   func NewPolicyBindingResolved(...) PolicyBindingResolved { ... }
   ```

2. **Publish from the appropriate feature**:
   ```go
   bus.PublishAsync(ctx, events.NewPolicyBindingResolved(...))
   ```
   Use `PublishAsync` for fire-and-forget (most cases); `Publish` if you need error propagation.

3. **Subscribe from the consuming feature**. Since today we have no precedent, follow the test pattern:
   ```go
   func (f *Feature) registerSubscriptions(bus *events.EventBus) {
       events.Subscribe(bus, func(ctx context.Context, e events.PolicyBindingResolved) error {
           // react: e.g., enqueue the role for re-reconcile
           return f.triggerReconcile(e.RoleName)
       })
   }
   ```
   Call `registerSubscriptions(bus)` from the feature's `New` or `SetupWithManager`.

4. **Add tests** in `shared/events/` and in the subscribing feature's test file.

5. **Update [FLOW_EVENTS.md](FLOW_EVENTS.md)** — add the event to the catalog and publisher/subscriber matrix.

**Verify**:
```bash
make test
# Tail operator logs; look for "publishing event" at V(1)
kubectl logs -n vault-access-operator-system -l app=vault-access-operator | grep "publishing event"
```

**Pitfalls**:
- Subscribers run **synchronously inside `Publish`** — keep them fast. If the handler must call K8s, make it fire-and-forget (`go f.triggerReconcile(...)`).
- `PublishAsync` spawns a goroutine per call. Under high publish rates, goroutine counts can climb. Add a `sync.WaitGroup` or worker pool if this matters.
- No at-least-once guarantees. A crash between `Publish` and the handler's K8s write loses the notification — design for idempotency.

---

## 6. Debug a stuck reconcile

**Goal**: Diagnose why a CR is stuck in `Phase=Error` or `Phase=Syncing` for longer than one reconcile cycle.

**Steps**:

1. **Read the status + events**:
   ```bash
   kubectl describe vaultpolicy -n my-ns my-policy
   ```
   Look for:
   - `Status.Phase` — should be `Active`, not `Error`/`Syncing`.
   - `Status.Conditions[*]` — `Ready=False` with a `Reason` and `Message` tells you the error class.
   - `Events:` section — last ~10 reconciles are visible here.

2. **Get the reconcileID** of the last attempt:
   ```bash
   kubectl get vaultpolicy -n my-ns my-policy -o jsonpath='{.status.lastReconcileID}'
   # e.g., "a1b2c3d4"
   ```

3. **Grep operator logs for that ID**:
   ```bash
   kubectl logs -n vault-access-operator-system deploy/vault-access-operator -c manager \
     | grep 'reconcileID=a1b2c3d4'
   ```
   Every log line within that reconcile shares the same `reconcileID` — all the steps, all the sub-operations, all the errors.

4. **Common stuck-reconcile patterns**:

   | Symptom | Likely cause | Next step |
   |---------|--------------|-----------|
   | `Reason=ConnectionNotReady` | `VaultConnection` not `Active` | `kubectl describe vaultconnection <name>` — check `Phase` and `AuthStatus` |
   | `Reason=ValidationFailed` | Spec invalid | Message has the specific rule violated |
   | `Reason=Conflict` | Vault resource exists, owned by someone else | Add `vault.platform.io/adopt=true` or fix collision |
   | `Phase=Deleting` + `DeletionStuck` event after 5m | Vault unreachable during cleanup | Restore Vault, or manually remove finalizer (Vault leak) |
   | `Phase=Error`, no updates in 30s+ | Operator panicking or stuck reconcile | Check operator pod logs for panic trace; consider restart |

5. **Direct Vault introspection** (need Vault creds):
   ```bash
   vault read sys/policies/acl/<namespace>-<name>       # the policy itself
   vault kv metadata get secret/vault-access-operator/managed/policies/<namespace>/<name>  # managed marker (custom_metadata; prefix policies/ with <cluster>/ if --cluster-name set; only when --managed-markers=true)
   vault token lookup-self                               # what token the operator is using
   ```

6. **If reconcile is visibly firing but status isn't updating**:
   - Check status subresource: `kubectl get vaultpolicy <name> -o yaml | grep -A 30 status:` — if the last `lastReconcileID` matches current logs but the user-visible status is stale, an earlier `.Status().Update` conflict may have left a stale object cached in the reconciler. Look for `conflict` / `409` in logs.
   - If using `--leader-elect`, confirm which pod holds the lease: `kubectl get lease -n vault-access-operator-system 2bf9394e.platform.io -o yaml`.

7. **Force a reconcile** (no built-in trigger — see [IMPROVEMENTS.md §H](IMPROVEMENTS.md#h-no-reconcile-now-trigger)):
   ```bash
   # Touch an annotation to bump generation (status-only change won't work due to GenerationChangedPredicate)
   kubectl annotate vaultpolicy <name> --overwrite force-reconcile="$(date)"
   ```

**Pitfalls**:
- The 8-char `reconcileID` isn't globally unique forever — it's unique enough for a single debug session but two reconciles hours apart might collide. Check timestamps.
- Logs may have rolled off. `kubectl logs --previous` pulls the previous container; if the pod restarted multiple times, only the last-1 container's logs are retained by default.
- If webhooks are enabled and the webhook server is down, `kubectl apply` will fail with `admission webhook ... denied` or network errors before a reconcile even starts.

---

## 7. Run unit, integration, and e2e tests locally

**Goal**: Validate changes across the three test tiers before pushing.

### Unit

```bash
make test
```
Runs `go test ./...` excluding `_test.go` files with `//go:build integration` tags. Uses `httptest.Server` for mock Vault. Fast (<30s typical).

### Integration

```bash
make setup-envtest              # one-time install of envtest binaries
make test-integration
```
Uses `ginkgo` + `envtest` (an in-memory K8s API server) + `testcontainers-go` (a real Vault Docker container). Tags: `//go:build integration`. Lives under [test/integration/](../../test/integration/). Slower (2-5 min typical).

### E2E (local)

```bash
make e2e-local-up               # starts k3s + Vault + Dex via docker-compose
make e2e-local-test             # runs all scenarios
make e2e-local-down             # tear down

# Optional: with admission webhooks (requires cert-manager)
make e2e-local-up-with-webhooks
make e2e-local-test

# Targeted subsets:
make e2e-local-test-auth        # auth-methods scenarios only
make e2e-local-test-modules     # everything except auth
```
[docker-compose.e2e.yaml](../../docker-compose.e2e.yaml) provisions a full stack. Slowest — 10-30 min depending on selection.

### E2E (CI)

```bash
make test-e2e                   # requires pre-existing K8s cluster + Vault via env vars
```
Used in GitHub Actions against a provisioned environment.

**Pitfalls**:
- `make test-integration` fails with "docker daemon not running" if Docker is down — needed by testcontainers.
- envtest binaries are version-pinned; `make setup-envtest` can fail if `ENVTEST_K8S_VERSION` in the Makefile doesn't match a published release.
- E2E `make e2e-local-up` takes ~2 minutes; don't assume it's hung. Check `make e2e-local-status` if unsure.
- Running integration tests on a branch that changed CRDs: must `make manifests generate` first or envtest will use stale schemas.

---

## 8. Regenerate CRDs and deepcopy

**Goal**: Sync generated artifacts with changes to `api/v1alpha1/*_types.go`.

**When to use**:
- Any time you add/remove a field or kubebuilder marker.
- When you add a new CRD family.
- When you change RBAC markers on reconcilers or webhooks.

**Steps**:

```bash
make manifests               # regenerates config/crd/bases/*, config/rbac/*, config/webhook/manifests.yaml
make generate                # regenerates *_deepcopy.go files
make helm-update-crds        # copies CRDs into charts/vault-access-operator/crds
make verify-templates        # sanity-check Helm templates
```

**Verify**:
```bash
git diff --stat config/crd/bases charts/vault-access-operator/crds api/v1alpha1
# expect changes matching your type edits
```

**Pitfalls**:
- Forgetting `make generate` after a type change → DeepCopy code is stale → runtime panic when `client.Get` is called on the new field.
- Kubebuilder strips leading whitespace and trailing periods from comment-derived validation messages. If a marker validation fails with a weird-looking message, check the comment.
- `make helm-update-crds` overwrites `charts/.../crds/*.yaml`. Manual edits there are lost on regeneration.

---

## 9. Bump `controller-runtime`

**Goal**: Upgrade the controller-runtime dependency to a new minor version.

**When to use**: Upstream has security fixes, or you need a new feature (e.g., an improved predicate helper).

**Steps**:

1. **Check release notes** at https://github.com/kubernetes-sigs/controller-runtime/releases. Pay attention to:
   - Deprecations (often removed two minors later).
   - Default behavior changes (e.g., the `GracefulShutdownTimeout` default changed in v0.17).
   - API breaks (rare within v0.x).

2. **Update [go.mod](../../go.mod)**:
   ```bash
   go get sigs.k8s.io/controller-runtime@v0.24.0
   go mod tidy
   ```

3. **Update imports** if anything was renamed. Common breaks:
   - `client.Options` field renames.
   - `metrics.Server` vs `metrics.Options` shape changes.
   - `webhook.Server` constructor signature.

4. **Rerun codegen** (kubebuilder markers may have new options):
   ```bash
   make manifests generate
   ```

5. **Run the full test suite**:
   ```bash
   make test test-integration test-e2e
   ```

6. **Manually verify**:
   - `/metrics` endpoint still serves after `make e2e-local-up`.
   - Webhook rejections still come back with the same error shape.
   - Leader election still works (`--leader-elect=true`).

**Pitfalls**:
- Controller-runtime occasionally changes log-level defaults; logs may suddenly go quiet or verbose.
- Manager option struct sometimes gains required fields — compile error, easy fix.
- Runnable `Start(ctx)` signatures have evolved; check if `pkg/cleanup/controller.go` or `pkg/orphan/controller.go` need updates.

---

## 10. Build both documentation sites

**Goal**: Preview user-facing docs (`docs/`, nav-listed) **and** internal contributor docs (`docs/internal/`, hidden at `/internal/`) together.

**Steps**:

```bash
# Install once
pip install mkdocs mkdocs-material

# Build both
mkdocs build --strict                          # → site/
mkdocs build --strict -f mkdocs-internal.yml   # → site/internal/

# Serve locally (combined)
python3 -m http.server --directory site 8000
```

Open:
- `http://localhost:8000/` — main user docs
- `http://localhost:8000/internal/` — contributor docs with its own sidebar nav

Or iterate on just one:
```bash
mkdocs serve                                    # main docs, live reload
mkdocs serve -f mkdocs-internal.yml --dev-addr :8001   # internal docs, separate port
```

**Pitfalls**:
- Both configs emit their own `search_index.json`; they don't share search across sites. Fine today.
- `mkdocs-internal.yml` has `site_dir: site/internal`, so running the main build *after* the internal build **does not** overwrite `site/internal/` (main config has `exclude_docs: internal/`). Running them in the wrong order is fine.
- When adding a new internal doc, remember to update `mkdocs-internal.yml` → `nav:` so it shows in the sidebar.

---

## Cross-References

- [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) — where to find things
- [ARCHITECTURE.md](ARCHITECTURE.md) — what the layers are
- [FLOW_*.md](FLOW_OVERVIEW.md) — how runtime flows work
- [IMPROVEMENTS.md](IMPROVEMENTS.md) — known gaps you might hit while following these procedures
