# FLOW: VaultConnection Reconciliation

## Summary

The VaultConnection reconciler is the entry point for every conversation the operator has with Vault. It establishes an authenticated `*vault.Client`, caches it in `ClientCache`, performs a health check, and publishes a `ConnectionReady` event so dependent policies/roles know they can proceed. It also owns the **bootstrap** path — a one-time setup where a high-privilege token is used to enable the kubernetes auth mount, create the operator's own role + policy, then (optionally) self-revoke.

**Unlike policy/role, this reconciler does NOT use the shared `SyncWorkflow`**: connection state (bootstrap state, token state, health state) doesn't fit the generic "write content, verify, detect drift" model. Its logic lives entirely in [`features/connection/controller/handler.go`](../../features/connection/controller/handler.go).

## Participants

| # | Component | Layer | Source | Role |
|---|-----------|-------|--------|------|
| 1 | `connection.Reconciler` | transport | [features/connection/controller/reconciler.go](../../features/connection/controller/reconciler.go) | wraps `BaseReconciler[*VaultConnection]` |
| 2 | `connection.Handler` | feature | [features/connection/controller/handler.go:56](../../features/connection/controller/handler.go:56) | `Sync` + `Cleanup` |
| 3 | `bootstrap.Manager` | pkg | [pkg/vault/bootstrap/](../../pkg/vault/bootstrap/) | `Bootstrap(vaultClient, cfg)` — creates k8s mount, role, policy |
| 4 | `token.TokenProvider` | pkg | [pkg/vault/token/provider.go](../../pkg/vault/token/provider.go) | TokenRequest API wrapper |
| 5 | `auth.*` | pkg | [pkg/vault/auth/](../../pkg/vault/auth/) | cloud-identity login-data generators |
| 6 | `vault.Client` | pkg | [pkg/vault/client.go](../../pkg/vault/client.go) | Vault REST facade |
| 7 | `vault.ClientCache` | pkg | [pkg/vault/client_cache.go](../../pkg/vault/client_cache.go) | map[name]Client, owned by connection feature |
| 8 | `events.EventBus` | shared | [shared/events/bus.go](../../shared/events/bus.go) | publishes `ConnectionReady`, `BootstrapCompleted`, `ConnectionDisconnected` |
| 9 | K8s API | external | — | CR fetch/update, Secret reads, TokenRequest |
| 10 | Vault | external | — | health, auth, version |

## Full Interaction (Sync, happy path, post-bootstrap)

```mermaid
sequenceDiagram
    participant RT as controller-runtime
    participant R as BaseReconciler
    participant H as connection.Handler
    participant K8s as K8s API
    participant TP as TokenProvider
    participant VC as vault.Client
    participant Cache as ClientCache
    participant Bus as EventBus
    participant V as Vault

    RT->>R: Reconcile(req)
    R->>K8s: Get VaultConnection
    K8s-->>R: conn
    R->>R: ensure finalizer
    R->>H: Sync(conn)
    activate H

    alt Phase != Syncing && != Active
        H->>K8s: Status().Update(Phase=Syncing)
    end

    H->>H: isBootstrapRequired(conn)?
    Note over H: No bootstrap or already complete
    H->>Cache: Get(conn.Name)
    Cache-->>H: cachedClient or nil
    alt cached & authenticated & same address & token fresh
        Note over H: reuse (no Vault call)
    else token near expiry + RenewalStrategy=renew
        H->>VC: RenewSelf(ctx)
        VC->>V: POST /auth/token/renew-self
        V-->>VC: new expiration
        VC-->>H: ok
    else token expired / renew failed / RenewalStrategy=reauth
        H->>H: buildAndAuthenticateClient
        H->>K8s: get CA cert Secret (if TLS.CASecretRef)
        H->>VC: NewClient(addr, tlsCfg)
        H->>TP: GetToken(SA, audiences, duration)
        TP->>K8s: TokenRequest API
        K8s-->>TP: JWT
        H->>VC: AuthenticateKubernetesWithToken(role, path, jwt)
        VC->>V: POST /auth/kubernetes/login
        V-->>VC: vault token
    end

    H->>Cache: Set(conn.Name, vaultClient)
    H->>VC: GetVersion(ctx)
    VC->>V: GET /sys/seal-status
    V-->>VC: version
    H->>VC: IsHealthy(ctx)
    VC->>V: GET /sys/health
    V-->>VC: healthy bool

    alt healthy
        H->>H: updateHealthStatus(true)
        H->>H: updateAuthStatus(conn, vc) — tokenExpiration, accessor
        alt token was renewed
            H->>H: trackRenewal — increments counter
        end
        H->>K8s: Status().Update(Phase=Active, VaultVersion, Ready=true)
        H->>Bus: PublishAsync(ConnectionReady)
    else unhealthy or error
        H->>H: handleSyncError
        alt isAuthError
            H->>Cache: Delete(conn.Name) — force fresh auth next cycle
        end
        H->>K8s: Status().Update(Phase=Error, Ready=false)
    end

    deactivate H
    H-->>R: err?
    R->>R: emit Synced / SyncFailed event
    R-->>RT: Result{RequeueAfter: 30s}
```

## Bootstrap Path (first-time setup)

```mermaid
sequenceDiagram
    participant H as Handler
    participant K8s as K8s API
    participant BM as bootstrap.Manager
    participant VC as vault.Client
    participant V as Vault
    participant Bus as EventBus

    H->>H: isBootstrapRequired: spec.Auth.Bootstrap != nil && !AuthStatus.BootstrapComplete
    H->>K8s: Get Secret (bootstrap token)
    K8s-->>H: root/admin token
    H->>VC: buildVaultClient(addr, tls)
    H->>VC: AuthenticateToken(bootstrapToken)
    VC->>V: set client token (no HTTP)

    H->>BM: Bootstrap(vc, cfg)
    activate BM
    Note over BM: cfg = { authMethodName, operatorRole, operatorSA,<br/>tokenReviewerSA, tokenReviewerDuration, autoRevoke, operatorPolicy }
    BM->>V: GET /sys/auth — auth mount exists?
    alt not mounted
        BM->>V: POST /sys/auth/{mount} — enable kubernetes
    end
    BM->>V: POST /auth/{mount}/config — kubernetes_host, CA cert, token_reviewer_jwt
    BM->>V: PUT /sys/policies/acl/vault-access-operator — operator policy HCL
    BM->>V: POST /auth/{mount}/role/{operatorRole} — bind SA + policy
    alt AutoRevoke=true (default)
        BM->>V: POST /auth/token/revoke-self — bootstrap token suicide
    end
    BM-->>H: Result{authMethodCreated, roleCreated, bootstrapRevoked, tokenReviewerExpiration}
    deactivate BM

    H->>K8s: Status().Update(AuthStatus.BootstrapComplete=true, BootstrapCompletedAt, TokenReviewerExpiration)
    H->>Bus: PublishAsync(BootstrapCompleted)
    Note over H: return nil — next reconcile (30s) proceeds to normal auth path<br/>with a FRESH CR fetch so BootstrapComplete is seen
```

**Why return immediately after bootstrap instead of proceeding to auth?**
The handler just persisted `BootstrapComplete=true` to status. If it continued in the same function call, `conn` in memory and `conn` in K8s are in sync, but the next reconciler invocation needs a fresh `Get` (the object version has changed). Returning yields to the requeue interval, which triggers a new reconcile with the updated object. This prevents a subtle race where `Sync` accidentally re-runs bootstrap.

## Auth Backend Selection (Handler.authenticate)

```mermaid
flowchart TD
    Start["authenticate(ctx, vc, conn)"]
    Start --> CheckK8s{Auth.Kubernetes<br/>!= nil?}
    CheckK8s -->|yes| K8sAuth["1. TokenProvider.GetToken<br/>2. vc.AuthenticateKubernetesWithToken"]
    CheckK8s -->|no| CheckToken{Auth.Token<br/>!= nil?}
    CheckToken -->|yes| TokAuth["1. getSecretData<br/>2. vc.AuthenticateToken"]
    CheckToken -->|no| CheckAppRole{Auth.AppRole<br/>!= nil?}
    CheckAppRole -->|yes| ARAuth["1. getSecretData(SecretIDRef)<br/>2. vc.AuthenticateAppRole(roleID, secretID, mount)"]
    CheckAppRole -->|no| CheckJWT{Auth.JWT<br/>!= nil?}
    CheckJWT -->|yes| JWTAuth["getJWTToken:<br/>- if JWTSecretRef: read Secret<br/>- else TokenRequest API<br/>→ vc.AuthenticateJWT"]
    CheckJWT -->|no| CheckOIDC{Auth.OIDC<br/>!= nil?}
    CheckOIDC -->|yes| OIDCAuth["getOIDCToken:<br/>- if JWTSecretRef: read Secret<br/>- elif UseServiceAccountToken: TokenRequest<br/>- else error<br/>→ vc.AuthenticateOIDC"]
    CheckOIDC -->|no| CheckAWS{Auth.AWS<br/>!= nil?}
    CheckAWS -->|yes| AWSAuth["auth.GenerateAWSIAMLoginData<br/>→ vc.AuthenticateAWS"]
    CheckAWS -->|no| CheckGCP{Auth.GCP<br/>!= nil?}
    CheckGCP -->|yes| GCPAuth["auth.GenerateGCPIAMJWT<br/>or GenerateGCPGCELoginData<br/>→ vc.AuthenticateGCP"]
    CheckGCP -->|no| Err["❌ error: no auth method configured"]
```

Only the first non-nil branch is taken. The connection webhook (`validateAuthExactlyOne`) enforces exactly-one at admission (bootstrap+kubernetes is the only legal pair).

## Role Mount Resolution (RoleMount)

The connection is the **sole source** of the auth mount + backend family for dependent `VaultRole`/`VaultClusterRole` resources — role CRDs carry no mount fields ([ADR 0009](../adr/0009-connection-owned-role-mount.md)). This is pure spec resolution, not a reconcile step: [`VaultConnection.RoleMount()`](../../api/v1alpha1/vaultconnection_rolemount.go) is called by the role handler, the role/connection webhooks, discovery, and orphan scanning.

Resolution order:

1. `spec.defaults.authPath` if set — family from the optional `spec.defaults.authType`, else the `kubernetes*`/`jwt*` mount-name heuristic (exact or `-`/`_`-separated); unclassifiable names are an admission error (set `defaults.authType`).
2. Otherwise the connection's own login mount: `auth.kubernetes` → kubernetes family; `auth.jwt`/`auth.oidc` → jwt family (Vault's OIDC method IS the jwt backend).
3. Token/appRole/aws/gcp/bootstrap-only logins without `defaults.authPath` have **no role-capable mount** — the webhook denies dependent roles at admission; the role reconciler parks them at `Reason=ValidationFailed` as backstop.

The `defaults` block is now `{authPath, authType, driftMode}`: `authPath` carries **no baked `auth/kubernetes` default** (absent = follow the login mount); the dead `secretEnginePath`/`transitPath` fields are gone. The connection webhook validates unclassifiable `defaults.authPath` names at apply time, and `ValidateUpdate` **warns** (with the dependent-role count) when an update changes the resolved role mount under existing roles — their next sync re-targets the new mount while their recorded status bindings still pin deletion to the old one.

## Token Lifecycle (getOrRenewClient detail)

[handler.go:591-669](../../features/connection/controller/handler.go:591)

```mermaid
flowchart TD
    Start["getOrRenewClient(ctx, conn)"] --> Cached{"ClientCache.Get<br/>authenticated &<br/>same address?"}
    Cached -->|no| Fresh["buildAndAuthenticateClient<br/>(full re-auth)"]
    Cached -->|yes| HasExp{"TokenExpiration<br/>known & TTL > 0?"}
    HasExp -->|no| ReuseStatic["return cached,<br/>renewed=false<br/>(static token)"]
    HasExp -->|yes| Remaining{"remaining = exp - now<br/>> 0?"}
    Remaining -->|no| Fresh
    Remaining -->|yes| Threshold{"remaining > ttl * 0.25?<br/>(75% threshold)"}
    Threshold -->|yes| ReuseFresh["return cached,<br/>renewed=false"]
    Threshold -->|no| Strategy{RenewalStrategy<br/>= reauth?}
    Strategy -->|yes| Fresh
    Strategy -->|no| Renew["vc.RenewSelf(ctx)"]
    Renew --> RenewOk{renew ok?}
    RenewOk -->|yes| ReturnRenewed["return cached,<br/>renewed=true"]
    RenewOk -->|no| Fresh

    Fresh --> ReturnFresh["return new client,<br/>renewed=(was-cached)"]
```

The 75% threshold is a constant (`renewalThreshold = 0.75`) at [handler.go:587](../../features/connection/controller/handler.go:587). The reason: Vault's default token renewal behavior is generous early in the TTL — waiting until ≥75% elapsed reduces Vault API load without risking expiration during a typical reconcile interval.

## Step-by-Step Narrative

### Step 1: Fetch + finalizer
`BaseReconciler.Reconcile` fetches the CR and ensures the finalizer is present. Delegated to `base`.

### Step 2: Bootstrap check
[isBootstrapRequired](../../features/connection/controller/handler.go:184): `spec.Auth.Bootstrap != nil && !AuthStatus.BootstrapComplete`. If true, run `runBootstrap` and return.

### Step 3: Cached-client reuse / renewal / re-auth
[getOrRenewClient](../../features/connection/controller/handler.go:591) — see flowchart above. Returns `(*vault.Client, renewed bool, error)`.

### Step 4: Cache store
Always overwrite: `ClientCache.Set(conn.Name, vaultClient)`. The cache value is a `*vault.Client` with TTL-aware state. Other features `Get` this by name.

### Step 5: Version + health
`GetVersion` (GET `/sys/seal-status`) and `IsHealthy` (GET `/sys/health`). Both are required to reach `Phase: Active`. Failures go through `handleSyncError`.

### Step 6: Status + event publication
- `updateHealthStatus` — `Healthy=true`, resets `ConsecutiveFails`, records heartbeat.
- `updateAuthStatus` — sets `TokenExpiration`, `TokenAccessor`, emits `TokenReviewerRotationDisabled` condition if the user opted out.
- `trackRenewal` — increments `TokenRenewalCount` if a renewal occurred.
- `Phase=Active`, `Ready=True`.
- `Status().Update`.
- Publish `ConnectionReady(name, address, version)` async.

### Step 7: Retry on error
If any step errors, `handleSyncError`:
- evicts the cached client if the error is an auth error (forces fresh auth next cycle)
- sets `Phase=Error`, `Ready=False`, writes `Message=err.Error()`
- updates `LastHealthCheck` if not already set (for errors before explicit health check)
- returns the error to `BaseReconciler.Status.Error` which requeues after the error interval

## Cleanup (conn deletion)

[handler.Cleanup](../../features/connection/controller/handler.go:423)

```mermaid
sequenceDiagram
    participant H as Handler
    participant K8s as K8s API
    participant Cache
    participant VC as cached vault.Client
    participant V as Vault
    participant Life as LifecycleCtrl
    participant Rev as ReviewerCtrl
    participant Bus as EventBus

    H->>K8s: List VaultPolicies, VaultClusterPolicies, VaultRoles, VaultClusterRoles
    H->>H: filter by Spec.ConnectionRef == conn.Name
    alt dependents > 0
        H->>K8s: Status.Update(Phase=Deleting, Deleting=False, Reason=ChildrenExist)
        H-->>H: return error (blocks finalizer removal, retries next cycle)
    end

    H->>K8s: Status.Update(Phase=Deleting)
    alt Bootstrap.CleanupAuthMount=true && AuthStatus.BootstrapComplete
        H->>Cache: Get(conn.Name)
        Cache-->>H: vc
        H->>VC: DisableAuth(authPath)
        VC->>V: DELETE /sys/auth/{path}
    end

    H->>Cache: Get(conn.Name)
    alt authenticated
        H->>VC: RevokeSelf(ctx) with 5s timeout
        VC->>V: POST /auth/token/revoke-self
    end

    H->>Life: Unregister(conn.Name)
    H->>Rev: Unregister(conn.Name)
    H->>Cache: Delete(conn.Name)
    H->>Bus: PublishAsync(ConnectionDisconnected)
    H-->>R: nil (BaseReconciler removes finalizer)
```

**Deletion is blocked by dependents** — this is a "soft" block: the finalizer stays, `Phase=Deleting`, `Deleting` condition = False with reason `ChildrenExist`. User must delete all dependent CRs first.

## Interface Boundary Summary

| # | Crossing | Port | Method | Payload |
|---|----------|------|--------|---------|
| 1 | Reconciler → Handler | `FeatureHandler[*VaultConnection]` | `Sync(ctx, conn)` | `*VaultConnection` |
| 2 | Handler → K8s | `client.Client` | `Get`, `Status().Update` | CR |
| 3 | Handler → Secret | `client.Client.Get` | — | `*corev1.Secret` |
| 4 | Handler → TokenProvider | `TokenProvider` | `GetToken(opts)` | `*TokenInfo` |
| 5 | Handler → Vault | `vault.Client` | `AuthenticateKubernetesWithToken`, `AuthenticateJWT`, `AuthenticateAppRole`, `AuthenticateAWS`, `AuthenticateGCP`, `AuthenticateOIDC`, `AuthenticateToken`, `GetVersion`, `IsHealthy`, `RenewSelf` | HTTPS bodies |
| 6 | Handler → BootstrapManager | `bootstrap.Manager` | `Bootstrap(vc, cfg)` | `*Result` |
| 7 | Handler → ClientCache | `vault.ClientCache` | `Get`, `Set`, `Delete` | `*vault.Client` |
| 8 | Handler → EventBus | `events.EventBus` | `PublishAsync` | `ConnectionReady`, `BootstrapCompleted`, `ConnectionDisconnected` |

## Error Scenarios

| Error | Origin step | Trigger | Phase → | Recovery |
|-------|------------|---------|---------|----------|
| Secret not found | step 3 or bootstrap | bootstrap Secret, CA cert Secret, token Secret missing | Error | user creates Secret |
| Vault unreachable | step 3 (auth) | network / DNS / TLS | Error | retry every 30s |
| 403 / invalid token | any Vault call | token revoked / role permissions changed | Error + cache evict | next reconcile re-auths with fresh TokenRequest |
| Vault sealed | step 5 (`IsHealthy`) | seal operation | Error | user unseals Vault |
| `BootstrapFailed` | runBootstrap | bootstrap token lacks permissions | Error | user provides higher-privilege token |
| `kubernetes auth config required for bootstrap` | runBootstrap | `Spec.Auth.Kubernetes` missing | Error | user adds `Auth.Kubernetes` spec |
| Dependents exist | Cleanup | policies/roles reference this connection | Deleting + ChildrenExist cond | user deletes dependents |
| Status conflict (409) | Status().Update | discovery also updating status | (retried implicitly by controller-runtime, or explicitly in discovery) | — |

## Files Read / Written

| File | Op | When |
|------|-----|------|
| `VaultConnection` CR | R + status W | every reconcile |
| `Secret` (bootstrap, token, appRole, jwt, gcp, tls.ca) | R | per-auth-method branches |
| `ServiceAccount` TokenRequest | R (synthetic) | k8s + JWT + OIDC auth flows |
| Vault `/sys/auth` | R + W | bootstrap only |
| Vault `/auth/{mount}/config` | W | bootstrap only |
| Vault `/auth/{mount}/role/{operatorRole}` | W | bootstrap only |
| Vault `/sys/policies/acl/vault-access-operator` | W | bootstrap only |
| Vault `/auth/{method}/login` | W | every full auth |
| Vault `/auth/token/renew-self` | W | renewal path |
| Vault `/auth/token/revoke-self` | W | cleanup + autoRevoke |
| Vault `/sys/health`, `/sys/seal-status` | R | every successful sync |
| K8s Event | W | via `BaseReconciler.recordEvent` |

## Events Published

| Event | Where | Payload |
|-------|-------|---------|
| `ConnectionReady` | Sync success | `{name, address, vaultVersion}` |
| `BootstrapCompleted` | runBootstrap success | `{name, authPath, revoked, transitionedToK8sAuth}` |
| `ConnectionDisconnected` | Cleanup | `{name, reason}` |

## Divergence from Other Flows

1. **No shared workflow** — connection doesn't fit the policy/role mold (no content to write, different state machine). Its own handler is bespoke.
2. **No drift detection** — conceptually, "drift" would mean someone changed the auth mount behind the operator's back. Not implemented.
3. **No conflict detection** — the reconciler doesn't check if another operator owns the same auth mount.
4. **Manual status update vs workflow** — policy/role statuses are updated by `workflow.finalizeSuccessfulSync`; connection updates its own status inline.
5. **Heavy branching** — 7 auth methods via chained `if != nil` checks. Could be refactored to a strategy map (see [IMPROVEMENTS.md §6](IMPROVEMENTS.md#6-auth-dispatch-chain-vs-strategy-map)).

## Cross-References

- Overview: [FLOW_OVERVIEW.md](FLOW_OVERVIEW.md)
- Architecture: [ARCHITECTURE.md](ARCHITECTURE.md)
- Auth detail: [FLOW_AUTH.md](FLOW_AUTH.md)
- Policy/role flows depend on a **ConnectionReady** event or cache entry: [FLOW_POLICY.md](FLOW_POLICY.md), [FLOW_ROLE.md](FLOW_ROLE.md)
- Cleanup: [FLOW_DELETION.md](FLOW_DELETION.md)
