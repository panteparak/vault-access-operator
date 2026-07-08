# FLOW: VaultRole / VaultClusterRole Sync

## Summary

Roles bind a set of Kubernetes service accounts (or JWT identities) to a list of Vault policies. The operator resolves `PolicyReference` objects (which point at `VaultPolicy` / `VaultClusterPolicy` CRs) into concrete Vault policy names, builds a role data payload appropriate for the **auth backend** (Kubernetes or JWT), and writes it to `auth/{mount}/role/{name}`.

Like policy, role uses the shared `workflow.SyncWorkflow`. Unlike policy, role branches on the **auth backend** at several points. Roles carry **no mount fields**: the referenced VaultConnection is the sole source of the mount + backend family, resolved by [`VaultConnection.RoleMount()`](../../api/v1alpha1/vaultconnection_rolemount.go) ([ADR 0009](../adr/0009-connection-owned-role-mount.md)). The handler resolves this into a `roleTarget{conn, mount, backend}` via `resolveRoleTarget` **before** the sync workflow runs — a connection with no role-capable mount never enters the workflow.

!!! note "Ownership tracking gated by `--managed-markers` (default OFF)"
    The conflict check runs **only when `--managed-markers=true`**. With markers off (the default), the operator writes the role and forgets it. Roles carry **no Vault-side ownership record** (Vault auth roles have no metadata surface — ADR 0008): ownership memory is the CR's own status (a CR that has synced owns its role), and cross-cluster safety is structural — every cluster's operator authenticates through its own auth mount, so another cluster never reaches this mount's roles. Conflict = role exists in Vault AND this CR never synced it → adopt-or-fail. See [ADR 0008](../adr/0008-in-band-ownership-markers.md), [CONTEXT.md `Managed marker`](CONTEXT.md#managed-marker).

## Participants

| # | Component | Source | Role |
|---|-----------|--------|------|
| 1 | `RoleReconciler` / `ClusterRoleReconciler` | [role_reconciler.go](../../features/role/controller/role_reconciler.go), [clusterrole_reconciler.go](../../features/role/controller/clusterrole_reconciler.go) | watches VaultRole + VaultConnection |
| 2 | `roleFeatureHandler` | same | adapter to `FeatureHandler[*VaultRole]` |
| 3 | `role.Handler` | [handler.go:47](../../features/role/controller/handler.go:47) | `SyncRole`, `CleanupRole`, `resolveRoleTarget`/`resolveCleanupTarget`, policy resolution, drift comparison |
| 4 | `RoleAdapter` | [features/role/domain/adapter.go](../../features/role/domain/adapter.go) | interface over both role kinds |
| 5 | `RoleOps` | [ops.go:37](../../features/role/controller/ops.go:37) | implements `workflow.ResourceOps` for roles |
| 6 | `workflow.SyncWorkflow` | shared | same 9-step orchestration as policy |
| 7 | `vault.Client` | pkg | `WriteKubernetesAuthRole`, `ReadKubernetesAuthRole`, `KubernetesAuthRoleExists`, `DeleteKubernetesAuthRole`, `PolicyExists` |
| 8 | `drift.Comparator` | [drift/compare.go](../../shared/controller/drift/compare.go) | sort-insensitive field-by-field comparison |
| 9 | `hash.FromMapDeterministic` | [hash/hash.go](../../shared/controller/hash/hash.go) | sorted-key hashing of role data map |

## Full Sync Interaction (Kubernetes auth backend)

```mermaid
sequenceDiagram
    participant Base as BaseReconciler
    participant H as role.Handler
    participant WF as SyncWorkflow
    participant Ops as RoleOps
    participant VC as vault.Client
    participant K8s as K8s API
    participant Bus as EventBus
    participant V as Vault

    Base->>H: Sync(role)
    H->>K8s: Get VaultConnection(connectionRef) — resolveRoleTarget
    alt connection not found
        H-->>Base: DependencyError → Reason=ConnectionNotReady
    end
    H->>H: conn.RoleMount() → (mount, backend family)
    alt no role-capable mount (token/appRole/aws/gcp/bootstrap-only)
        H-->>Base: ValidationError → Reason=ValidationFailed (backstop; webhook denies at admission)
    end
    H->>Ops: NewRoleOps(adapter, handler, roleTarget{conn, mount, backend})
    H->>WF: Execute

    WF->>WF: resolve driftMode, resolve vault client
    WF->>Ops: Validate — no-op for roles
    WF->>Ops: CheckConflict
    Ops->>VC: KubernetesAuthRoleExists(authPath, name)
    VC->>V: GET /auth/{authPath}/role/{name}
    alt exists & different owner & !shouldAdopt
        Ops-->>WF: ConflictError
    end

    WF->>Ops: PrepareContent

    Ops->>H: resolvePolicyNames(adapter)
    Note over H: for each PolicyRef:<br/>- VaultPolicy → "{namespace}-{name}"<br/>- VaultClusterPolicy → "{name}"
    H-->>Ops: []string policyNames

    Ops->>H: verifyPoliciesExistInVault(policyNames)
    loop each policy
        H->>VC: PolicyExists(name)
        VC->>V: GET /sys/policies/acl/{name}
    end
    alt any missing
        H->>H: setCondition(PoliciesResolved=False, Reason=PolicyNotInVault)
        H->>Recorder: Event(Warning, PolicyNotInVault)
        Note over H: non-blocking — Vault allows referencing nonexistent policies
    else all present
        H->>H: setCondition(PoliciesResolved=True)
    end

    Ops->>Ops: serviceAccountBindings = adapter.GetServiceAccountBindings() — ["ns/name", ...]

    Ops->>H: buildRoleData(target.backend, ..., target.conn)
    Note over H: backend family was resolved from the connection<br/>(roleTarget); target.conn feeds JWT audience defaults
    alt backend = Kubernetes
        H->>H: buildKubernetesRoleData<br/>- split "ns/name" → names[] + namespaces[] (deduped)<br/>- sort both for deterministic hash<br/>- policies = policyNames<br/>- token_ttl, token_max_ttl (optional)
    else backend = JWT
        H->>H: buildJWTRoleData<br/>- role_type = "jwt"<br/>- user_claim default "sub"<br/>- bound_audiences (spec or conn fallback)<br/>- bound_claims = mergeBoundClaims(scalars, lists) OR bound_subject<br/>- bound_claims_type (when bound_claims is set; default "string")<br/>- policies, token_ttl, token_max_ttl
    end

    H-->>Ops: roleData map

    Ops->>H: calculateSpecHash(roleData) → hash.FromMapDeterministic
    H-->>Ops: specHash

    WF->>WF: handleDriftDetection (Active + detect/correct)
    WF->>Ops: DetectDrift(vc)
    Ops->>H: detectRoleDrift
    H->>VC: ReadKubernetesAuthRole(authPath, name)
    VC->>V: GET /auth/{authPath}/role/{name}
    V-->>VC: currentData
    H->>H: drift.Comparator
    alt backend = Kubernetes
        H->>H: compare policies, bound_service_account_names, bound_service_account_namespaces
    else backend = JWT
        H->>H: compare policies (fallback token_policies), bound_audiences, role_type, user_claim, bound_claims + bound_claims_type, or bound_subject
    end
    H->>H: compareValuesIfExpected token_ttl, token_max_ttl (normalized to int seconds)
    H-->>Ops: (drifted, summary)

    WF->>WF: handleDriftModes (same branching as policy)

    WF->>Ops: WriteToVault
    Ops->>VC: WriteKubernetesAuthRole(authPath, name, roleData)
    VC->>V: PUT /auth/{authPath}/role/{name}

    WF->>Ops: ReadbackVerify
    Ops->>H: detectRoleDrift (same compare, after write)
    alt drift still present
        Ops-->>WF: TransientError
    end

    Note over WF: no Vault-side ownership write —<br/>the CR's status IS the ownership memory (ADR 0008)

    WF->>Ops: ApplyBindings
    Ops->>Ops: adapter.SetBinding(VaultResourceBinding{authMount, path})
    Note over Ops: records the BARE mount name (e.g. "kubernetes") —<br/>passing the normalized authPath used to double-prefix<br/>vaultPath as auth/auth/kubernetes/role/x
    Ops->>H: buildPolicyBindings
    H-->>Ops: []PolicyBinding (tracks resolved + resolution status)
    Ops->>Ops: adapter.SetPolicyBindings

    WF->>Ops: ApplyActiveStatus
    Ops->>Ops: adapter.SetVaultRoleName, SetBoundServiceAccounts, SetResolvedPolicies

    WF->>WF: set Phase=Active, Ready/Synced/DependencyReady=True, Drifted=False
    WF->>K8s: Status.Update
    WF->>Ops: PublishSyncEvent
    Ops->>Bus: PublishAsync(RoleCreated)
```

## Auth Backend Branching

The mount + family come from the connection, never the role ([ADR 0009](../adr/0009-connection-owned-role-mount.md)):

```mermaid
flowchart TD
    Start["resolveRoleTarget(adapter)"] --> Defaults{conn.spec.defaults.authPath set?}
    Defaults -->|yes| Family{"family = defaults.authType,<br/>else kubernetes*/jwt* name heuristic"}
    Family -->|kubernetes| K8sPath["kubernetes backend"]
    Family -->|jwt| JWTPath["jwt backend"]
    Family -->|unclassifiable| UnsupportedOut["ValidationError:<br/>set defaults.authType"]
    Defaults -->|no| Login{connection login method}
    Login -->|auth.kubernetes| K8sPath
    Login -->|auth.jwt / auth.oidc| JWTPath
    Login -->|token / appRole / aws / gcp / bootstrap-only| NoMount["ValidationError:<br/>no role-capable mount"]

    K8sPath --> BuildK8s["buildKubernetesRoleData:<br/>- bound_service_account_names<br/>- bound_service_account_namespaces<br/>- policies"]
    JWTPath --> BuildJWT["buildJWTRoleData:<br/>- role_type (default 'jwt')<br/>- user_claim (default 'sub')<br/>- bound_audiences<br/>- (bound_claims + bound_claims_type) OR bound_subject"]

    BuildJWT --> JWTSub{boundClaims OR<br/>boundClaimsList set?}
    JWTSub -->|yes| UseClaims["bound_claims = mergeBoundClaims<br/>(lists win on collision,<br/>scalars wrapped as []interface{}{v}<br/>so round-trip matches Vault JSON)<br/>bound_claims_type = spec or 'string' default"]
    JWTSub -->|no| Subject{spec.jwt.boundSubject<br/>set?}
    Subject -->|yes| ExplicitSub["bound_subject = override"]
    Subject -->|no| DeriveSub["derive from first SA<br/>'system:serviceaccount:ns:sa'"]
    DeriveSub --> MultiSA{more than 1 SA?}
    MultiSA -->|yes| SubErr["ValidationError:<br/>multi-SA requires explicit subject"]
    MultiSA -->|no| UseSubject["bound_subject = derived"]
```

### JWT Audience Resolution

If `spec.jwt.boundAudiences` is empty, fall back to:
1. `VaultConnection.Spec.Auth.JWT.Audiences` (if present)
2. Cluster default: `https://kubernetes.default.svc.cluster.local`

See [defaultJWTAudiences](../../features/role/controller/handler.go:528) and `defaultJWTAudience` constant.

### TTL Normalization

Vault returns TTLs as integer seconds. The operator normalizes expected values before comparison:
[normalizeTTLToSeconds](../../features/role/controller/handler.go:540) — parses "30s"/"5m"/"1h" to `int(d.Seconds())`. This prevents false-positive drift where "30s" (expected string) ≠ 30 (actual int).

## Policy Resolution

From [resolvePolicyNames](../../features/role/controller/handler.go:307):

```mermaid
flowchart TD
    Start[policies list] --> Loop[for each ref]
    Loop --> Kind{ref.Kind}
    Kind -->|VaultPolicy| NamespaceCheck{namespace set?}
    NamespaceCheck -->|yes| UseNS["policyName = namespace + '-' + name"]
    NamespaceCheck -->|no, role is namespaced| DefaultNS["namespace = role.Namespace"]
    NamespaceCheck -->|no, cluster role| Err["ValidationError:<br/>namespace required for<br/>VaultPolicy ref in cluster-scoped role"]
    DefaultNS --> UseNS
    Kind -->|VaultClusterPolicy| NameOnly["policyName = name"]
    Kind -->|other| KindErr["ValidationError:<br/>must be VaultPolicy or VaultClusterPolicy"]
    UseNS --> Append
    NameOnly --> Append
    Append --> Loop
    Loop -.->|done| Return[return policyNames]
```

Note the **asymmetry**: VaultPolicy (namespaced) gets prefixed with its namespace to prevent collisions across namespaces (`prod-read` vs `staging-read`). VaultClusterPolicy keeps its raw name.

## Drift Comparison Fields

```mermaid
graph TB
    subgraph Kubernetes
        K1[policies]
        K2[bound_service_account_names]
        K3[bound_service_account_namespaces]
        K4[token_ttl — optional]
        K5[token_max_ttl — optional]
    end
    subgraph JWT
        J1[policies — fallback token_policies]
        J2[bound_audiences]
        J3[role_type — optional]
        J4[user_claim — optional]
        J5[bound_claims OR bound_subject]
        J6[token_ttl, token_max_ttl — optional]
    end
```

The comparator uses `CompareStringSlices` (order-insensitive via sort) for list fields and `CompareValuesIfExpected` for optional scalars (drift isn't flagged when the spec doesn't set the field).

## Step-by-Step Narrative

### Step 0: Resolve the role target (before the workflow)
[resolveRoleTarget](../../features/role/controller/handler.go:137) — fetch the referenced VaultConnection, call `conn.RoleMount()`. Connection NotFound → `DependencyError` (`Reason=ConnectionNotReady` — it may appear later); no role-capable mount → `ValidationError` (`Reason=ValidationFailed`, permanent until the connection is fixed). The webhook already denies the latter at admission; this is the reconcile backstop.

### Step 1: Resolve policy names
Kind-aware: namespaced prefix for VaultPolicy, bare name for VaultClusterPolicy. Cluster roles referencing namespaced policies **must** specify `namespace` explicitly.

### Step 2: Verify policies exist (warning, non-blocking)
Loop `PolicyExists` for each resolved name. Missing policies emit a warning condition (`PoliciesResolved=False`) and a K8s event but **do not block** the sync — Vault permits binding non-existent policies. This supports workflows where you create the role CR first and the policy CRs catch up.

### Step 3: Service account bindings
`RoleAdapter.GetServiceAccountBindings()` returns `[]string` of `"namespace/name"`:
- VaultRole (namespaced): adapter prepends the role's own namespace to each SA name.
- VaultClusterRole: adapter uses the explicit `ServiceAccountRef.Namespace`.

### Step 4: Connection for JWT defaults
`roleTarget.conn` (already fetched in Step 0) feeds the JWT audience fallback — no second fetch.

### Step 5: Build role data (backend-aware)
- **Kubernetes**: split bindings into names + namespaces (deduped), sort both (stable hashing), add optional TTLs.
- **JWT**: compute role_type, user_claim, bound_audiences, then either `bound_claims` map or derived `bound_subject`. Multi-SA JWT roles require explicit `boundSubject` or `boundClaims` (error otherwise).

### Step 6: Spec hash
`hash.FromMapDeterministic(roleData)` — sorted keys, JSON marshal, SHA-256. Any change in bindings, policies, or TTLs produces a new hash.

### Step 7 onwards
Same as policy: drift detection, write, readback, apply bindings, status, event.

## Cleanup Target Resolution (binding-first)

[resolveCleanupTarget](../../features/role/controller/handler.go:161) picks the mount to **delete** from:

1. `status.binding.authMount` recorded at last sync — wins. A connection whose resolved mount changed after the role synced still deletes from where the role was actually written (`AuthMountName` normalizes legacy `auth/`-prefixed records).
2. Fall back to `resolveRoleTarget` (the connection's current mount).
3. Neither → empty target: a never-synced role under a mount-less connection has nothing in Vault, so `DeleteFromVault` skips the Vault call and the finalizer clears.

## Status Fields Set on Success

| Field | Source |
|-------|--------|
| `VaultRoleName` | `adapter.GetVaultRoleName()` |
| `BoundServiceAccounts` | resolved `"ns/name"` list |
| `ResolvedPolicies` | resolved Vault policy names |
| `Binding` | `{vaultPath: auth/{mount}/role/{name}, authMount: bare mount name, ...}` — drives binding-first cleanup |
| `PolicyBindings[]` | per-ref: `{VaultPolicyRef, vaultPolicyName, resolved:bool}` |
| `LastAppliedHash` | spec hash |
| `LastSyncedAt` | now |
| `EffectiveDriftMode` | resolved mode |

## Error Scenarios

| Error | Step | Trigger |
|-------|------|---------|
| `DependencyError "not found"` | resolveRoleTarget | referenced VaultConnection doesn't exist (`Reason=ConnectionNotReady`) |
| `ValidationError "no role-capable mount"` | resolveRoleTarget | connection logs in via token/appRole/aws/gcp/bootstrap without `defaults.authPath` (`Reason=ValidationFailed`) |
| `ValidationError "invalid policy kind"` | resolvePolicyNames | user set `kind: Role` or empty |
| `ValidationError "namespace required"` | resolvePolicyNames | cluster role references VaultPolicy without namespace |
| `ValidationError "at least one service account"` | resolveJWTBoundSubject | JWT role has no SAs & no `boundSubject` override |
| `ValidationError "multi-SA JWT VaultRole must set boundSubject"` | resolveJWTBoundSubject | JWT role with >1 SA |
| `ConflictError` | CheckConflict | existing role owned by another resource |
| `DependencyError` | vaultclient.Resolve | connection not Active |
| Vault 403 → `Reason=VaultPermissionDenied` | any Vault write/read | operator token lacks a grant on the resolved mount — permanent until the operator's Vault policy changes (still requeued at 30s) |
| `TransientError "readback verification"` | ReadbackVerify | role content differs after write (rare) |
| Warning `PolicyNotInVault` | verifyPoliciesExistInVault | referenced policy missing — non-fatal |

## Cross-References

- [FLOW_POLICY.md](FLOW_POLICY.md) — sibling flow sharing the workflow
- [FLOW_CONNECTION.md](FLOW_CONNECTION.md) — required dependency
- [FLOW_AUTH.md](FLOW_AUTH.md) — more on kubernetes vs jwt auth backend handling
- [FLOW_DELETION.md](FLOW_DELETION.md)
- [IMPROVEMENTS.md](IMPROVEMENTS.md) — drift comparator divergence, backend coverage gaps
