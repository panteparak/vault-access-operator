# API Reference

This page documents all Custom Resource Definitions (CRDs) provided by the Vault Access Operator.

## Overview

| CRD | Scope | Description |
|-----|-------|-------------|
| [VaultConnection](#vaultconnection) | Cluster | Establishes connection to Vault server |
| [VaultPolicy](#vaultpolicy) | Namespaced | Manages namespace-scoped Vault policies |
| [VaultClusterPolicy](#vaultclusterpolicy) | Cluster | Manages cluster-wide Vault policies |
| [VaultRole](#vaultrole) | Namespaced | Manages namespace-scoped Kubernetes auth roles |
| [VaultClusterRole](#vaultclusterrole) | Cluster | Manages cluster-wide Kubernetes auth roles |
| [VaultKVSecret](#vaultkvsecret) | Namespaced | Seeds (pre-creates) a KV v2 secret path for External Secrets Operator |

All CRDs belong to the `vault.platform.io` API group with version `v1alpha1`.

---

## Common Concepts

### Conflict Policies

When creating resources that may already exist in Vault:

| Policy | Behavior |
|--------|----------|
| `Fail` | Fail if a resource with the same name exists (default) |
| `Adopt` | Adopt and manage the existing resource |

### Deletion Policies

Control what happens when a Kubernetes resource is deleted:

| Policy | Behavior |
|--------|----------|
| `Delete` | Delete the resource from Vault (default) |
| `Retain` | Keep the resource in Vault |

### Variable Substitution

Policies support variable substitution in paths:

| Variable | Substituted With |
|----------|------------------|
| `{{namespace}}` | The Kubernetes namespace of the resource |
| `{{name}}` | The name of the Kubernetes resource |

### Resource Phases

All resources report their current phase in status:

| Phase | Description |
|-------|-------------|
| `Pending` | Resource is awaiting initial processing |
| `Syncing` | Resource is being synced to Vault |
| `Active` | Resource is successfully synced to Vault |
| `Conflict` | Conflict with existing Vault resource |
| `Error` | Resource sync failed |
| `Deleting` | Resource is being removed from Vault (finalizer running) |

---

## VaultConnection

Establishes and manages a connection to a HashiCorp Vault server.

- **Scope:** Cluster
- **Short Name:** N/A

### Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-primary
spec:
  address: https://vault.example.com:8200
  auth:
    kubernetes:
      role: vault-access-operator
  healthCheckInterval: 30s
```

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `address` | string | Yes | - | Vault server address |
| `auth` | AuthConfig | Yes | - | Authentication configuration |
| `tls` | TLSConfig | No | - | TLS configuration |
| `healthCheckInterval` | duration | No | `30s` | Health check interval |

### AuthConfig

| Field | Type | Description |
|-------|------|-------------|
| `kubernetes` | KubernetesAuth | Kubernetes service account authentication |
| `token` | TokenAuth | Static token authentication |
| `appRole` | AppRoleAuth | AppRole authentication |
| `bootstrap` | BootstrapAuth | One-time bootstrap authentication |
| `jwt` | JWTAuth | JWT authentication with external identity providers |
| `oidc` | OIDCAuth | OIDC authentication for workload identity federation |
| `aws` | AWSAuth | AWS IAM authentication (EKS/IRSA) |
| `gcp` | GCPAuth | GCP IAM authentication (GKE Workload Identity) |

#### KubernetesAuth

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `role` | string | **Required** | Vault role to authenticate as |
| `authPath` | string | `kubernetes` | Mount path of Kubernetes auth method |
| `kubernetesHost` | string | auto-discover | Override the Kubernetes API server address for Vault auth config. Required when Vault is external to the cluster |
| `tokenDuration` | duration | `1h` | Requested SA token lifetime (uses TokenRequest API) |
| `tokenReviewerRotation` | bool | `true` | Enable automatic token_reviewer_jwt rotation |
| `renewalStrategy` | string | `renew` | Token renewal strategy: `renew` (proactive renewal) or `reauth` (re-authenticate with fresh credentials) |

#### TokenAuth

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `secretRef` | SecretKeySelector | **Required** | Reference to secret containing Vault token |

#### AppRoleAuth

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `roleId` | string | **Required** | AppRole role ID |
| `secretIdRef` | SecretKeySelector | **Required** | Reference to secret containing AppRole secret ID |
| `mountPath` | string | `approle` | Mount path of AppRole auth method |

#### JWTAuth

Configures JWT authentication with external identity providers. Use this for generic JWT-based authentication from any identity provider (Cognito, Auth0, Okta, etc.).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `role` | string | **Required** | Vault role configured for JWT auth |
| `authPath` | string | `jwt` | Auth method mount path |
| `jwtSecretRef` | SecretKeySelector | - | Reference to secret containing JWT. If not provided, uses TokenRequest API |
| `audiences` | []string | `["vault"]` | Token audiences (maps to `aud` claim) |
| `tokenDuration` | duration | `1h` | Requested token lifetime |
| `expectedIssuer` | string | - | Expected `iss` claim value (for pre-flight validation) |
| `expectedAudience` | string | - | Expected `aud` claim value (for pre-flight validation) |
| `userClaim` | string | `sub` | Claim to use for Vault entity alias |
| `groupsClaim` | string | - | Claim containing group membership |
| `claimsToPass` | []string | - | Claims to include in auth response metadata |

#### OIDCAuth

Configures OIDC authentication for workload identity federation. Supports EKS OIDC, Azure AD, GKE, and any OpenID Connect provider.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `role` | string | **Required** | Vault role configured for OIDC auth |
| `authPath` | string | `oidc` | Auth method mount path |
| `providerURL` | string | - | OIDC provider URL (issuer). Examples: `https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE` |
| `useServiceAccountToken` | bool | `true` | Use K8s service account token for OIDC auth |
| `audiences` | []string | `[providerURL]` | Token audiences |
| `tokenDuration` | duration | `1h` | Requested token lifetime |
| `jwtSecretRef` | SecretKeySelector | - | Pre-obtained JWT (alternative to SA token) |
| `userClaim` | string | - | Claim to use for Vault entity alias |
| `groupsClaim` | string | - | Claim containing group membership |
| `scopes` | []string | - | OIDC scopes (for browser-based flows) |

#### AWSAuth

Configures AWS IAM authentication for EKS workloads using IRSA (IAM Roles for Service Accounts) or EC2 instance profiles.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `role` | string | **Required** | Vault role configured for AWS auth |
| `authPath` | string | `aws` | Auth method mount path |
| `authType` | string | `iam` | Auth type: `iam` (recommended) or `ec2` |
| `region` | string | auto-detect | AWS region |
| `stsEndpoint` | string | - | Custom STS endpoint (for private endpoints) |
| `iamServerIdHeaderValue` | string | - | X-Vault-AWS-IAM-Server-ID header value |

#### GCPAuth

Configures GCP IAM authentication for GKE workloads using Workload Identity or service account keys.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `role` | string | **Required** | Vault role configured for GCP auth |
| `authPath` | string | `gcp` | Auth method mount path |
| `authType` | string | `iam` | Auth type: `iam` (recommended) or `gce` |
| `serviceAccountEmail` | string | auto-detect | GCP service account email |
| `credentialsSecretRef` | SecretKeySelector | - | GCP credentials JSON (for non-Workload Identity) |

#### BootstrapAuth

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `secretRef` | SecretKeySelector | **Required** | Reference to secret containing bootstrap token |
| `autoRevoke` | bool | `true` | Revoke bootstrap token after successful setup |
| `cleanupAuthMount` | bool | `false` | Disable auth backend on VaultConnection deletion. WARNING: revokes ALL tokens issued through this auth mount |

#### TLSConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `skipVerify` | bool | `false` | Skip TLS verification (not recommended) |
| `caSecretRef` | SecretKeySelector | - | Reference to CA certificate secret |

### ConnectionDefaults

Optional platform-team knobs inherited by resources referencing this connection.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `authPath` | string | follows the login mount | Auth mount that `VaultRole` / `VaultClusterRole` resources referencing this connection are written to — a bare mount name like `kubernetes-prod` (an `auth/` prefix is tolerated). When unset, roles follow the connection's own login mount (`auth.kubernetes` / `auth.jwt` / `auth.oidc`) |
| `authType` | string | inferred from `authPath` | Backend family (`kubernetes` or `jwt`) of `authPath` when its name alone can't be classified — the mount name must otherwise be `kubernetes`/`jwt` exactly or with a `-`/`_` separator (`jwt-gitlab`). Ignored when `authPath` is unset |
| `driftMode` | string | `detect` | Default drift detection mode for all resources using this connection (`ignore`, `detect`, `correct`) |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | `Pending`, `Syncing`, `Active`, `Conflict`, `Error`, `Deleting` |
| `vaultVersion` | string | Version of connected Vault server |
| `lastHeartbeat` | time | Time of last successful health check |
| `authStatus` | AuthStatus | Authentication-related status information |
| `conditions` | []Condition | Detailed state conditions |
| `message` | string | Additional status information |
| `healthy` | bool | Whether the Vault connection is currently healthy |
| `lastHealthCheck` | time | Timestamp of the last health check attempt |
| `lastHealthyTime` | time | Timestamp of the last successful health check |
| `healthCheckError` | string | Error message from the last failed health check |
| `consecutiveFails` | int | Number of consecutive failed health checks |

### AuthStatus

Authentication-specific status information.

| Field | Type | Description |
|-------|------|-------------|
| `bootstrapComplete` | bool | Whether bootstrap has completed |
| `bootstrapCompletedAt` | time | When bootstrap completed |
| `authMethod` | string | Currently active auth method |
| `tokenExpiration` | time | Current Vault token expiration |
| `tokenAccessor` | string | Vault token accessor for audit trail correlation (not a secret) |
| `tokenLastRenewed` | time | When token was last renewed |
| `tokenRenewalCount` | int | Number of token renewals |
| `tokenReviewerExpiration` | time | When token_reviewer_jwt expires (K8s auth only) |
| `tokenReviewerLastRefresh` | time | When token_reviewer_jwt was last refreshed |

### kubectl Output

```bash
$ kubectl get vaultconnection
NAME            ADDRESS                          PHASE    HEALTHY   VERSION   AGE
vault-primary   https://vault.example.com:8200   Active   true      1.15.0    5d
```

---

## VaultPolicy

Manages namespace-scoped Vault policies.

- **Scope:** Namespaced
- **Short Name:** `vp`
- **Vault Name Format:** `{namespace}-{name}`

### Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: app-secrets
  namespace: my-app
spec:
  connectionRef: vault-primary
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read, list]
      description: "Read application secrets"
```

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connectionRef` | string | Yes | - | Name of VaultConnection to use |
| `rules` | []PolicyRule | Yes | - | List of policy rules (min 1) |
| `conflictPolicy` | string | No | `Fail` | `Fail` or `Adopt` |
| `deletionPolicy` | string | No | `Delete` | `Delete` or `Retain` |
| `enforceNamespaceBoundary` | bool | No | `false` | Require `{{namespace}}` in all paths |

### PolicyRule

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Vault path (supports `{{namespace}}`, `{{name}}`) |
| `capabilities` | []string | `create`, `read`, `update`, `delete`, `list`, `sudo`, `deny` |
| `description` | string | Optional description |
| `parameters` | PolicyParameters | Optional fine-grained parameter constraints |

#### PolicyParameters

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | []string | Allowed parameter values |
| `denied` | []string | Denied parameter values |
| `required` | []string | Required parameters |

### VaultResourceBinding

All synced resources include a `binding` field in their status that acts as a foreign key reference to the Vault resource:

| Field | Type | Description |
|-------|------|-------------|
| `vaultPath` | string | Full API path to the Vault resource (e.g., `sys/policies/acl/prod-my-policy`) |
| `vaultResourceName` | string | Name of the resource in Vault (e.g., `prod-my-policy`) |
| `authMount` | string | Auth mount path (roles only, e.g., `kubernetes`) |
| `boundAt` | time | When the binding was established |
| `bindingVerified` | bool | Whether the binding was verified against Vault |
| `lastVerifiedAt` | time | When the binding was last verified |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | `Pending`, `Syncing`, `Active`, `Conflict`, `Error`, `Deleting` |
| `vaultName` | string | Recorded name of the policy in Vault (`vao.{identity}.{namespace}.{name}`, ADR 0010) — authoritative for cleanup/rename |
| `rulesCount` | int | Number of rules |
| `lastSyncedAt` | time | Time of last successful sync |
| `lastAppliedHash` | string | Hash of the last applied policy content |
| `binding` | VaultResourceBinding | Binding to the Vault resource |
| `driftDetected` | bool | Whether the Vault resource differs from the desired state |
| `effectiveDriftMode` | string | Resolved drift mode (`ignore`, `detect`, `correct`) |
| `driftSummary` | string | Human-readable description of detected drift |

### kubectl Output

```bash
$ kubectl get vaultpolicy -n my-app
NAME          VAULT NAME          PHASE    RULES   AGE
app-secrets   my-app-app-secrets  Active   2       1h
```

---

## VaultClusterPolicy

Manages cluster-wide Vault policies.

- **Scope:** Cluster
- **Short Name:** `vcp`
- **Vault Name Format:** `{name}` (same as resource name)

### Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: shared-secrets-reader
spec:
  connectionRef: vault-primary
  rules:
    - path: "secret/data/shared/*"
      capabilities: [read, list]
      description: "Read shared configuration"
```

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connectionRef` | string | Yes | - | Name of VaultConnection to use |
| `rules` | []PolicyRule | Yes | - | List of policy rules (min 1) |
| `conflictPolicy` | string | No | `Fail` | `Fail` or `Adopt` |
| `deletionPolicy` | string | No | `Delete` | `Delete` or `Retain` |

### Comparison with VaultPolicy

| Feature | VaultPolicy | VaultClusterPolicy |
|---------|-------------|-------------------|
| Scope | Namespaced | Cluster |
| Vault name | `{namespace}-{name}` | `{name}` |
| Variables | `{{namespace}}`, `{{name}}` | `{{name}}` only |
| Namespace boundary | Optional | N/A |

### kubectl Output

```bash
$ kubectl get vaultclusterpolicy
NAME                    VAULT NAME              PHASE    RULES   AGE
shared-secrets-reader   shared-secrets-reader   Active   2       5d
```

---

## VaultRole

Manages namespace-scoped Kubernetes authentication roles in Vault.

- **Scope:** Namespaced
- **Short Name:** `vr`
- **Vault Role Name Format:** `{namespace}-{name}`

!!! warning "Supported auth backends"
    `VaultRole` currently writes role data to **Kubernetes auth** and **JWT auth** mounts only (Vault's OIDC method is the jwt backend). The role spec carries no mount fields — the auth mount and backend family come from the referenced [VaultConnection](#vaultconnection): `spec.defaults.authPath` when set (see [ConnectionDefaults](#connectiondefaults)), otherwise the connection's own login mount (`auth.kubernetes` → kubernetes, `auth.jwt` / `auth.oidc` → jwt). Tracked as [IMPROVEMENTS.md §7](internal/IMPROVEMENTS.md#7-role-backend-coverage-gap).

    Connections whose login method has no role-capable mount (Token, AppRole, AWS, GCP, bootstrap-only) and no `defaults.authPath` are rejected by the admission webhook with a clear error; without webhooks the role parks at `Phase=Error` / `ValidationFailed`. To write roles to a different mount than a role's connection resolves, create a dedicated `VaultConnection` for that mount (e.g. one with `defaults.authPath: jwt-gitlab`).

### Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: app-role
  namespace: my-app
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - default
  policies:
    - kind: VaultPolicy
      name: app-secrets
  tokenTTL: 1h
```

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connectionRef` | string | Yes | - | Name of VaultConnection to use |
| `serviceAccounts` | []string | Yes | - | Service account names (same namespace) |
| `policies` | []PolicyReference | Yes | - | Policies to attach (min 1) |
| `conflictPolicy` | string | No | `Fail` | `Fail` or `Adopt` |
| `deletionPolicy` | string | No | `Delete` | `Delete` or `Retain` |
| `tokenTTL` | duration | No | Vault default | Default token TTL |
| `tokenMaxTTL` | duration | No | Vault default | Maximum token TTL |
| `jwt` | VaultRoleJWTSpec | No | - | JWT-auth-specific overrides (only when the referenced connection resolves to a JWT mount) |

### VaultRoleJWTSpec

Optional sub-object on `VaultRole` / `VaultClusterRole`. Used when the referenced `VaultConnection` resolves to a JWT auth mount — a JWT/OIDC login, or a `defaults.authPath` of jwt family (e.g. `jwt`, `jwt-gitlab`). All fields are optional — defaults are derived from `serviceAccounts` and the referenced `VaultConnection`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `userClaim` | string | `sub` | JWT claim to read as the Vault entity alias |
| `boundAudiences` | []string | From connection or `["https://kubernetes.default.svc.cluster.local"]` | Required `aud` values |
| `boundSubject` | string | `system:serviceaccount:<ns>:<sa>` | Exact `sub` claim match. Mutually exclusive with `boundClaims*` |
| `boundClaims` | map[string]string | - | **Deprecated.** Scalar claim restrictions. Use `boundClaimsList` for new specs |
| `boundClaimsList` | map[string][]string | - | Multi-value claim restrictions, e.g. `ref: ["main","develop"]`. Mutually exclusive with `boundSubject` |
| `boundClaimsType` | string (`string` \| `glob`) | `string` | Match mode for all keys in bound_claims. `glob` enables shell-style wildcards |
| `roleType` | string (`jwt`) | `jwt` | Vault JWT role type |

**Webhook warnings (non-blocking)** fire when `ref` is bound without `ref_type` (tag-spoof guard) or `ref_protected` (unprotected-namesake guard), when `boundClaimsType` is set with no claims, and when a key appears in both `boundClaims` and `boundClaimsList`.

See [JWT for GitLab CI](auth-methods/jwt-gitlab.md) for an end-to-end example.

### PolicyReference

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | `VaultPolicy` or `VaultClusterPolicy` |
| `name` | string | Name of the policy resource |
| `namespace` | string | Namespace (only for VaultPolicy, defaults to same) |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | `Pending`, `Syncing`, `Active`, `Conflict`, `Error`, `Deleting` |
| `vaultRoleName` | string | Recorded name of the role in Vault (`vao.{identity}.{namespace}.{name}`, ADR 0010) — authoritative for cleanup/rename |
| `boundServiceAccounts` | []string | Resolved service account names |
| `resolvedPolicies` | []string | Resolved Vault policy names |

### kubectl Output

```bash
$ kubectl get vaultrole -n my-app
NAME       VAULT ROLE        PHASE    POLICIES                               AGE
app-role   my-app-app-role   Active   ["my-app-app-secrets","shared-reader"] 1h
```

---

## VaultClusterRole

Manages cluster-wide Kubernetes authentication roles in Vault.

- **Scope:** Cluster
- **Short Name:** `vcr`
- **Vault Role Name Format:** `{name}` (same as resource name)

### Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: platform-services
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: platform-controller
      namespace: platform-system
  policies:
    - kind: VaultClusterPolicy
      name: shared-secrets-reader
  tokenTTL: 1h
```

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connectionRef` | string | Yes | - | Name of VaultConnection to use |
| `serviceAccounts` | []ServiceAccountRef | Yes | - | Service accounts with namespace |
| `policies` | []PolicyReference | Yes | - | Policies to attach (min 1) |
| `conflictPolicy` | string | No | `Fail` | `Fail` or `Adopt` |
| `deletionPolicy` | string | No | `Delete` | `Delete` or `Retain` |
| `tokenTTL` | duration | No | Vault default | Default token TTL |
| `tokenMaxTTL` | duration | No | Vault default | Maximum token TTL |
| `jwt` | VaultRoleJWTSpec | No | - | JWT-auth-specific overrides — same fields as [VaultRole.spec.jwt](#vaultrolejwtspec) |

### ServiceAccountRef

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Name of the service account |
| `namespace` | string | Namespace of the service account |

### Comparison with VaultRole

| Feature | VaultRole | VaultClusterRole |
|---------|-----------|-----------------|
| Scope | Namespaced | Cluster |
| Vault role name | `{namespace}-{name}` | `{name}` |
| Service accounts | Same namespace only | Any namespace |

### kubectl Output

```bash
$ kubectl get vaultclusterrole
NAME                VAULT ROLE          PHASE    POLICIES                    AGE
platform-services   platform-services   Active   ["shared-secrets-reader"]   5d
```

---

## VaultKVSecret

Pre-creates ("seeds") a Vault KV v2 secret path so consumers such as External Secrets Operator (ESO) don't fail when the source path is missing on a fresh deployment.

- **Scope:** Namespaced
- **Short Name:** `vks`

The operator follows a strict **create-only-if-absent** model: it writes the path **only when it does not already exist**, and it **never overwrites or reads** the values stored there. Real data written later by ESO or a human is always preserved. On deletion, the operator runs a **delete-if-untouched** check — it removes the seeded secret only if it is still operator-owned and unmodified since seeding; otherwise it retains it.

!!! warning "ESO `.property` references need explicit placeholder keys"
    A literally empty `data: {}` secret unblocks ESO whole-secret references (`spec.dataFrom`), but an ESO `spec.data[].remoteRef.property` reference against a **zero-key** secret still reports a *missing property*. For `.property` refs, seed explicit placeholder keys with empty-string values:

    ```yaml
    data:
      username: ""
      password: ""
    ```

### Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultKVSecret
metadata:
  name: app-config
  namespace: my-app
spec:
  connectionRef: vault-primary
  # Full KV v2 data path; must contain a "/data/" segment and is immutable.
  path: "secret/data/apps/my-app/config"
  # Placeholder content, written ONLY if the path is absent — never overwrites.
  # Omit `data` entirely for a truly empty {} (fine for whole-secret reads).
  data:
    username: ""
    password: ""
  deletionPolicy: Delete
```

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connectionRef` | string | Yes | - | Name of VaultConnection to use |
| `path` | string | Yes | - | Full KV v2 data path, e.g. `secret/data/apps/myapp/config`. **Must** contain a `/data/` segment. **Immutable** after creation (enforced by a CEL validation rule) |
| `data` | map[string]string | No | `{}` | Initial placeholder content, written **only** when the path is absent. Never overwrites an existing secret. Use empty-string placeholder keys for ESO `remoteRef.property` references |
| `deletionPolicy` | string | No | `Delete` | `Delete` (delete-if-untouched) or `Retain` (never delete) — see below |

### Deletion Behavior

For `VaultKVSecret`, the standard `Delete`/`Retain` enum has secret-seeding-specific semantics:

| Policy | Behavior |
|--------|----------|
| `Delete` (default) | **Delete-if-untouched.** On CR deletion, the seeded secret is removed **only if** it is still operator-owned (`custom_metadata.managed-by == vault-access-operator`) **and** its current KV v2 version equals `status.seededVersion` (no writes since seeding). A secret written to since seeding, or owned by someone else, is **retained**. |
| `Retain` | Never delete the seeded secret. |

When the operator seeds a path it stamps the secret's KV v2 `custom_metadata` with `{managed-by: vault-access-operator, k8s-resource: <namespace/name>}` — this ownership marker, plus `status.seededVersion`, drives the delete-if-untouched check. The operator never destroys data it didn't seed or that has been modified since seeding.

!!! note "Operator Vault policy requirement"
    To seed, the operator's own Vault policy needs **`create`-only** on the target `secret/data/*` (NOT `update`, `read`, or `delete`) plus `create`/`read`/`update`/`patch`/`delete`/`list` on `secret/metadata/*`. This is deliberate least-privilege — the operator only ever CREATES secrets, so Vault itself enforces the never-clobber guarantee. In production, scope the `secret/data/*` prefix to the paths you actually seed (e.g. `secret/data/apps/*`). See [Bootstrap Authentication](auth-methods/bootstrap.md) and [Configuration](configuration.md).

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | `Pending`, `Syncing`, `Active`, `Conflict`, `Error`, `Deleting` |
| `vaultPath` | string | Resolved KV v2 data path that was seeded |
| `seeded` | bool | `true` if the operator created this path; `false` if it already existed when first reconciled |
| `seededVersion` | int | KV v2 version the operator created — the baseline for the delete-if-untouched check. Zero when the path pre-existed |
| `message` | string | Additional status information (e.g. "seeded empty secret at … (version 1)" or "already exists; left untouched") |
| `conditions` | []Condition | Detailed state conditions (`Ready`, `Synced`, and `DryRun` when the dry-run annotation is set) |
| `lastSyncedAt` | time | Time of last successful sync |
| `binding` | VaultResourceBinding | Binding to the seeded Vault path |

### Dry Run

Annotate the resource with `vault.platform.io/dry-run=true` to skip the Vault write: the operator surfaces a `DryRun` status condition and a "dry-run: would seed `<path>`" message without creating the secret. Cleanup also skips the delete-if-untouched check while dry-run is active.

### kubectl Output

```bash
$ kubectl get vaultkvsecret -n my-app
NAME         PATH                              PHASE    SEEDED   AGE
app-config   secret/data/apps/my-app/config    Active   true     1h
```

---

## SecretKeySelector

Reference to a key in a Kubernetes Secret (used in multiple CRDs):

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Name of the Secret |
| `namespace` | string | Namespace (defaults to resource namespace) |
| `key` | string | Key within the Secret |

---

## Next Steps

- [Getting Started](getting-started.md) - Installation guide
- [Examples](examples.md) - CRD usage examples
- [Troubleshooting](troubleshooting.md) - Common issues
