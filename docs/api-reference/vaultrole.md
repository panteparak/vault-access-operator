# VaultRole

VaultRole manages namespace-scoped Kubernetes authentication roles in Vault.

## Overview

- **API Group:** `vault.platform.io`
- **API Version:** `v1alpha1`
- **Kind:** `VaultRole`
- **Scope:** Namespaced
- **Short Name:** `vr`

## Basic Example

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

## Spec Fields

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `connectionRef` | string | Name of the VaultConnection to use |
| `serviceAccounts` | []string | Service account names in the same namespace (minimum 1) |
| `policies` | [][PolicyReference](#policyreference) | Policies to attach (minimum 1) |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `authPath` | string | From VaultConnection | Mount path of Kubernetes auth method |
| `conflictPolicy` | string | `Fail` | How to handle conflicts: `Fail` or `Adopt` |
| `deletionPolicy` | string | `Delete` | What happens on deletion: `Delete` or `Retain` |
| `tokenTTL` | string | Vault default | Default token TTL |
| `tokenMaxTTL` | string | Vault default | Maximum token TTL |

## PolicyReference

Reference to a VaultPolicy or VaultClusterPolicy.

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Policy kind: `VaultPolicy` or `VaultClusterPolicy` |
| `name` | string | Name of the policy resource |
| `namespace` | string | Namespace (only for VaultPolicy, defaults to same namespace) |

## Vault Role Naming

The Vault role name is automatically generated as `{namespace}-{name}`:

| Kubernetes Resource | Vault Role Name |
|--------------------|-----------------|
| `my-app/app-role` | `my-app-app-role` |
| `production/api` | `production-api` |

## Service Account Binding

VaultRole binds service accounts from the **same namespace** to Vault policies:

```yaml
spec:
  serviceAccounts:
    - default        # my-app/default
    - app-sa         # my-app/app-sa
    - worker-sa      # my-app/worker-sa
```

All listed service accounts will be able to authenticate to Vault using the role.

## Mixed Policy Types

VaultRole can reference both namespace-scoped and cluster-wide policies:

```yaml
spec:
  policies:
    # Namespace-scoped policy (same namespace)
    - kind: VaultPolicy
      name: app-secrets

    # Cluster-wide policy
    - kind: VaultClusterPolicy
      name: shared-secrets-reader
```

## Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase: `Pending`, `Syncing`, `Active`, `Conflict`, `Error`, `Deleting` |
| `vaultRoleName` | string | Name of the role in Vault |
| `managed` | bool | Whether managed by the operator |
| `boundServiceAccounts` | []string | Resolved service account names |
| `resolvedPolicies` | []string | Resolved Vault policy names |
| `lastSyncedAt` | time | Time of last successful sync |
| `lastAttemptAt` | time | Time of last sync attempt |
| `retryCount` | int | Retry attempt count |
| `nextRetryAt` | time | Time of next retry |
| `message` | string | Additional information |
| `conditions` | []Condition | Detailed conditions |

## kubectl Output

```bash
$ kubectl get vaultrole -n my-app
NAME       VAULT ROLE        PHASE    POLICIES                                    AGE
app-role   my-app-app-role   Active   ["my-app-app-secrets","shared-reader"]     1h
```

## Examples

### Basic Application Role

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
  tokenMaxTTL: 4h
```

### Multiple Service Accounts

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: backend-services
  namespace: my-app
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - api-server
    - worker
    - scheduler
  policies:
    - kind: VaultPolicy
      name: backend-secrets
  tokenTTL: 30m
```

### Mixed Policy Types

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: full-access
  namespace: my-app
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - default
  policies:
    # Application-specific secrets
    - kind: VaultPolicy
      name: app-secrets

    # Shared configuration
    - kind: VaultClusterPolicy
      name: shared-config-reader

    # Database credentials
    - kind: VaultClusterPolicy
      name: database-readonly
  tokenTTL: 1h
```

### Short-lived Tokens

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: batch-job
  namespace: batch
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - batch-runner
  policies:
    - kind: VaultPolicy
      name: batch-secrets
  tokenTTL: 5m
  tokenMaxTTL: 15m
```

### Adopt Existing Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: legacy-role
  namespace: my-app
spec:
  connectionRef: vault-primary
  conflictPolicy: Adopt  # Take over existing Vault role
  serviceAccounts:
    - default
  policies:
    - kind: VaultPolicy
      name: app-secrets
```

### Custom Auth Path

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: custom-auth
  namespace: my-app
spec:
  connectionRef: vault-primary
  authPath: auth/kubernetes-prod  # Non-default auth mount
  serviceAccounts:
    - default
  policies:
    - kind: VaultPolicy
      name: app-secrets
```

## Authentication Flow

Once a VaultRole is created, pods can authenticate to Vault:

```bash
# Inside a pod with the bound service account
vault login -method=kubernetes role=my-app-app-role
```

Or programmatically:

```go
// Using vault/api
config := vault.DefaultConfig()
client, _ := vault.NewClient(config)

secret, _ := client.Logical().Write("auth/kubernetes/login", map[string]interface{}{
    "role": "my-app-app-role",
    "jwt":  serviceAccountToken,
})
```

## See Also

- [VaultClusterRole](vaultclusterrole.md) - Cluster-wide roles
- [VaultPolicy](vaultpolicy.md) - Namespace-scoped policies
- [Quick Start](../quickstart.md) - Getting started guide
