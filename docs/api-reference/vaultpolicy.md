# VaultPolicy

VaultPolicy manages namespace-scoped Vault policies through Kubernetes resources.

## Overview

- **API Group:** `vault.platform.io`
- **API Version:** `v1alpha1`
- **Kind:** `VaultPolicy`
- **Scope:** Namespaced
- **Short Name:** `vp`

## Basic Example

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

## Spec Fields

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `connectionRef` | string | Name of the VaultConnection to use |
| `rules` | [][PolicyRule](#policyrule) | List of policy rules (minimum 1) |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `conflictPolicy` | string | `Fail` | How to handle conflicts: `Fail` or `Adopt` |
| `deletionPolicy` | string | `Delete` | What happens on deletion: `Delete` or `Retain` |
| `enforceNamespaceBoundary` | bool | `false` | Require `{{namespace}}` in all paths |

## PolicyRule

Defines a single rule in the Vault policy.

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Vault path (supports `{{namespace}}` and `{{name}}` variables) |
| `capabilities` | []string | Capabilities to grant: `create`, `read`, `update`, `delete`, `list`, `sudo`, `deny` |
| `description` | string | Optional description of the rule |
| `parameters` | [PolicyParameters](#policyparameters) | Optional fine-grained parameter constraints |

### PolicyParameters

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | []string | Allowed parameter values |
| `denied` | []string | Denied parameter values |
| `required` | []string | Required parameters |

## Variable Substitution

VaultPolicy supports variable substitution in paths:

| Variable | Value | Example |
|----------|-------|---------|
| `{{namespace}}` | Kubernetes namespace | `my-app` |
| `{{name}}` | Resource name | `app-secrets` |

Example:

```yaml
rules:
  - path: "secret/data/{{namespace}}/{{name}}/*"
    capabilities: [read]
```

For a VaultPolicy named `app-secrets` in namespace `my-app`, this becomes:
`secret/data/my-app/app-secrets/*`

## Namespace Boundary Enforcement

When `enforceNamespaceBoundary: true`, all paths must contain the `{{namespace}}` variable. This prevents namespace-scoped policies from accessing secrets outside their namespace.

```yaml
spec:
  enforceNamespaceBoundary: true
  rules:
    # Valid - contains {{namespace}}
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read]

    # Invalid - would fail validation
    # - path: "secret/data/other-namespace/*"
    #   capabilities: [read]
```

## Vault Policy Naming

The Vault policy name is automatically generated as `{namespace}-{name}`:

| Kubernetes Resource | Vault Policy Name |
|--------------------|-------------------|
| `my-app/app-secrets` | `my-app-app-secrets` |
| `production/database` | `production-database` |

## Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase: `Pending`, `Syncing`, `Active`, `Conflict`, `Error`, `Deleting` |
| `vaultName` | string | Name of the policy in Vault |
| `managed` | bool | Whether the policy is managed by the operator |
| `rulesCount` | int | Number of rules in the policy |
| `lastAppliedHash` | string | Hash of the last applied spec |
| `lastSyncedAt` | time | Time of last successful sync |
| `lastAttemptAt` | time | Time of last sync attempt |
| `retryCount` | int | Number of retry attempts |
| `nextRetryAt` | time | Time of next retry |
| `message` | string | Additional state information |
| `conditions` | []Condition | Detailed conditions |

## kubectl Output

```bash
$ kubectl get vaultpolicy -n my-app
NAME          VAULT NAME          PHASE    RULES   AGE
app-secrets   my-app-app-secrets  Active   2       1h
```

## Examples

### Read-Only Secrets Access

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: secrets-reader
  namespace: my-app
spec:
  connectionRef: vault-primary
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read, list]
```

### Full CRUD Access

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: secrets-admin
  namespace: my-app
spec:
  connectionRef: vault-primary
  enforceNamespaceBoundary: true
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [create, read, update, delete, list]
    - path: "secret/metadata/{{namespace}}/*"
      capabilities: [read, list, delete]
```

### Transit Encryption

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: transit-user
  namespace: my-app
spec:
  connectionRef: vault-primary
  rules:
    - path: "transit/encrypt/{{namespace}}-key"
      capabilities: [update]
      description: "Encrypt data"
    - path: "transit/decrypt/{{namespace}}-key"
      capabilities: [update]
      description: "Decrypt data"
```

### Retain on Delete

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: persistent-policy
  namespace: my-app
spec:
  connectionRef: vault-primary
  deletionPolicy: Retain  # Keep in Vault when K8s resource is deleted
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read]
```

### Adopt Existing Policy

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: existing-policy
  namespace: my-app
spec:
  connectionRef: vault-primary
  conflictPolicy: Adopt  # Take over management of existing Vault policy
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read]
```

## See Also

- [VaultClusterPolicy](vaultclusterpolicy.md) - Cluster-wide policies
- [VaultRole](vaultrole.md) - Bind policies to service accounts
- [Configuration Examples](../configuration/examples.md) - More examples
