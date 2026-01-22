# VaultClusterPolicy

VaultClusterPolicy manages cluster-wide Vault policies through Kubernetes resources.

## Overview

- **API Group:** `vault.platform.io`
- **API Version:** `v1alpha1`
- **Kind:** `VaultClusterPolicy`
- **Scope:** Cluster
- **Short Name:** `vcp`

## Basic Example

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

## PolicyRule

Defines a single rule in the Vault policy.

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Vault path to apply the rule to |
| `capabilities` | []string | Capabilities: `create`, `read`, `update`, `delete`, `list`, `sudo`, `deny` |
| `description` | string | Optional description |
| `parameters` | [PolicyParameters](#policyparameters) | Optional parameter constraints |

### PolicyParameters

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | []string | Allowed parameter values |
| `denied` | []string | Denied parameter values |
| `required` | []string | Required parameters |

## Vault Policy Naming

Unlike VaultPolicy, VaultClusterPolicy uses the resource name directly as the Vault policy name:

| Kubernetes Resource | Vault Policy Name |
|--------------------|-------------------|
| `shared-secrets-reader` | `shared-secrets-reader` |
| `platform-admin` | `platform-admin` |

## Comparison with VaultPolicy

| Feature | VaultPolicy | VaultClusterPolicy |
|---------|-------------|-------------------|
| Scope | Namespaced | Cluster |
| Vault name format | `{namespace}-{name}` | `{name}` |
| Variable substitution | `{{namespace}}`, `{{name}}` | `{{name}}` only |
| Namespace boundary | Optional enforcement | N/A |
| Use case | Application-specific | Shared/platform-wide |

## Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase: `Pending`, `Syncing`, `Active`, `Conflict`, `Error`, `Deleting` |
| `vaultName` | string | Name of the policy in Vault |
| `managed` | bool | Whether managed by the operator |
| `rulesCount` | int | Number of rules |
| `lastAppliedHash` | string | Hash of last applied spec |
| `lastSyncedAt` | time | Time of last successful sync |
| `lastAttemptAt` | time | Time of last sync attempt |
| `retryCount` | int | Retry attempt count |
| `nextRetryAt` | time | Time of next retry |
| `message` | string | Additional information |
| `conditions` | []Condition | Detailed conditions |

## kubectl Output

```bash
$ kubectl get vaultclusterpolicy
NAME                    VAULT NAME              PHASE    RULES   AGE
shared-secrets-reader   shared-secrets-reader   Active   2       5d
platform-admin          platform-admin          Active   3       5d
```

## Examples

### Shared Configuration Reader

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: shared-config-reader
spec:
  connectionRef: vault-primary
  rules:
    - path: "secret/data/shared/*"
      capabilities: [read, list]
      description: "Read shared configuration"
    - path: "secret/data/global/config"
      capabilities: [read]
      description: "Read global config"
```

### Platform Administrator

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: platform-admin
spec:
  connectionRef: vault-primary
  conflictPolicy: Fail
  deletionPolicy: Delete
  rules:
    - path: "secret/*"
      capabilities: [create, read, update, delete, list]
      description: "Full access to secrets"
    - path: "auth/kubernetes/role/*"
      capabilities: [read, list]
      description: "Read auth roles"
    - path: "sys/policies/acl/*"
      capabilities: [read, list]
      description: "Read policies"
```

### CI/CD Pipeline Secrets

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: cicd-secrets
spec:
  connectionRef: vault-primary
  rules:
    - path: "secret/data/cicd/*"
      capabilities: [read, list]
      description: "Read CI/CD secrets"
    - path: "secret/data/docker-registry"
      capabilities: [read]
      description: "Docker registry credentials"
    - path: "secret/data/npm-token"
      capabilities: [read]
      description: "NPM authentication token"
```

### PKI Certificate Issuer

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: pki-issuer
spec:
  connectionRef: vault-primary
  rules:
    - path: "pki/issue/internal"
      capabilities: [create, update]
      description: "Issue internal certificates"
    - path: "pki/ca/pem"
      capabilities: [read]
      description: "Read CA certificate"
```

### Database Credentials Reader

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: database-readonly
spec:
  connectionRef: vault-primary
  rules:
    - path: "database/creds/readonly"
      capabilities: [read]
      description: "Generate readonly database credentials"
```

### Retain Policy on Delete

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: critical-policy
spec:
  connectionRef: vault-primary
  deletionPolicy: Retain  # Keep in Vault even when K8s resource is deleted
  rules:
    - path: "secret/data/critical/*"
      capabilities: [read]
```

## See Also

- [VaultPolicy](vaultpolicy.md) - Namespace-scoped policies
- [VaultClusterRole](vaultclusterrole.md) - Bind cluster policies to service accounts
- [Configuration Examples](../configuration/examples.md) - More examples
