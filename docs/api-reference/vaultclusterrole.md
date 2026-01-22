# VaultClusterRole

VaultClusterRole manages cluster-wide Kubernetes authentication roles in Vault.

## Overview

- **API Group:** `vault.platform.io`
- **API Version:** `v1alpha1`
- **Kind:** `VaultClusterRole`
- **Scope:** Cluster
- **Short Name:** `vcr`

## Basic Example

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

## Spec Fields

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `connectionRef` | string | Name of the VaultConnection to use |
| `serviceAccounts` | [][ServiceAccountRef](#serviceaccountref) | Service accounts with namespace (minimum 1) |
| `policies` | [][PolicyReference](#policyreference) | Policies to attach (minimum 1) |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `authPath` | string | From VaultConnection | Mount path of Kubernetes auth method |
| `conflictPolicy` | string | `Fail` | How to handle conflicts: `Fail` or `Adopt` |
| `deletionPolicy` | string | `Delete` | What happens on deletion: `Delete` or `Retain` |
| `tokenTTL` | string | Vault default | Default token TTL |
| `tokenMaxTTL` | string | Vault default | Maximum token TTL |

## ServiceAccountRef

Reference to a Kubernetes service account.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Name of the service account |
| `namespace` | string | Namespace of the service account |

## PolicyReference

Reference to a VaultPolicy or VaultClusterPolicy.

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Policy kind: `VaultPolicy` or `VaultClusterPolicy` |
| `name` | string | Name of the policy resource |
| `namespace` | string | Namespace (required for VaultPolicy) |

## Vault Role Naming

Unlike VaultRole, VaultClusterRole uses the resource name directly:

| Kubernetes Resource | Vault Role Name |
|--------------------|-----------------|
| `platform-services` | `platform-services` |
| `cicd-pipeline` | `cicd-pipeline` |

## Comparison with VaultRole

| Feature | VaultRole | VaultClusterRole |
|---------|-----------|-----------------|
| Scope | Namespaced | Cluster |
| Vault name | `{namespace}-{name}` | `{name}` |
| Service accounts | Same namespace (names only) | Any namespace (name + namespace) |
| Use case | Application-specific | Cross-namespace, platform |

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
$ kubectl get vaultclusterrole
NAME                VAULT ROLE          PHASE    POLICIES                    AGE
platform-services   platform-services   Active   ["shared-secrets-reader"]   5d
cicd-pipeline       cicd-pipeline       Active   ["cicd-secrets"]            3d
```

## Examples

### Platform Services Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: platform-services
spec:
  connectionRef: vault-primary
  authPath: auth/kubernetes
  serviceAccounts:
    - name: platform-controller
      namespace: platform-system
    - name: monitoring-agent
      namespace: monitoring
    - name: logging-collector
      namespace: logging
  policies:
    - kind: VaultClusterPolicy
      name: shared-secrets-reader
  tokenTTL: 1h
  tokenMaxTTL: 24h
```

### CI/CD Pipeline Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: cicd-pipeline
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: tekton-pipeline
      namespace: tekton-pipelines
    - name: argo-workflow
      namespace: argo
    - name: github-actions-runner
      namespace: actions-runner-system
  policies:
    - kind: VaultClusterPolicy
      name: cicd-secrets
  tokenTTL: 15m
  tokenMaxTTL: 1h
```

### Mixed Policy Types

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: cross-namespace-reader
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: aggregator
      namespace: data-platform
  policies:
    # Cluster-wide policy
    - kind: VaultClusterPolicy
      name: shared-config-reader

    # Namespace-specific policy from another namespace
    - kind: VaultPolicy
      name: analytics-secrets
      namespace: analytics

    # Another namespace-specific policy
    - kind: VaultPolicy
      name: reporting-secrets
      namespace: reporting
```

### Ingress Controller Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: ingress-controller
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: nginx-ingress-controller
      namespace: ingress-nginx
    - name: traefik
      namespace: traefik
  policies:
    - kind: VaultClusterPolicy
      name: pki-issuer
  tokenTTL: 30m
```

### External Secrets Operator Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: external-secrets
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: external-secrets
      namespace: external-secrets
  policies:
    - kind: VaultClusterPolicy
      name: secrets-reader-all
  tokenTTL: 1h
  tokenMaxTTL: 4h
```

### Backup Service Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: backup-service
spec:
  connectionRef: vault-primary
  conflictPolicy: Adopt
  deletionPolicy: Retain
  serviceAccounts:
    - name: velero
      namespace: velero
    - name: backup-agent
      namespace: backup-system
  policies:
    - kind: VaultClusterPolicy
      name: backup-credentials
  tokenTTL: 2h
```

### Service Mesh Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: service-mesh
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: istiod
      namespace: istio-system
    - name: istio-proxy
      namespace: istio-system
  policies:
    - kind: VaultClusterPolicy
      name: pki-issuer
    - kind: VaultClusterPolicy
      name: mesh-config
  tokenTTL: 1h
```

## Authentication Flow

Pods with bound service accounts can authenticate:

```bash
# From a pod in platform-system namespace
vault login -method=kubernetes role=platform-services
```

The Vault Kubernetes auth method verifies:
1. The pod's service account token is valid
2. The service account (name + namespace) is bound to the role
3. The role exists and has associated policies

## See Also

- [VaultRole](vaultrole.md) - Namespace-scoped roles
- [VaultClusterPolicy](vaultclusterpolicy.md) - Cluster-wide policies
- [Configuration Examples](../configuration/examples.md) - More examples
