# CRD Reference

This document provides detailed reference documentation for all Custom Resource Definitions (CRDs) provided by the Vault Access Operator.

## Table of Contents

- [VaultConnection](#vaultconnection)
- [VaultClusterPolicy](#vaultclusterpolicy)
- [VaultPolicy](#vaultpolicy)
- [VaultClusterRole](#vaultclusterrole)
- [VaultRole](#vaultrole)
- [Common Types](#common-types)

---

## VaultConnection

**API Version:** `vault.platform.io/v1alpha1`
**Kind:** `VaultConnection`
**Scope:** Cluster

VaultConnection establishes and maintains a connection to a HashiCorp Vault server. It handles authentication and provides the connection for other resources to use.

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `address` | string | Yes | - | Vault server address (e.g., `https://vault.example.com:8200`). Must start with `http://` or `https://`. |
| `tls` | [TLSConfig](#tlsconfig) | No | - | TLS configuration for the Vault connection. |
| `auth` | [AuthConfig](#authconfig) | Yes | - | Authentication configuration for Vault. |
| `defaults` | [ConnectionDefaults](#connectiondefaults) | No | - | Default paths for various Vault operations. |
| `healthCheckInterval` | string | No | `30s` | How often to check Vault connectivity (duration format). |

### TLSConfig

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `skipVerify` | boolean | No | `false` | Skip TLS certificate verification. **Not recommended for production.** |
| `caSecretRef` | [SecretKeySelector](#secretkeyselector) | No | - | Reference to a secret containing the CA certificate. |

### AuthConfig

One of the following authentication methods must be configured:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kubernetes` | [KubernetesAuth](#kubernetesauth) | No | Kubernetes auth method configuration. |
| `token` | [TokenAuth](#tokenauth) | No | Token auth method configuration. |
| `appRole` | [AppRoleAuth](#approleauth) | No | AppRole auth method configuration. |

### KubernetesAuth

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `role` | string | Yes | - | Vault role to authenticate as. |
| `mountPath` | string | No | `kubernetes` | Mount path of the Kubernetes auth method. |
| `serviceAccountTokenPath` | string | No | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Path to the service account token. |

### TokenAuth

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `secretRef` | [SecretKeySelector](#secretkeyselector) | Yes | Reference to a secret containing the Vault token. |

### AppRoleAuth

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `roleId` | string | Yes | - | AppRole role ID. |
| `secretIdRef` | [SecretKeySelector](#secretkeyselector) | Yes | - | Reference to a secret containing the AppRole secret ID. |
| `mountPath` | string | No | `approle` | Mount path of the AppRole auth method. |

### ConnectionDefaults

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `secretEnginePath` | string | No | - | Default path for secret engines. |
| `transitPath` | string | No | - | Default path for the transit engine. |
| `authPath` | string | No | `auth/kubernetes` | Default path for auth methods. |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase: `Pending`, `Syncing`, `Active`, `Error`. |
| `vaultVersion` | string | Version of the connected Vault server. |
| `lastHeartbeat` | Time | Time of the last successful health check. |
| `conditions` | [][Condition](#condition) | Latest available observations. |
| `message` | string | Additional information about the current state. |

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
      mountPath: kubernetes
  tls:
    skipVerify: false
    caSecretRef:
      name: vault-ca-cert
      namespace: vault-access-operator-system
      key: ca.crt
  healthCheckInterval: 30s
  defaults:
    authPath: auth/kubernetes
```

---

## VaultClusterPolicy

**API Version:** `vault.platform.io/v1alpha1`
**Kind:** `VaultClusterPolicy`
**Scope:** Cluster
**Short Name:** `vcp`

VaultClusterPolicy manages cluster-wide Vault policies. The policy name in Vault matches the Kubernetes resource name.

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connectionRef` | string | Yes | - | Name of the VaultConnection to use. |
| `conflictPolicy` | string | No | `Fail` | How to handle conflicts: `Fail` or `Adopt`. |
| `rules` | [][PolicyRule](#policyrule) | Yes | - | Policy rules (minimum 1 required). |
| `deletionPolicy` | string | No | `Delete` | What happens when deleted: `Delete` or `Retain`. |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase: `Pending`, `Syncing`, `Active`, `Conflict`, `Error`, `Deleting`. |
| `vaultName` | string | Name of the policy in Vault. |
| `managed` | boolean | Whether this policy is managed by the operator. |
| `rulesCount` | integer | Number of rules in the policy. |
| `lastAppliedHash` | string | Hash of the last applied spec for change detection. |
| `lastSyncedAt` | Time | Time of the last successful sync. |
| `lastAttemptAt` | Time | Time of the last sync attempt. |
| `retryCount` | integer | Number of retry attempts. |
| `nextRetryAt` | Time | Time of the next retry attempt. |
| `message` | string | Additional information about the current state. |
| `conditions` | [][Condition](#condition) | Latest available observations. |

### Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: shared-secrets-reader
spec:
  connectionRef: vault-primary
  conflictPolicy: Fail
  deletionPolicy: Delete
  rules:
    - path: "secret/data/shared/*"
      capabilities: [read, list]
      description: "Read access to shared secrets"
    - path: "secret/metadata/shared/*"
      capabilities: [read, list]
      description: "Read metadata for shared secrets"
    - path: "secret/data/global/config"
      capabilities: [read]
      description: "Read global configuration"
```

---

## VaultPolicy

**API Version:** `vault.platform.io/v1alpha1`
**Kind:** `VaultPolicy`
**Scope:** Namespaced
**Short Name:** `vp`

VaultPolicy manages namespace-scoped Vault policies with optional namespace boundary enforcement. The policy name in Vault follows the format `{namespace}-{name}`.

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connectionRef` | string | Yes | - | Name of the VaultConnection to use. |
| `conflictPolicy` | string | No | `Fail` | How to handle conflicts: `Fail` or `Adopt`. |
| `rules` | [][PolicyRule](#policyrule) | Yes | - | Policy rules (minimum 1 required). |
| `deletionPolicy` | string | No | `Delete` | What happens when deleted: `Delete` or `Retain`. |
| `enforceNamespaceBoundary` | boolean | No | `false` | Ensure all paths contain `{{namespace}}` variable. |

### Namespace Boundary Enforcement

When `enforceNamespaceBoundary` is `true`:

1. All paths in rules **must** contain the `{{namespace}}` variable
2. Wildcards (`*`) **cannot** appear before the `{{namespace}}` variable
3. This prevents policies from accidentally granting access to other namespaces

**Valid paths:**
- `secret/data/{{namespace}}/*`
- `secret/data/{{namespace}}/{{name}}/*`
- `kv/data/apps/{{namespace}}/config`

**Invalid paths (when enforcement is enabled):**
- `secret/data/*` (missing `{{namespace}}`)
- `secret/*/{{namespace}}/data` (wildcard before namespace)

### Variable Substitution

The following variables are substituted when the policy is applied:

| Variable | Description | Example |
|----------|-------------|---------|
| `{{namespace}}` | Kubernetes namespace of the VaultPolicy | `my-app` |
| `{{name}}` | Name of the VaultPolicy resource | `app-secrets` |

### Status Fields

Same as [VaultClusterPolicy Status](#status-fields-1).

### Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: app-secrets
  namespace: my-app
spec:
  connectionRef: vault-primary
  enforceNamespaceBoundary: true
  conflictPolicy: Fail
  deletionPolicy: Delete
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read, list]
      description: "Read secrets for this namespace"
    - path: "secret/data/{{namespace}}/{{name}}/*"
      capabilities: [create, read, update, delete, list]
      description: "Full access to app-specific secrets"
    - path: "database/creds/{{namespace}}-db"
      capabilities: [read]
      description: "Read database credentials"
```

This creates a policy named `my-app-app-secrets` in Vault with paths:
- `secret/data/my-app/*`
- `secret/data/my-app/app-secrets/*`
- `database/creds/my-app-db`

---

## VaultClusterRole

**API Version:** `vault.platform.io/v1alpha1`
**Kind:** `VaultClusterRole`
**Scope:** Cluster
**Short Name:** `vcr`

VaultClusterRole manages cluster-wide Kubernetes auth roles in Vault. It can bind service accounts from any namespace to policies.

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connectionRef` | string | Yes | - | Name of the VaultConnection to use. |
| `authPath` | string | No | - | Mount path of the Kubernetes auth method. Uses VaultConnection default if not set. |
| `conflictPolicy` | string | No | `Fail` | How to handle conflicts: `Fail` or `Adopt`. |
| `serviceAccounts` | [][ServiceAccountRef](#serviceaccountref) | Yes | - | Service accounts that can use this role (minimum 1 required). |
| `policies` | [][PolicyReference](#policyreference) | Yes | - | Policies to attach to this role (minimum 1 required). |
| `tokenTTL` | string | No | - | Default TTL for tokens (e.g., `1h`, `30m`). |
| `tokenMaxTTL` | string | No | - | Maximum TTL for tokens. |
| `deletionPolicy` | string | No | `Delete` | What happens when deleted: `Delete` or `Retain`. |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase: `Pending`, `Syncing`, `Active`, `Conflict`, `Error`, `Deleting`. |
| `vaultRoleName` | string | Name of the role in Vault. |
| `managed` | boolean | Whether this role is managed by the operator. |
| `boundServiceAccounts` | []string | List of service accounts bound to this role. |
| `resolvedPolicies` | []string | List of resolved Vault policy names. |
| `lastSyncedAt` | Time | Time of the last successful sync. |
| `lastAttemptAt` | Time | Time of the last sync attempt. |
| `retryCount` | integer | Number of retry attempts. |
| `nextRetryAt` | Time | Time of the next retry attempt. |
| `message` | string | Additional information about the current state. |
| `conditions` | [][Condition](#condition) | Latest available observations. |

### Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: platform-services
spec:
  connectionRef: vault-primary
  authPath: auth/kubernetes
  conflictPolicy: Fail
  deletionPolicy: Delete
  serviceAccounts:
    - name: platform-controller
      namespace: platform-system
    - name: monitoring-agent
      namespace: monitoring
    - name: backup-operator
      namespace: backup-system
  policies:
    - kind: VaultClusterPolicy
      name: shared-secrets-reader
    - kind: VaultClusterPolicy
      name: platform-admin
  tokenTTL: 1h
  tokenMaxTTL: 24h
```

---

## VaultRole

**API Version:** `vault.platform.io/v1alpha1`
**Kind:** `VaultRole`
**Scope:** Namespaced
**Short Name:** `vr`

VaultRole manages namespace-scoped Kubernetes auth roles. Service accounts are restricted to the same namespace. The role name in Vault follows the format `{namespace}-{name}`.

### Spec Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connectionRef` | string | Yes | - | Name of the VaultConnection to use. |
| `authPath` | string | No | - | Mount path of the Kubernetes auth method. Uses VaultConnection default if not set. |
| `conflictPolicy` | string | No | `Fail` | How to handle conflicts: `Fail` or `Adopt`. |
| `serviceAccounts` | []string | Yes | - | Service account names in the same namespace (minimum 1 required). |
| `policies` | [][PolicyReference](#policyreference) | Yes | - | Policies to attach to this role (minimum 1 required). |
| `tokenTTL` | string | No | - | Default TTL for tokens (e.g., `1h`, `30m`). |
| `tokenMaxTTL` | string | No | - | Maximum TTL for tokens. |
| `deletionPolicy` | string | No | `Delete` | What happens when deleted: `Delete` or `Retain`. |

### Policy Resolution

When referencing policies:

- **VaultPolicy**: If no namespace is specified, defaults to the VaultRole's namespace. The resolved Vault policy name is `{policyNamespace}-{policyName}`.
- **VaultClusterPolicy**: Namespace is ignored. The resolved Vault policy name matches the VaultClusterPolicy name.

### Status Fields

Same as [VaultClusterRole Status](#status-fields-3).

### Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: app-role
  namespace: my-app
spec:
  connectionRef: vault-primary
  conflictPolicy: Fail
  deletionPolicy: Delete
  serviceAccounts:
    - default
    - app-service-account
    - worker-sa
  policies:
    - kind: VaultPolicy
      name: app-secrets
      # namespace defaults to my-app, resolves to: my-app-app-secrets
    - kind: VaultPolicy
      name: shared-policy
      namespace: shared
      # resolves to: shared-shared-policy
    - kind: VaultClusterPolicy
      name: shared-secrets-reader
      # resolves to: shared-secrets-reader
  tokenTTL: 1h
  tokenMaxTTL: 4h
```

This creates a role named `my-app-app-role` in Vault.

---

## Common Types

### PolicyRule

Defines a single policy rule for Vault.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | Yes | Path in Vault to apply the rule to. Pattern: `^[a-zA-Z0-9/_*{}\-+]+$` |
| `capabilities` | []string | Yes | Capabilities to grant on this path. |
| `description` | string | No | Human-readable description of this rule. |
| `parameters` | [PolicyParameters](#policyparameters) | No | Fine-grained parameter control. |

#### Valid Capabilities

| Capability | Description |
|------------|-------------|
| `create` | Create new data |
| `read` | Read data |
| `update` | Update existing data |
| `delete` | Delete data |
| `list` | List paths |
| `sudo` | Perform privileged operations |
| `deny` | Explicitly deny access (takes precedence) |

### PolicyParameters

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | []string | Allowed parameter values. |
| `denied` | []string | Denied parameter values. |
| `required` | []string | Required parameters. |

### SecretKeySelector

References a key in a Kubernetes Secret.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Name of the secret. |
| `namespace` | string | No | Resource's namespace | Namespace of the secret. |
| `key` | string | Yes | - | Key in the secret to select. |

### ServiceAccountRef

References a Kubernetes ServiceAccount.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Name of the service account. |
| `namespace` | string | Yes | Namespace of the service account. |

### PolicyReference

References a VaultPolicy or VaultClusterPolicy.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `kind` | string | Yes | - | Kind of the policy: `VaultPolicy` or `VaultClusterPolicy`. |
| `name` | string | Yes | - | Name of the policy. |
| `namespace` | string | No | Referencing resource's namespace | Namespace of the policy (only for VaultPolicy). |

### Condition

Represents the status condition of a resource.

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Type of condition: `Ready`, `Synced`, `ConnectionReady`, `PoliciesResolved`. |
| `status` | string | Status: `True`, `False`, `Unknown`. |
| `lastTransitionTime` | Time | Last time the condition transitioned. |
| `reason` | string | Reason for the condition's last transition. |
| `message` | string | Human-readable explanation. |
| `observedGeneration` | integer | Generation observed by the controller. |

#### Condition Types

| Type | Description |
|------|-------------|
| `Ready` | Resource is fully reconciled and ready. |
| `Synced` | Resource has been synced to Vault. |
| `ConnectionReady` | VaultConnection is available and healthy. |
| `PoliciesResolved` | All referenced policies have been resolved. |

#### Condition Reasons

| Reason | Description |
|--------|-------------|
| `Succeeded` | Operation completed successfully. |
| `Failed` | Operation failed. |
| `InProgress` | Operation is in progress. |
| `Conflict` | Conflict with existing Vault resource. |
| `ValidationFailed` | Validation failed. |
| `ConnectionNotReady` | VaultConnection is not ready. |
| `PolicyNotFound` | Referenced policy was not found. |

---

## Conflict and Deletion Policies

### ConflictPolicy

Controls how the operator handles conflicts with existing Vault resources.

| Value | Description |
|-------|-------------|
| `Fail` | Fail if the resource already exists in Vault and is not managed by this operator. |
| `Adopt` | Take over management of existing resources, even if not previously managed. |

### DeletionPolicy

Controls what happens to Vault resources when the Kubernetes resource is deleted.

| Value | Description |
|-------|-------------|
| `Delete` | Delete the resource from Vault when the K8s resource is deleted. |
| `Retain` | Keep the resource in Vault even after the K8s resource is deleted. |

---

## Resource Phases

All resources go through the following phases:

| Phase | Description |
|-------|-------------|
| `Pending` | Resource is waiting to be processed. |
| `Syncing` | Resource is being synced to Vault. |
| `Active` | Resource has been successfully synced and is active. |
| `Conflict` | Resource has a conflict with an existing Vault resource. |
| `Error` | An error occurred during processing. |
| `Deleting` | Resource is being deleted from Vault. |
