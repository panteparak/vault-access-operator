# VaultConnection

VaultConnection establishes and manages a connection between the operator and a HashiCorp Vault server.

## Overview

- **API Group:** `vault.platform.io`
- **API Version:** `v1alpha1`
- **Kind:** `VaultConnection`
- **Scope:** Cluster
- **Short Name:** N/A

## Basic Example

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

## Spec Fields

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Vault server address (e.g., `https://vault.example.com:8200`). Must start with `http://` or `https://`. |
| `auth` | [AuthConfig](#authconfig) | Authentication configuration for connecting to Vault |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tls` | [TLSConfig](#tlsconfig) | - | TLS configuration for secure connections |
| `defaults` | [ConnectionDefaults](#connectiondefaults) | - | Default paths for Vault operations |
| `healthCheckInterval` | string | `30s` | How often to check Vault connectivity |

## AuthConfig

Defines how the operator authenticates to Vault. Multiple authentication methods are supported:

| Field | Type | Description |
|-------|------|-------------|
| `bootstrap` | [BootstrapAuth](#bootstrapauth) | One-time bootstrap authentication |
| `kubernetes` | [KubernetesAuth](#kubernetesauth) | Kubernetes service account authentication |
| `token` | [TokenAuth](#tokenauth) | Static token authentication |
| `appRole` | [AppRoleAuth](#approleauth) | AppRole authentication |

!!! note "Authentication Priority"
    If `bootstrap` is configured, the operator uses the bootstrap token initially to set up Kubernetes auth, then switches to Kubernetes auth for subsequent operations.

### KubernetesAuth

Recommended authentication method using Kubernetes service accounts.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `role` | string | **Required** | Vault role to authenticate as |
| `authPath` | string | `kubernetes` | Mount path of the Kubernetes auth method |
| `tokenDuration` | duration | `1h` | Requested service account token lifetime |
| `tokenReviewerRotation` | bool | `true` | Enable automatic token_reviewer_jwt rotation |

Example:

```yaml
auth:
  kubernetes:
    role: vault-access-operator
    authPath: kubernetes
    tokenDuration: 1h
```

### BootstrapAuth

One-time authentication for initial setup of Kubernetes auth.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `secretRef` | [SecretKeySelector](#secretkeyselector) | **Required** | Reference to bootstrap token secret |
| `autoRevoke` | bool | `true` | Revoke bootstrap token after setup |

Example:

```yaml
auth:
  bootstrap:
    secretRef:
      name: vault-bootstrap-token
      namespace: vault-access-operator-system
      key: token
    autoRevoke: true
  kubernetes:
    role: vault-access-operator
```

### TokenAuth

Static token authentication (not recommended for production).

| Field | Type | Description |
|-------|------|-------------|
| `secretRef` | [SecretKeySelector](#secretkeyselector) | Reference to token secret |

### AppRoleAuth

AppRole authentication method.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `roleId` | string | **Required** | AppRole role ID |
| `secretIdRef` | [SecretKeySelector](#secretkeyselector) | **Required** | Reference to secret ID |
| `mountPath` | string | `approle` | Mount path of AppRole auth method |

## TLSConfig

TLS settings for secure Vault connections.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `skipVerify` | bool | `false` | Skip TLS certificate verification (not recommended) |
| `caSecretRef` | [SecretKeySelector](#secretkeyselector) | - | Reference to CA certificate secret |

Example:

```yaml
tls:
  skipVerify: false
  caSecretRef:
    name: vault-ca-cert
    namespace: vault-access-operator-system
    key: ca.crt
```

## ConnectionDefaults

Default paths for Vault operations.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `secretEnginePath` | string | - | Default secret engine path |
| `transitPath` | string | - | Default transit engine path |
| `authPath` | string | `auth/kubernetes` | Default auth method path |

## SecretKeySelector

Reference to a key in a Kubernetes Secret.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Name of the Secret |
| `namespace` | string | Namespace of the Secret (optional, defaults to resource namespace) |
| `key` | string | Key within the Secret |

## Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase: `Pending`, `Active`, `Error`, `Deleting` |
| `vaultVersion` | string | Version of the connected Vault server |
| `lastHeartbeat` | time | Time of last successful health check |
| `message` | string | Additional information about current state |
| `conditions` | []Condition | Detailed condition information |
| `authStatus` | [AuthStatus](#authstatus) | Authentication-related status |

### AuthStatus

| Field | Type | Description |
|-------|------|-------------|
| `bootstrapComplete` | bool | Whether bootstrap has completed |
| `bootstrapCompletedAt` | time | When bootstrap was completed |
| `authMethod` | string | Currently active auth method |
| `tokenExpiration` | time | When current Vault token expires |
| `tokenLastRenewed` | time | When token was last renewed |
| `tokenRenewalCount` | int | Number of token renewals |
| `tokenReviewerExpiration` | time | When token_reviewer_jwt expires |
| `tokenReviewerLastRefresh` | time | When token_reviewer_jwt was last refreshed |

## kubectl Output

```bash
$ kubectl get vaultconnection
NAME            ADDRESS                          PHASE    VERSION   AGE
vault-primary   https://vault.example.com:8200   Active   1.15.0    5d
```

## Full Example

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-primary
spec:
  address: https://vault.example.com:8200
  auth:
    bootstrap:
      secretRef:
        name: vault-bootstrap-token
        namespace: vault-access-operator-system
        key: token
      autoRevoke: true
    kubernetes:
      role: vault-access-operator
      authPath: kubernetes
      tokenDuration: 1h
      tokenReviewerRotation: true
  tls:
    skipVerify: false
    caSecretRef:
      name: vault-ca-cert
      namespace: vault-access-operator-system
      key: ca.crt
  defaults:
    authPath: auth/kubernetes
    secretEnginePath: secret
  healthCheckInterval: 30s
```

## See Also

- [Quick Start](../quickstart.md) - Getting started guide
- [VaultPolicy](vaultpolicy.md) - Namespace-scoped policies
- [VaultRole](vaultrole.md) - Namespace-scoped roles
