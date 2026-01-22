# API Reference

This section provides detailed documentation for all Custom Resource Definitions (CRDs) provided by the Vault Access Operator.

## Overview

The Vault Access Operator provides five CRDs organized by scope and purpose:

### Connection Management

| CRD | Scope | Description |
|-----|-------|-------------|
| [VaultConnection](vaultconnection.md) | Cluster | Establishes and manages connections to Vault servers |

### Policy Management

| CRD | Scope | Description |
|-----|-------|-------------|
| [VaultPolicy](vaultpolicy.md) | Namespaced | Manages namespace-scoped Vault policies |
| [VaultClusterPolicy](vaultclusterpolicy.md) | Cluster | Manages cluster-wide Vault policies |

### Role Management

| CRD | Scope | Description |
|-----|-------|-------------|
| [VaultRole](vaultrole.md) | Namespaced | Manages namespace-scoped Kubernetes auth roles |
| [VaultClusterRole](vaultclusterrole.md) | Cluster | Manages cluster-wide Kubernetes auth roles |

## API Group and Version

All CRDs belong to the `vault.platform.io` API group with version `v1alpha1`:

```yaml
apiVersion: vault.platform.io/v1alpha1
```

## Common Concepts

### Connection Reference

All policy and role resources must reference a VaultConnection:

```yaml
spec:
  connectionRef: vault-primary  # Name of VaultConnection
```

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

Example:

```yaml
rules:
  - path: "secret/data/{{namespace}}/{{name}}/*"
    capabilities: [read]
```

### Resource Phases

All resources report their current phase in status:

| Phase | Description |
|-------|-------------|
| `Pending` | Resource is being processed |
| `Active` | Resource is successfully synced to Vault |
| `Failed` | Resource sync failed |
| `Deleting` | Resource is being deleted |

### Conditions

Resources expose detailed conditions for troubleshooting:

| Condition | Description |
|-----------|-------------|
| `Ready` | Resource is ready and synced |
| `Synced` | Last sync operation succeeded |
| `ConnectionReady` | VaultConnection is available |

## Quick Links

- [VaultConnection](vaultconnection.md) - Connect to Vault
- [VaultPolicy](vaultpolicy.md) - Namespace-scoped policies
- [VaultClusterPolicy](vaultclusterpolicy.md) - Cluster-wide policies
- [VaultRole](vaultrole.md) - Namespace-scoped roles
- [VaultClusterRole](vaultclusterrole.md) - Cluster-wide roles
