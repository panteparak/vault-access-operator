# Vault Access Operator

A Kubernetes operator for managing HashiCorp Vault access policies and Kubernetes authentication roles declaratively through Custom Resource Definitions (CRDs).

## Overview

The Vault Access Operator enables platform teams to manage Vault policies and Kubernetes authentication roles using native Kubernetes resources. It provides a GitOps-friendly approach to Vault access management, allowing teams to version control their Vault configurations alongside their application deployments.

## Features

- **Declarative Vault Policy Management** - Define Vault policies as Kubernetes resources
- **Kubernetes Auth Role Management** - Configure Vault Kubernetes authentication roles through CRDs
- **Namespace Boundary Enforcement** - Automatically restrict namespaced policies to their namespace scope
- **Multiple Authentication Methods** - Support for Kubernetes, Token, and AppRole authentication
- **Conflict Detection and Handling** - Choose between fail-fast or adopt strategies for existing resources
- **Automatic Policy Generation** - Generate Vault HCL policies from structured rule definitions
- **Variable Substitution** - Use `{{namespace}}` and `{{name}}` variables in policy paths
- **Exponential Backoff Retry** - Intelligent retry with jitter for transient failures
- **Deletion Policies** - Control whether Vault resources are retained or deleted when K8s resources are removed
- **Admission Webhooks** - Validate resources before creation with detailed error messages

## Quick Installation

=== "Helm (Recommended)"

    ```bash
    helm repo add vault-access-operator https://panteparak.github.io/vault-access-operator/charts
    helm install vault-access-operator vault-access-operator/vault-access-operator \
      --namespace vault-access-operator-system \
      --create-namespace
    ```

=== "kubectl"

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/panteparak/vault-access-operator/main/dist/install.yaml
    ```

For detailed installation instructions, see the [Getting Started](getting-started.md) guide.

## Custom Resource Definitions

The operator provides five CRDs for managing Vault access:

| CRD | Scope | Description |
|-----|-------|-------------|
| [VaultConnection](api-reference.md#vaultconnection) | Cluster | Establishes connection to Vault server |
| [VaultClusterPolicy](api-reference.md#vaultclusterpolicy) | Cluster | Manages cluster-wide Vault policies |
| [VaultPolicy](api-reference.md#vaultpolicy) | Namespaced | Manages namespace-scoped Vault policies |
| [VaultClusterRole](api-reference.md#vaultclusterrole) | Cluster | Manages cluster-wide Kubernetes auth roles |
| [VaultRole](api-reference.md#vaultrole) | Namespaced | Manages namespace-scoped Kubernetes auth roles |

## Prerequisites

- Kubernetes cluster (v1.25+)
- HashiCorp Vault server
- cert-manager (for webhook certificates, optional)
- kubectl configured to access your cluster

## Documentation

- [Getting Started](getting-started.md) - Installation and quick start guide
- [Configuration](configuration.md) - Helm chart configuration options
- [API Reference](api-reference.md) - Detailed CRD documentation
- [Examples](examples.md) - CRD usage examples
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Community

- [GitHub Repository](https://github.com/panteparak/vault-access-operator)
- [Issue Tracker](https://github.com/panteparak/vault-access-operator/issues)

## License

Copyright 2024-2026 Vault Access Operator Contributors.

Licensed under the Apache License, Version 2.0.
