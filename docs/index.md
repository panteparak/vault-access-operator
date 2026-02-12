# Vault Access Operator

A Kubernetes operator for managing HashiCorp Vault access policies and Kubernetes authentication roles declaratively through Custom Resource Definitions (CRDs).

## Overview

The Vault Access Operator enables platform teams to manage Vault policies and Kubernetes authentication roles using native Kubernetes resources. It provides a GitOps-friendly approach to Vault access management, allowing teams to version control their Vault configurations alongside their application deployments.

## Key Features

### Access Management

- **Declarative Vault Policy Management** - Define Vault policies as Kubernetes resources
- **Kubernetes Auth Role Management** - Configure Vault Kubernetes authentication roles through CRDs
- **Namespace Boundary Enforcement** - Automatically restrict namespaced policies to their namespace scope
- **Variable Substitution** - Use `{{namespace}}` and `{{name}}` variables in policy paths

### Authentication

- **8 Authentication Methods** - Support for [Kubernetes](auth-methods/kubernetes.md), [JWT](auth-methods/jwt.md), [OIDC](auth-methods/oidc.md), [AWS IAM](auth-methods/aws-iam.md), [GCP IAM](auth-methods/gcp-iam.md), [AppRole](auth-methods/approle.md), [Token](auth-methods/token.md), and [Bootstrap](auth-methods/bootstrap.md)
- **Token Renewal Strategies** - Choose between renew or re-authenticate strategies
- **Automatic Token Management** - Proactive token renewal before expiration

### Operations

- **[Drift Detection](concepts/drift-detection.md)** - Detect and optionally correct configuration drift between K8s and Vault
- **[Resource Discovery](concepts/discovery.md)** - Find unmanaged Vault resources for adoption
- **Conflict Detection and Handling** - Choose between fail-fast or adopt strategies for existing resources
- **Deletion Policies** - Control whether Vault resources are retained or deleted when K8s resources are removed

### Reliability

- **Exponential Backoff Retry** - Intelligent retry with jitter for transient failures
- **Health Monitoring** - Continuous health checks with automatic recovery
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

### Getting Started

- [Getting Started](getting-started.md) - Installation and quick start guide
- [Examples](examples.md) - CRD usage examples

### Concepts

- [Concepts Overview](concepts/index.md) - Core design principles and architecture
- [Architecture](concepts/architecture.md) - Internal structure and reconciliation flow
- [Drift Detection](concepts/drift-detection.md) - Detecting and correcting configuration drift
- [Discovery](concepts/discovery.md) - Finding unmanaged Vault resources

### Authentication Methods

- [Authentication Overview](auth-methods/index.md) - Comparison and decision guide
- [Kubernetes Auth](auth-methods/kubernetes.md) - Standard K8s authentication
- [AWS IAM](auth-methods/aws-iam.md) - EKS with IRSA
- [GCP IAM](auth-methods/gcp-iam.md) - GKE with Workload Identity
- [OIDC](auth-methods/oidc.md) - Workload identity federation
- [JWT](auth-methods/jwt.md) - External JWT providers
- [AppRole](auth-methods/approle.md) - CI/CD pipelines
- [Bootstrap](auth-methods/bootstrap.md) - Initial Vault setup
- [Token](auth-methods/token.md) - Development only

### Reference

- [Configuration](configuration.md) - Helm chart configuration options
- [API Reference](api-reference.md) - Detailed CRD documentation
- [Webhooks](webhooks.md) - Admission webhook documentation
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Community

- [GitHub Repository](https://github.com/panteparak/vault-access-operator)
- [Issue Tracker](https://github.com/panteparak/vault-access-operator/issues)

## License

Copyright 2024-2026 Vault Access Operator Contributors.

Licensed under the Apache License, Version 2.0.
