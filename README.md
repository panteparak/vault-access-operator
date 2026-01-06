# Vault Access Operator

A Kubernetes operator for managing HashiCorp Vault access policies and Kubernetes authentication roles declaratively through Custom Resource Definitions (CRDs).

## Overview

The Vault Access Operator enables platform teams to manage Vault policies and Kubernetes authentication roles using native Kubernetes resources. It provides a GitOps-friendly approach to Vault access management, allowing teams to version control their Vault configurations alongside their application deployments.

## Features

- **Declarative Vault Policy Management**: Define Vault policies as Kubernetes resources
- **Kubernetes Auth Role Management**: Configure Vault Kubernetes authentication roles through CRDs
- **Namespace Boundary Enforcement**: Automatically restrict namespaced policies to their namespace scope
- **Multiple Authentication Methods**: Support for Kubernetes, Token, and AppRole authentication
- **Conflict Detection and Handling**: Choose between fail-fast or adopt strategies for existing resources
- **Automatic Policy Generation**: Generate Vault HCL policies from structured rule definitions
- **Variable Substitution**: Use `{{namespace}}` and `{{name}}` variables in policy paths
- **Exponential Backoff Retry**: Intelligent retry with jitter for transient failures
- **Deletion Policies**: Control whether Vault resources are retained or deleted when K8s resources are removed
- **Admission Webhooks**: Validate resources before creation with detailed error messages

## Quick Start

### Prerequisites

- Kubernetes cluster (v1.25+)
- HashiCorp Vault server with Kubernetes auth method enabled
- cert-manager (for webhook certificates)
- kubectl configured to access your cluster

### Installation

#### Using Helm (Recommended)

```bash
# Add the Helm repository
helm repo add vault-access-operator https://panteparak.github.io/vault-access-operator

# Install the operator
helm install vault-access-operator vault-access-operator/vault-access-operator \
  --namespace vault-access-operator-system \
  --create-namespace
```

#### Using kubectl

```bash
# Install CRDs and operator
kubectl apply -f https://raw.githubusercontent.com/panteparak/vault-access-operator/main/dist/install.yaml
```

#### From Source

```bash
# Clone the repository
git clone https://github.com/panteparak/vault-access-operator.git
cd vault-access-operator

# Install CRDs
make install

# Deploy the operator
make deploy IMG=ghcr.io/panteparak/vault-access-operator:latest
```

### Basic Usage

#### 1. Create a VaultConnection

First, establish a connection to your Vault server:

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
```

#### 2. Create a VaultClusterPolicy

Define a cluster-wide Vault policy:

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
```

#### 3. Create a VaultPolicy

Define a namespace-scoped Vault policy with namespace boundary enforcement:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: app-secrets
  namespace: my-app
spec:
  connectionRef: vault-primary
  enforceNamespaceBoundary: true  # Optional: enforce namespace isolation (default: false)
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read, list]
      description: "Read secrets for this namespace"
    - path: "secret/data/{{namespace}}/{{name}}/*"
      capabilities: [create, read, update, delete, list]
      description: "Full access to app-specific secrets"
```

#### 4. Create a VaultClusterRole

Bind service accounts to policies cluster-wide:

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
  policies:
    - kind: VaultClusterPolicy
      name: shared-secrets-reader
  tokenTTL: 1h
  tokenMaxTTL: 24h
```

#### 5. Create a VaultRole

Bind service accounts to policies within a namespace:

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
    - app-service-account
  policies:
    - kind: VaultPolicy
      name: app-secrets
    - kind: VaultClusterPolicy
      name: shared-secrets-reader
  tokenTTL: 1h
  tokenMaxTTL: 4h
```

## Configuration

### Helm Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of operator replicas | `1` |
| `image.repository` | Container image repository | `ghcr.io/panteparak/vault-access-operator` |
| `image.tag` | Container image tag | Chart appVersion |
| `webhook.enabled` | Enable admission webhooks | `true` |
| `webhook.certManager.enabled` | Use cert-manager for webhook certs | `true` |
| `metrics.enabled` | Enable Prometheus metrics | `true` |
| `serviceMonitor.enabled` | Create ServiceMonitor resource | `false` |
| `logging.level` | Log level (debug, info, error) | `info` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `networkPolicy.enabled` | Enable network policy | `false` |
| `podDisruptionBudget.enabled` | Enable PDB | `false` |

See the [values.yaml](charts/vault-access-operator/values.yaml) for all available options.

### Environment Variables

The operator supports the following environment variables:

| Variable | Description |
|----------|-------------|
| `VAULT_SKIP_VERIFY` | Skip TLS verification (not recommended) |
| `HEALTH_PROBE_BIND_ADDRESS` | Health probe bind address (default: `:8081`) |
| `METRICS_BIND_ADDRESS` | Metrics bind address (default: `:8443`) |
| `LEADER_ELECTION_ENABLED` | Enable leader election (default: `true`) |

## Custom Resource Definitions

### VaultConnection (Cluster-scoped)

Establishes and maintains a connection to a Vault server. Supports multiple authentication methods and monitors connection health.

### VaultClusterPolicy (Cluster-scoped)

Manages cluster-wide Vault policies. Policies created with this resource are accessible across all namespaces.

### VaultPolicy (Namespaced)

Manages namespace-scoped Vault policies with optional namespace boundary enforcement. The policy name in Vault follows the format `{namespace}-{name}`.

### VaultClusterRole (Cluster-scoped)

Manages cluster-wide Kubernetes auth roles in Vault. Can bind service accounts from any namespace to policies.

### VaultRole (Namespaced)

Manages namespace-scoped Kubernetes auth roles. Can only bind service accounts from the same namespace. The role name in Vault follows the format `{namespace}-{name}`.

For detailed CRD reference, see [CRD Reference](docs/crd-reference.md).

## Documentation

- [Getting Started Guide](docs/getting-started.md)
- [CRD Reference](docs/crd-reference.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

## Development

### Prerequisites

- Go 1.24+
- Docker
- Kind (for local testing)
- make

### Building

```bash
# Build the operator
make build

# Run tests
make test

# Run linter
make lint

# Generate manifests
make manifests
```

### Local Development

```bash
# Create a Kind cluster for testing
make setup-test-e2e

# Run the operator locally
make run

# Run e2e tests
make test-e2e
```

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Run linter (`make lint`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Code Standards

- Follow Go best practices and conventions
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass before submitting PR
- Use meaningful commit messages

## Security

### Reporting Security Issues

If you discover a security vulnerability, please report it privately. Do not open a public issue.

### Security Best Practices

- Always use TLS for Vault connections in production
- Use namespace boundary enforcement for VaultPolicy resources
- Implement least-privilege access policies
- Regularly rotate Vault tokens and credentials
- Monitor operator logs for unauthorized access attempts

## License

Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Acknowledgments

- [HashiCorp Vault](https://www.vaultproject.io/)
- [Kubernetes Operator SDK](https://sdk.operatorframework.io/)
- [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime)
