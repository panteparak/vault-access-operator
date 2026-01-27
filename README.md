<p align="center">
  <img src="docs/assets/logo.svg" alt="Vault Access Operator" width="200" />
</p>

<h1 align="center">Vault Access Operator</h1>

<p align="center">
  <strong>Kubernetes-native management of HashiCorp Vault policies and authentication roles</strong>
</p>

<p align="center">
  <a href="https://github.com/panteparak/vault-access-operator/actions/workflows/ci.yaml">
    <img src="https://github.com/panteparak/vault-access-operator/actions/workflows/ci.yaml/badge.svg" alt="CI Status" />
  </a>
  <a href="https://github.com/panteparak/vault-access-operator/releases">
    <img src="https://img.shields.io/github/v/release/panteparak/vault-access-operator?include_prereleases" alt="Release" />
  </a>
  <a href="https://goreportcard.com/report/github.com/panteparak/vault-access-operator">
    <img src="https://goreportcard.com/badge/github.com/panteparak/vault-access-operator" alt="Go Report Card" />
  </a>
  <a href="https://pkg.go.dev/github.com/panteparak/vault-access-operator">
    <img src="https://pkg.go.dev/badge/github.com/panteparak/vault-access-operator.svg" alt="Go Reference" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License" />
  </a>
</p>

<p align="center">
  <a href="https://panteparak.github.io/vault-access-operator/">Documentation</a> |
  <a href="https://panteparak.github.io/vault-access-operator/getting-started/">Getting Started</a> |
  <a href="https://panteparak.github.io/vault-access-operator/examples/">Examples</a> |
  <a href="https://github.com/panteparak/vault-access-operator/releases">Releases</a>
</p>

---

## Why Vault Access Operator?

Managing Vault policies and Kubernetes authentication roles at scale is challenging. Teams often struggle with:

- **Manual policy management** - Vault policies scattered across CLI commands and scripts
- **No GitOps workflow** - Changes bypass version control and code review
- **Namespace isolation** - Difficult to enforce tenant boundaries in multi-tenant clusters
- **Credential sprawl** - Managing secrets for multiple authentication methods

**Vault Access Operator** solves these problems by bringing Vault access management into Kubernetes as native Custom Resources, enabling GitOps workflows, automated reconciliation, and secure multi-tenancy.

```yaml
# Define Vault policies as Kubernetes resources
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: app-secrets
  namespace: production
spec:
  connectionRef: vault-primary
  enforceNamespaceBoundary: true
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read, list]
```

## Key Features

| Feature | Description |
|---------|-------------|
| **Declarative Policies** | Define Vault policies as Kubernetes CRDs with full YAML/JSON support |
| **GitOps Ready** | Version control policies alongside application manifests |
| **Namespace Isolation** | Automatic enforcement of tenant boundaries with `{{namespace}}` variables |
| **Multi-Cloud Auth** | Support for Kubernetes, JWT, OIDC, AWS IAM (IRSA), and GCP Workload Identity |
| **Admission Webhooks** | Validate configurations before they reach Vault |
| **Conflict Handling** | Choose between fail-fast or adopt strategies for existing resources |
| **Automatic Reconciliation** | Self-healing with exponential backoff and jitter |
| **Least Privilege** | Operator requires minimal Vault permissions - no access to secrets |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Kubernetes Cluster                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐      │
│  │   VaultPolicy   │    │   VaultRole     │    │ VaultConnection │      │
│  │   (namespace)   │    │   (namespace)   │    │    (cluster)    │      │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘      │
│           │                      │                      │               │
│           └──────────────────────┼──────────────────────┘               │
│                                  │                                      │
│                    ┌─────────────▼─────────────┐                        │
│                    │   Vault Access Operator   │                        │
│                    │  ┌─────────────────────┐  │                        │
│                    │  │ Policy Controller   │  │                        │
│                    │  │ Role Controller     │  │                        │
│                    │  │ Connection Manager  │  │                        │
│                    │  └─────────────────────┘  │                        │
│                    └─────────────┬─────────────┘                        │
└──────────────────────────────────┼──────────────────────────────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │      HashiCorp Vault        │
                    │  ┌────────┐  ┌────────────┐ │
                    │  │Policies│  │ Auth Roles │ │
                    │  └────────┘  └────────────┘ │
                    └─────────────────────────────┘
```

## Quick Start

### Prerequisites

- Kubernetes v1.25+
- HashiCorp Vault v1.12+
- Helm v3+ (recommended) or kubectl

### Installation

**Option 1: Helm (Recommended)**

```bash
helm repo add vault-access-operator https://panteparak.github.io/vault-access-operator/charts
helm repo update

helm install vault-access-operator vault-access-operator/vault-access-operator \
  --namespace vault-access-operator-system \
  --create-namespace
```

**Option 2: kubectl**

```bash
kubectl apply -f https://raw.githubusercontent.com/panteparak/vault-access-operator/main/dist/install.yaml
```

### Create a Vault Connection

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
```

```bash
kubectl apply -f vault-connection.yaml
kubectl get vaultconnection
# NAME            ADDRESS                          PHASE    VERSION   AGE
# vault-primary   https://vault.example.com:8200   Active   1.15.0    30s
```

### Create a Policy and Role

```yaml
---
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
---
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: app-role
  namespace: my-app
spec:
  connectionRef: vault-primary
  serviceAccounts: [default]
  policies:
    - kind: VaultPolicy
      name: app-secrets
```

```bash
kubectl apply -f policy-and-role.yaml
kubectl get vaultpolicy,vaultrole -n my-app
```

## Custom Resource Definitions

| CRD | Scope | Description |
|-----|-------|-------------|
| **VaultConnection** | Cluster | Establishes authenticated connection to Vault |
| **VaultPolicy** | Namespaced | Namespace-scoped Vault policies with `{{namespace}}` variable |
| **VaultClusterPolicy** | Cluster | Cluster-wide Vault policies |
| **VaultRole** | Namespaced | Kubernetes auth roles for namespace service accounts |
| **VaultClusterRole** | Cluster | Kubernetes auth roles spanning multiple namespaces |

## Authentication Methods

The operator supports multiple authentication methods to connect to Vault:

| Method | Best For | Cloud Support |
|--------|----------|---------------|
| **Kubernetes** | Standard K8s clusters | Any |
| **JWT** | External identity providers | Any |
| **OIDC** | Workload identity | EKS, AKS, GKE |
| **AWS IAM** | EKS with IRSA | AWS |
| **GCP IAM** | GKE with Workload Identity | GCP |
| **Token** | Development/testing | Any |
| **AppRole** | CI/CD pipelines | Any |

<details>
<summary><strong>AWS IAM (IRSA) Example</strong></summary>

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-aws
spec:
  address: https://vault.example.com:8200
  auth:
    aws:
      role: eks-workload-role
      authType: iam
      region: us-west-2
```

</details>

<details>
<summary><strong>GCP Workload Identity Example</strong></summary>

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-gcp
spec:
  address: https://vault.example.com:8200
  auth:
    gcp:
      role: gke-workload-role
      authType: iam
      serviceAccountEmail: vault-auth@project.iam.gserviceaccount.com
```

</details>

<details>
<summary><strong>OIDC (EKS) Example</strong></summary>

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-oidc
spec:
  address: https://vault.example.com:8200
  auth:
    oidc:
      role: eks-oidc-role
      providerURL: https://oidc.eks.us-west-2.amazonaws.com/id/CLUSTER_ID
      audiences: ["sts.amazonaws.com"]
```

</details>

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](https://panteparak.github.io/vault-access-operator/getting-started/) | Installation and first steps |
| [Configuration](https://panteparak.github.io/vault-access-operator/configuration/) | Helm chart options and operator settings |
| [API Reference](https://panteparak.github.io/vault-access-operator/api-reference/) | Complete CRD field documentation |
| [Examples](https://panteparak.github.io/vault-access-operator/examples/) | Real-world usage patterns |
| [Webhooks](https://panteparak.github.io/vault-access-operator/webhooks/) | Admission webhook validation rules |
| [Troubleshooting](https://panteparak.github.io/vault-access-operator/troubleshooting/) | Common issues and solutions |

## Comparison with Alternatives

| Feature | Vault Access Operator | Vault Secrets Operator | External Secrets | Manual Scripts |
|---------|:---------------------:|:----------------------:|:----------------:|:--------------:|
| Policy Management | Yes | No | No | Manual |
| Auth Role Management | Yes | No | No | Manual |
| Namespace Isolation | Built-in | N/A | N/A | Manual |
| GitOps Workflow | Yes | Yes | Yes | Partial |
| Least Privilege | Yes | No* | No* | Varies |
| Secret Sync | No** | Yes | Yes | Manual |
| Multi-Cloud Auth | Yes | Partial | Partial | Manual |

\* *Requires access to secrets for syncing*
\** *Use alongside Vault Secrets Operator or External Secrets for secret syncing*

## Security

### Principle of Least Privilege

The operator is designed with security in mind:

- **No secret access** - Only manages policies and roles, never reads secrets
- **Minimal permissions** - Requires only `sys/policies/acl/*` and `auth/kubernetes/role/*`
- **Namespace boundary enforcement** - Prevents cross-namespace access leaks
- **Admission webhooks** - Validates configurations before applying

### Reporting Security Issues

Please report security vulnerabilities via [GitHub Security Advisories](https://github.com/panteparak/vault-access-operator/security/advisories/new) rather than public issues.

## Development

```bash
# Clone the repository
git clone https://github.com/panteparak/vault-access-operator.git
cd vault-access-operator

# Install dependencies
make install

# Run locally against current kubeconfig
make run

# Run tests
make test

# Run linter
make lint

# Build container image
make docker-build IMG=my-registry/vault-access-operator:dev

# Run end-to-end tests
make test-e2e
```

### Project Structure

```
.
├── api/v1alpha1/          # CRD type definitions
├── cmd/                   # Entrypoints
├── config/                # Kustomize manifests
├── docs/                  # Documentation source
├── features/              # Feature controllers (Domain-Driven Design)
│   ├── connection/        # VaultConnection feature
│   ├── policy/            # VaultPolicy/VaultClusterPolicy feature
│   └── role/              # VaultRole/VaultClusterRole feature
├── internal/              # Internal packages
├── pkg/                   # Reusable packages
│   └── vault/             # Vault client and auth helpers
└── test/                  # Test fixtures and e2e tests
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with tests
4. Run `make test && make lint`
5. Commit with [conventional commits](https://www.conventionalcommits.org/)
6. Open a Pull Request

### Code of Conduct

This project follows the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

## Roadmap

- [x] Core policy and role management
- [x] Multi-cloud authentication (AWS, GCP, OIDC)
- [x] Admission webhooks
- [x] Comprehensive documentation
- [ ] Metrics and observability
- [ ] Policy validation against Vault
- [ ] Azure Workload Identity support
- [ ] Vault Enterprise namespace support

See the [open issues](https://github.com/panteparak/vault-access-operator/issues) for a full list of proposed features and known issues.

## Community

- [GitHub Discussions](https://github.com/panteparak/vault-access-operator/discussions) - Ask questions and share ideas
- [GitHub Issues](https://github.com/panteparak/vault-access-operator/issues) - Report bugs and request features
- [Releases](https://github.com/panteparak/vault-access-operator/releases) - Download and changelog

## License

Copyright 2024-2026 Vault Access Operator Contributors.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

---

<p align="center">
  Made with :heart: by the community
</p>
