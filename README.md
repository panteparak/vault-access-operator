# Vault Access Operator

A Kubernetes operator for managing HashiCorp Vault access policies and roles declaratively through Custom Resource Definitions (CRDs).

## Features

- **Declarative Vault Policy Management** - Define Vault policies as Kubernetes resources
- **Kubernetes Auth Role Management** - Configure Vault Kubernetes authentication roles through CRDs
- **Namespace Boundary Enforcement** - Automatically restrict namespaced policies to their namespace scope
- **Multiple Authentication Methods** - Support for Kubernetes, Token, and AppRole authentication
- **Conflict Detection** - Choose between fail-fast or adopt strategies for existing resources
- **Admission Webhooks** - Validate resources before creation with detailed error messages

## Quick Install

```bash
helm repo add vault-access-operator https://panteparak.github.io/vault-access-operator/charts
helm install vault-access-operator vault-access-operator/vault-access-operator \
  --namespace vault-access-operator-system \
  --create-namespace
```

Or with kubectl:

```bash
kubectl apply -f https://raw.githubusercontent.com/panteparak/vault-access-operator/main/dist/install.yaml
```

## Documentation

**[https://panteparak.github.io/vault-access-operator/](https://panteparak.github.io/vault-access-operator/)**

- [Getting Started](https://panteparak.github.io/vault-access-operator/getting-started/) - Installation and configuration
- [Configuration](https://panteparak.github.io/vault-access-operator/configuration/) - Helm chart options
- [API Reference](https://panteparak.github.io/vault-access-operator/api-reference/) - CRD documentation
- [Examples](https://panteparak.github.io/vault-access-operator/examples/) - Usage examples
- [Troubleshooting](https://panteparak.github.io/vault-access-operator/troubleshooting/) - Common issues

## Development

```bash
make build        # Build the operator
make test         # Run tests
make lint         # Run linter
make run          # Run locally
make test-e2e     # Run e2e tests
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and add tests
4. Run `make test && make lint`
5. Open a Pull Request

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
