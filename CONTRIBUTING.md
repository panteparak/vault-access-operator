# Contributing to Vault Access Operator

Thank you for your interest in contributing to the Vault Access Operator! This document provides guidelines and information for contributors.

## Code of Conduct

This project follows the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check the [existing issues](https://github.com/panteparak/vault-access-operator/issues) to avoid duplicates.

When filing a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details**:
  - Kubernetes version (`kubectl version`)
  - Vault version
  - Operator version
  - Cloud provider (if applicable)
- **Relevant logs** from the operator and affected resources
- **Manifests** (sanitized) that reproduce the issue

### Suggesting Features

Feature requests are welcome! Please:

1. Check [existing issues](https://github.com/panteparak/vault-access-operator/issues) and [discussions](https://github.com/panteparak/vault-access-operator/discussions)
2. Open a [new discussion](https://github.com/panteparak/vault-access-operator/discussions/new?category=ideas) for initial feedback
3. Once discussed, a maintainer may convert it to an issue

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-new-feature
   ```
3. **Make your changes** with appropriate tests
4. **Run validation**:
   ```bash
   make test
   make lint
   ```
5. **Commit** using [conventional commits](#commit-messages)
6. **Push** and open a Pull Request

## Development Setup

### Prerequisites

- Go 1.21+
- Docker
- kubectl
- Kind or Minikube (for local testing)
- Make

### Getting Started

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/vault-access-operator.git
cd vault-access-operator

# Install dependencies
make install

# Run tests
make test

# Run linter
make lint

# Run locally against current kubeconfig
make run
```

### Running Tests

```bash
# Unit tests
make test

# Unit tests with coverage
make test-coverage

# End-to-end tests (requires Kind cluster)
make test-e2e

# Specific package tests
go test ./pkg/vault/... -v
```

### Building

```bash
# Build binary
make build

# Build container image
make docker-build IMG=my-registry/vault-access-operator:dev

# Push container image
make docker-push IMG=my-registry/vault-access-operator:dev
```

## Coding Guidelines

### Go Style

- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Use `gofmt` for formatting (handled by `make lint`)
- Keep functions focused and testable
- Add comments for exported types and functions

### Project Structure

```
.
├── api/v1alpha1/          # CRD type definitions
├── cmd/                   # Entrypoints
├── config/                # Kustomize manifests
├── docs/                  # Documentation
├── features/              # Feature controllers (DDD style)
│   ├── connection/        # VaultConnection feature
│   ├── policy/            # VaultPolicy feature
│   └── role/              # VaultRole feature
├── internal/              # Internal packages
├── pkg/                   # Reusable packages
│   └── vault/             # Vault client and auth
└── test/                  # Test fixtures
```

### Testing Requirements

- **Unit tests** for all new functionality
- **Integration tests** for controller logic
- **E2E tests** for user-facing features
- Aim for >80% coverage on new code

### Error Handling

- Use wrapped errors with context: `fmt.Errorf("failed to do X: %w", err)`
- Return errors to callers; let controllers decide logging
- Use structured logging with relevant fields

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting (no code change) |
| `refactor` | Code change (no feature/fix) |
| `perf` | Performance improvement |
| `test` | Adding/updating tests |
| `chore` | Maintenance tasks |

### Examples

```
feat(auth): add GCP Workload Identity support

Implement GCP IAM authentication for GKE workloads using
Workload Identity federation.

Closes #123
```

```
fix(webhook): validate namespace boundary correctly

The webhook was allowing wildcards before {{namespace}} which
could lead to cross-namespace access.

Fixes #456
```

## Pull Request Process

1. **Title**: Use conventional commit format
2. **Description**: Fill out the PR template completely
3. **Tests**: Ensure all tests pass
4. **Documentation**: Update docs if needed
5. **Review**: Address reviewer feedback promptly

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated (if applicable)
- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] Commits follow conventional format
- [ ] PR description explains the change

## Release Process

Releases are automated via GitHub Actions when a tag is pushed:

```bash
git tag v0.1.0
git push origin v0.1.0
```

This triggers:
1. CI validation
2. Container image build and push
3. Helm chart release
4. GitHub release with changelog

## Getting Help

- **Questions**: [GitHub Discussions](https://github.com/panteparak/vault-access-operator/discussions)
- **Bugs**: [GitHub Issues](https://github.com/panteparak/vault-access-operator/issues)
- **Security**: [Security Advisories](https://github.com/panteparak/vault-access-operator/security/advisories/new)

## Recognition

Contributors are recognized in:
- Release notes
- GitHub contributors page
- Project documentation

Thank you for contributing!
