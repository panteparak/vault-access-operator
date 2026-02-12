# Authentication Methods

The Vault Access Operator supports multiple authentication methods to connect to HashiCorp Vault. Choose the method that best fits your environment and security requirements.

## Quick Reference

| Method | Best For | Cloud Provider | Complexity |
|--------|----------|----------------|------------|
| [Kubernetes](kubernetes.md) | Standard K8s clusters | Any | Low |
| [AWS IAM](aws-iam.md) | EKS with IRSA | AWS | Medium |
| [GCP IAM](gcp-iam.md) | GKE with Workload Identity | GCP | Medium |
| [OIDC](oidc.md) | EKS/GKE/Azure workload identity | Any | Medium |
| [JWT](jwt.md) | External identity providers | Any | Medium |
| [AppRole](approle.md) | CI/CD pipelines | Any | Low |
| [Token](token.md) | Development/testing only | Any | Very Low |
| [Bootstrap](bootstrap.md) | Initial Vault setup | Any | Medium |

## Decision Guide

```
                    ┌─────────────────────────┐
                    │ What environment are    │
                    │ you running in?         │
                    └───────────┬─────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
   ┌─────────┐            ┌─────────┐            ┌─────────┐
   │   EKS   │            │   GKE   │            │  Other  │
   └────┬────┘            └────┬────┘            └────┬────┘
        │                      │                      │
        ▼                      ▼                      ▼
  ┌───────────┐          ┌───────────┐         ┌───────────┐
  │ IRSA      │          │ Workload  │         │ Standard  │
  │ enabled?  │          │ Identity? │         │ K8s auth  │
  └─────┬─────┘          └─────┬─────┘         └───────────┘
        │                      │                      │
   Yes  │  No             Yes  │  No                  │
   ┌────┴────┐            ┌────┴────┐                 │
   ▼         ▼            ▼         ▼                 │
AWS IAM   Kubernetes    GCP IAM  Kubernetes    ◄──────┘
```

## Method Comparison

### Security Level

| Method | Token Lifetime | Credential Type | Auto-Rotation |
|--------|---------------|-----------------|---------------|
| Kubernetes | Short (1h default) | Service Account Token | Yes |
| AWS IAM | Short | IAM Credentials | Yes (IRSA) |
| GCP IAM | Short | Workload Identity Token | Yes |
| OIDC | Short | JWT from IdP | Yes |
| JWT | Configurable | External JWT | Depends |
| AppRole | Configurable | SecretID | Manual |
| Token | Long-lived | Static Token | No |
| Bootstrap | One-time | Bootstrap Token | N/A |

### Prerequisites

| Method | Vault Config Required | K8s Config Required | Cloud Config Required |
|--------|----------------------|---------------------|----------------------|
| Kubernetes | Kubernetes auth enabled | ServiceAccount | None |
| AWS IAM | AWS auth enabled | IRSA annotation | IAM Role + Trust Policy |
| GCP IAM | GCP auth enabled | Workload Identity annotation | GCP SA + IAM Binding |
| OIDC | OIDC auth enabled | ServiceAccount | OIDC Provider |
| JWT | JWT auth enabled | ServiceAccount or Secret | IdP configuration |
| AppRole | AppRole auth enabled | Secret with credentials | None |
| Token | None | Secret with token | None |
| Bootstrap | Permissive token | Secret with token | None |

## Which Method Should I Use?

### Production Workloads

1. **EKS clusters**: Use [AWS IAM](aws-iam.md) with IRSA for the strongest security
2. **GKE clusters**: Use [GCP IAM](gcp-iam.md) with Workload Identity
3. **Standard Kubernetes**: Use [Kubernetes](kubernetes.md) auth - it's secure and well-tested
4. **Multi-cloud or hybrid**: Use [OIDC](oidc.md) for consistent identity federation

### CI/CD Pipelines

Use [AppRole](approle.md) auth for:

- GitHub Actions
- GitLab CI
- Jenkins
- ArgoCD

### Development and Testing

Use [Token](token.md) auth only for:

- Local development
- Quick testing
- Demos

!!! warning "Never use Token auth in production"
    Token auth uses long-lived static credentials and should never be used in production environments.

### Initial Setup

Use [Bootstrap](bootstrap.md) auth to:

- Configure Vault's Kubernetes auth method
- Set up initial policies
- Transition to Kubernetes auth afterward

## Common Configuration

All authentication methods share these common fields:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: my-vault
spec:
  address: https://vault.example.com:8200
  tls:
    caCert:
      secretRef:
        name: vault-ca-cert
        key: ca.crt
  auth:
    # Choose ONE of the following auth methods
    kubernetes: { ... }
    aws: { ... }
    gcp: { ... }
    oidc: { ... }
    jwt: { ... }
    appRole: { ... }
    token: { ... }
    bootstrap: { ... }
```

## Next Steps

Choose your authentication method and follow the detailed setup guide:

- [Kubernetes Authentication](kubernetes.md) - Standard K8s clusters
- [AWS IAM Authentication](aws-iam.md) - EKS with IRSA
- [GCP IAM Authentication](gcp-iam.md) - GKE with Workload Identity
- [OIDC Authentication](oidc.md) - Workload identity federation
- [JWT Authentication](jwt.md) - External identity providers
- [AppRole Authentication](approle.md) - CI/CD pipelines
- [Token Authentication](token.md) - Development only
- [Bootstrap Authentication](bootstrap.md) - Initial setup
