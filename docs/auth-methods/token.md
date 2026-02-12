# Token Authentication

Token authentication uses a static Vault token stored in a Kubernetes secret. This is the simplest authentication method but offers the least security.

!!! danger "Development Only"
    Token authentication should **never** be used in production. It uses long-lived, static credentials that:

    - Don't automatically rotate
    - Can be easily leaked
    - Provide no audit trail of who used them
    - Cannot be scoped to specific workloads

## Overview

**Best for:** Local development, quick testing, demos.

**How it works:**

1. A Vault token is stored in a Kubernetes secret
2. The operator reads the token from the secret
3. The token is used directly for Vault API calls

```
┌─────────────────┐
│   K8s Secret    │
│   (Vault Token) │
└────────┬────────┘
         │ 1. Read token
         ▼
┌─────────────────┐     2. Use token      ┌─────────────────┐
│                 │ ─────────────────────►│                 │
│    Operator     │                       │      Vault      │
│                 │◄───────────────────── │                 │
└─────────────────┘     3. Authenticated  └─────────────────┘
```

## Prerequisites

### Vault Requirements

- Vault server running and accessible
- A Vault token with appropriate permissions

### Kubernetes Requirements

- Secret containing the Vault token

## Quick Setup

### Step 1: Create Vault Token

For development, you can use the root token or create a limited token:

```bash
# Option A: Use root token (dev only!)
# The root token is printed when starting Vault in dev mode

# Option B: Create a limited token
vault policy write vault-access-operator - <<EOF
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/policies/acl" {
  capabilities = ["list"]
}
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/kubernetes/role" {
  capabilities = ["list"]
}
EOF

vault token create -policy=vault-access-operator -ttl=24h
```

### Step 2: Create Kubernetes Secret

```bash
kubectl create secret generic vault-token \
    -n vault-access-operator-system \
    --from-literal=token=hvs.your-token-here
```

### Step 3: Create VaultConnection

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-dev
spec:
  address: http://vault.default.svc:8200  # or http://localhost:8200

  auth:
    token:
      secretRef:
        name: vault-token
        namespace: vault-access-operator-system
        key: token
```

Apply:

```bash
kubectl apply -f vaultconnection.yaml
```

### Step 4: Verify

```bash
kubectl get vaultconnection vault-dev
```

## Configuration Reference

### Required Fields

| Field | Description |
|-------|-------------|
| `auth.token.secretRef.name` | Name of the secret containing the token |
| `auth.token.secretRef.key` | Key within the secret |

### Optional Fields

| Field | Default | Description |
|-------|---------|-------------|
| `secretRef.namespace` | VaultConnection namespace | Namespace of the secret |

## Local Development Setup

For local development with Vault in dev mode:

```bash
# Start Vault in dev mode
vault server -dev -dev-root-token-id=root

# In another terminal, export the address
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root

# Create the secret
kubectl create secret generic vault-token \
    -n vault-access-operator-system \
    --from-literal=token=root
```

VaultConnection for local development:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-local
spec:
  address: http://host.docker.internal:8200  # For Docker Desktop
  # address: http://172.17.0.1:8200          # For Linux
  auth:
    token:
      secretRef:
        name: vault-token
        namespace: vault-access-operator-system
        key: token
```

## Security Warnings

### Why Token Auth is Dangerous in Production

| Issue | Impact |
|-------|--------|
| **No rotation** | Compromised tokens remain valid until manually revoked |
| **No identity** | Vault can't distinguish between uses of the same token |
| **Audit gaps** | Logs show token ID but not the actual user/workload |
| **Credential sprawl** | Tokens may be copied to multiple locations |
| **No scope limits** | Token has same permissions everywhere it's used |

### Alternatives for Production

| Method | Use Case |
|--------|----------|
| [Kubernetes Auth](kubernetes.md) | Standard K8s clusters |
| [AWS IAM](aws-iam.md) | EKS with IRSA |
| [GCP IAM](gcp-iam.md) | GKE with Workload Identity |
| [AppRole](approle.md) | CI/CD pipelines |

## Troubleshooting

### "token is expired" error

**Symptoms:**
```
Error: permission denied
```

**Solutions:**

1. Check token TTL:
   ```bash
   vault token lookup <token>
   ```

2. Create a new token:
   ```bash
   vault token create -policy=vault-access-operator
   ```

3. Update the secret:
   ```bash
   kubectl create secret generic vault-token \
       -n vault-access-operator-system \
       --from-literal=token=<new-token> \
       --dry-run=client -o yaml | kubectl apply -f -
   ```

### Connection refused (local development)

**Symptoms:**
```
Error: dial tcp 127.0.0.1:8200: connect: connection refused
```

**Solutions:**

1. For Docker Desktop, use `host.docker.internal`:
   ```yaml
   address: http://host.docker.internal:8200
   ```

2. For Linux, use the Docker bridge IP:
   ```yaml
   address: http://172.17.0.1:8200
   ```

3. Or run Vault with network binding:
   ```bash
   vault server -dev -dev-listen-address=0.0.0.0:8200
   ```

## See Also

- [Kubernetes Authentication](kubernetes.md) - Recommended for production
- [Bootstrap Authentication](bootstrap.md) - For initial setup
- [Getting Started](../getting-started.md) - Complete setup guide
