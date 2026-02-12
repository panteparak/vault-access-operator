# AppRole Authentication

AppRole authentication is designed for machine-to-machine authentication, making it ideal for CI/CD pipelines and automated systems.

## Overview

**Best for:** CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins), automated deployments, non-Kubernetes workloads.

**How it works:**

1. The operator reads RoleID and SecretID from Kubernetes secrets
2. Credentials are sent to Vault's AppRole auth endpoint
3. Vault validates the credentials
4. Vault returns a token with the configured policies

```
┌─────────────────┐
│   K8s Secret    │
│   (RoleID +     │
│    SecretID)    │
└────────┬────────┘
         │ 1. Read credentials
         ▼
┌─────────────────┐     2. Login          ┌─────────────────┐
│                 │ ─────────────────────►│                 │
│    Operator     │                       │      Vault      │
│                 │◄───────────────────── │                 │
└─────────────────┘     3. Vault Token    └─────────────────┘
```

## Prerequisites

### Vault Requirements

- Vault server v1.12 or later
- AppRole auth method enabled

### Kubernetes Requirements

- Secret containing RoleID
- Secret containing SecretID

## Assumptions

This guide assumes:

- You have `vault` CLI access to create AppRole credentials
- You can create Kubernetes secrets in the operator namespace
- You have a secure way to distribute the initial SecretID

## Step-by-Step Setup

### Step 1: Enable AppRole Auth in Vault

```bash
vault auth enable approle
```

### Step 2: Create Vault Policy

```bash
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
```

### Step 3: Create AppRole in Vault

```bash
# Create the AppRole
vault write auth/approle/role/vault-access-operator \
    token_policies="vault-access-operator" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0 \
    secret_id_num_uses=0

# Get the RoleID
vault read auth/approle/role/vault-access-operator/role-id
# role_id    db02de05-fa39-4855-059b-67221c5c2f63

# Generate a SecretID
vault write -f auth/approle/role/vault-access-operator/secret-id
# secret_id             6a174c20-f6de-a53c-74d2-6018fcceff64
# secret_id_accessor    c454f7e5-996e-7230-6074-6ef26b7bcf86
```

| Parameter | Description |
|-----------|-------------|
| `token_policies` | Vault policies attached to tokens |
| `token_ttl` | Default token lifetime |
| `token_max_ttl` | Maximum token lifetime |
| `secret_id_ttl` | SecretID expiration (0 = never) |
| `secret_id_num_uses` | Max SecretID uses (0 = unlimited) |

### Step 4: Create Kubernetes Secrets

```bash
# Create secret for RoleID
kubectl create secret generic vault-approle-role-id \
    -n vault-access-operator-system \
    --from-literal=role-id=db02de05-fa39-4855-059b-67221c5c2f63

# Create secret for SecretID
kubectl create secret generic vault-approle-secret-id \
    -n vault-access-operator-system \
    --from-literal=secret-id=6a174c20-f6de-a53c-74d2-6018fcceff64
```

!!! warning "SecretID Security"
    SecretID is a sensitive credential. Consider:

    - Using short-lived SecretIDs with rotation
    - Limiting SecretID uses
    - Using External Secrets Operator to sync from Vault

### Step 5: Create VaultConnection Resource

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-approle
spec:
  address: https://vault.example.com:8200

  tls:
    caCert:
      secretRef:
        name: vault-ca-cert
        namespace: vault-access-operator-system
        key: ca.crt

  auth:
    appRole:
      roleId: db02de05-fa39-4855-059b-67221c5c2f63
      secretIdRef:
        name: vault-approle-secret-id
        namespace: vault-access-operator-system
        key: secret-id
      # mountPath: approle  # default
```

Apply the configuration:

```bash
kubectl apply -f vaultconnection.yaml
```

### Step 6: Verify the Connection

```bash
kubectl get vaultconnection vault-approle -o yaml
```

## Configuration Reference

### Required Fields

| Field | Description |
|-------|-------------|
| `auth.appRole.roleId` | The AppRole RoleID |
| `auth.appRole.secretIdRef` | Reference to secret containing SecretID |

### Optional Fields

| Field | Default | Description |
|-------|---------|-------------|
| `mountPath` | `approle` | Vault auth mount path |

## SecretID Rotation

For production, implement SecretID rotation:

### Option 1: Wrapped SecretID

Generate a wrapped SecretID that can only be unwrapped once:

```bash
vault write -wrap-ttl=120s -f auth/approle/role/vault-access-operator/secret-id
```

### Option 2: External Secrets Operator

Use External Secrets to sync SecretID from Vault:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: vault-approle-secret-id
  namespace: vault-access-operator-system
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault
    kind: ClusterSecretStore
  target:
    name: vault-approle-secret-id
  data:
    - secretKey: secret-id
      remoteRef:
        key: auth/approle/role/vault-access-operator/secret-id
        property: secret_id
```

### Option 3: Limited-Use SecretID

Create SecretIDs that expire after a set number of uses:

```bash
vault write auth/approle/role/vault-access-operator \
    secret_id_num_uses=10 \
    secret_id_ttl=24h
```

## Troubleshooting

### "invalid role or secret ID" error

**Symptoms:**
```
Error: invalid role or secret ID
```

**Solutions:**

1. Verify the RoleID is correct:
   ```bash
   vault read auth/approle/role/vault-access-operator/role-id
   ```

2. Check if the SecretID is valid:
   ```bash
   vault write auth/approle/role/vault-access-operator/secret-id-accessor/lookup \
       secret_id_accessor=<accessor>
   ```

3. Verify the secret contents in Kubernetes:
   ```bash
   kubectl get secret vault-approle-secret-id -n vault-access-operator-system -o jsonpath='{.data.secret-id}' | base64 -d
   ```

### SecretID has expired

**Symptoms:**
```
Error: secret ID is expired
```

**Solutions:**

1. Generate a new SecretID:
   ```bash
   vault write -f auth/approle/role/vault-access-operator/secret-id
   ```

2. Update the Kubernetes secret:
   ```bash
   kubectl create secret generic vault-approle-secret-id \
       -n vault-access-operator-system \
       --from-literal=secret-id=<new-secret-id> \
       --dry-run=client -o yaml | kubectl apply -f -
   ```

## CI/CD Integration Examples

=== "GitHub Actions"
    ```yaml
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - name: Get Vault Token
            env:
              VAULT_ADDR: https://vault.example.com:8200
              VAULT_ROLE_ID: ${{ secrets.VAULT_ROLE_ID }}
              VAULT_SECRET_ID: ${{ secrets.VAULT_SECRET_ID }}
            run: |
              VAULT_TOKEN=$(vault write -field=token auth/approle/login \
                  role_id=$VAULT_ROLE_ID \
                  secret_id=$VAULT_SECRET_ID)
              echo "VAULT_TOKEN=$VAULT_TOKEN" >> $GITHUB_ENV
    ```

=== "GitLab CI"
    ```yaml
    variables:
      VAULT_ADDR: https://vault.example.com:8200

    get_vault_token:
      script:
        - |
          export VAULT_TOKEN=$(vault write -field=token auth/approle/login \
              role_id=$VAULT_ROLE_ID \
              secret_id=$VAULT_SECRET_ID)
    ```

## See Also

- [Kubernetes Authentication](kubernetes.md) - Better for K8s-native workloads
- [Token Authentication](token.md) - Simpler but less secure
- [API Reference](../api-reference.md) - Complete field reference
