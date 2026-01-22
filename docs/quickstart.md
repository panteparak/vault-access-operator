# Quick Start

This guide walks you through creating your first Vault policies and roles in 5 minutes.

!!! info "Prerequisites"
    Before starting, ensure you have completed the [Installation](installation.md) guide and have a running operator.

## Step 1: Create a VaultConnection

The VaultConnection resource establishes the connection between the operator and your Vault server.

### Prepare Vault

First, create a policy in Vault that allows the operator to manage policies and roles:

```bash
vault policy write vault-access-operator - <<EOF
# Manage policies
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/policies/acl" {
  capabilities = ["list"]
}

# Manage Kubernetes auth roles
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/kubernetes/role" {
  capabilities = ["list"]
}
EOF

# Create a Kubernetes auth role for the operator
vault write auth/kubernetes/role/vault-access-operator \
    bound_service_account_names=vault-access-operator-controller-manager \
    bound_service_account_namespaces=vault-access-operator-system \
    policies=vault-access-operator \
    ttl=1h
```

### Create VaultConnection Resource

```yaml
# vault-connection.yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-primary
spec:
  address: https://vault.example.com:8200
  auth:
    kubernetes:
      role: vault-access-operator
  tls:
    skipVerify: false  # Set to true for testing only
```

Apply the connection:

```bash
kubectl apply -f vault-connection.yaml
```

Verify the connection is active:

```bash
kubectl get vaultconnection vault-primary
```

Expected output:

```
NAME            ADDRESS                          PHASE    VERSION   AGE
vault-primary   https://vault.example.com:8200   Active   1.15.0    30s
```

## Step 2: Create a VaultPolicy

Now create a Vault policy using the operator.

### Namespace-scoped Policy (VaultPolicy)

```yaml
# app-secrets-policy.yaml
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
      description: "Read secrets for this namespace"
```

```bash
# Create the namespace
kubectl create namespace my-app

# Apply the policy
kubectl apply -f app-secrets-policy.yaml
```

The policy will be created in Vault with the name `my-app-app-secrets`, and `{{namespace}}` will be substituted with `my-app`.

### Cluster-wide Policy (VaultClusterPolicy)

```yaml
# shared-secrets-policy.yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: shared-secrets-reader
spec:
  connectionRef: vault-primary
  rules:
    - path: "secret/data/shared/*"
      capabilities: [read, list]
      description: "Read shared secrets"
```

```bash
kubectl apply -f shared-secrets-policy.yaml
```

Verify the policies:

```bash
kubectl get vaultpolicy -n my-app
kubectl get vaultclusterpolicy
```

## Step 3: Create a VaultRole

Bind service accounts to the policies you created.

### Namespace-scoped Role (VaultRole)

```yaml
# app-role.yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: app-role
  namespace: my-app
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - default
  policies:
    - kind: VaultPolicy
      name: app-secrets
    - kind: VaultClusterPolicy
      name: shared-secrets-reader
  tokenTTL: 1h
  tokenMaxTTL: 4h
```

```bash
kubectl apply -f app-role.yaml
```

### Cluster-wide Role (VaultClusterRole)

```yaml
# platform-role.yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: platform-services
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: monitoring-agent
      namespace: monitoring
    - name: platform-controller
      namespace: platform-system
  policies:
    - kind: VaultClusterPolicy
      name: shared-secrets-reader
  tokenTTL: 1h
```

```bash
kubectl apply -f platform-role.yaml
```

Verify the roles:

```bash
kubectl get vaultrole -n my-app
kubectl get vaultclusterrole
```

## Step 4: Test Authentication

Create a test pod to verify everything works:

```yaml
# test-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: vault-test
  namespace: my-app
spec:
  serviceAccountName: default
  containers:
    - name: vault
      image: hashicorp/vault:latest
      command: ["sleep", "infinity"]
      env:
        - name: VAULT_ADDR
          value: "https://vault.example.com:8200"
```

```bash
kubectl apply -f test-pod.yaml
```

Test Vault authentication:

```bash
# Get into the pod
kubectl exec -it vault-test -n my-app -- /bin/sh

# Inside the pod, authenticate to Vault
vault login -method=kubernetes role=my-app-app-role

# Test reading a secret (create one in Vault first)
vault kv get secret/my-app/test

# This should fail (policy boundary enforcement)
vault kv get secret/other-namespace/secret
```

## Summary

You've successfully:

1. **Connected** the operator to your Vault server using `VaultConnection`
2. **Created policies** using `VaultPolicy` (namespace-scoped) and `VaultClusterPolicy` (cluster-wide)
3. **Created roles** using `VaultRole` and `VaultClusterRole` to bind service accounts to policies
4. **Tested** Vault authentication from a Kubernetes pod

## Next Steps

- Read the [API Reference](api-reference/index.md) for detailed CRD documentation
- Explore [Configuration Examples](configuration/examples.md) for production setups
- Check the [Troubleshooting](troubleshooting.md) guide if you encounter issues

## Quick Reference

| Resource | Scope | Description |
|----------|-------|-------------|
| VaultConnection | Cluster | Establishes connection to Vault |
| VaultPolicy | Namespaced | Namespace-scoped Vault policy |
| VaultClusterPolicy | Cluster | Cluster-wide Vault policy |
| VaultRole | Namespaced | Namespace-scoped Kubernetes auth role |
| VaultClusterRole | Cluster | Cluster-wide Kubernetes auth role |
