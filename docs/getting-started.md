# Getting Started

This guide walks you through installing the Vault Access Operator and creating your first resources.

## Prerequisites

### Kubernetes Cluster

- Kubernetes v1.25 or later
- `kubectl` configured to access your cluster
- Cluster admin permissions for installing CRDs

```bash
kubectl version
kubectl cluster-info
```

### HashiCorp Vault

- Vault server v1.12 or later
- Vault unsealed and accessible from your Kubernetes cluster
- Kubernetes authentication method enabled

To enable the Kubernetes auth method in Vault:

```bash
vault auth enable kubernetes

vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

### cert-manager (Optional)

cert-manager is recommended for managing webhook certificates:

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml
kubectl wait --for=condition=Available deployment --all -n cert-manager --timeout=300s
```

!!! note "Without cert-manager"
    You can disable webhooks or use self-signed certificates. See [Configuration](configuration.md) for details.

---

## Installation

=== "Helm (Recommended)"

    ```bash
    helm repo add vault-access-operator https://panteparak.github.io/vault-access-operator/charts
    helm repo update

    helm install vault-access-operator vault-access-operator/vault-access-operator \
      --namespace vault-access-operator-system \
      --create-namespace
    ```

=== "kubectl"

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/panteparak/vault-access-operator/main/dist/install.yaml
    ```

=== "From Source"

    ```bash
    git clone https://github.com/panteparak/vault-access-operator.git
    cd vault-access-operator
    make install
    make deploy IMG=ghcr.io/panteparak/vault-access-operator:latest
    ```

### Verify Installation

```bash
# Check operator pod
kubectl get pods -n vault-access-operator-system

# Check CRDs
kubectl get crds | grep vault.platform.io
```

---

## Configure Vault for the Operator

Before creating resources, configure Vault to allow the operator to manage policies and roles.

### Create Operator Policy

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

# Health check
path "sys/health" {
  capabilities = ["read"]
}
EOF
```

### Create Kubernetes Auth Role

```bash
vault write auth/kubernetes/role/vault-access-operator \
    bound_service_account_names=vault-access-operator-controller-manager \
    bound_service_account_namespaces=vault-access-operator-system \
    policies=vault-access-operator \
    ttl=1h
```

---

## Quick Start: Create Your First Resources

### Step 1: Create a VaultConnection

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

```bash
kubectl apply -f vault-connection.yaml
kubectl get vaultconnection vault-primary
```

Expected output:
```
NAME            ADDRESS                          PHASE    VERSION   AGE
vault-primary   https://vault.example.com:8200   Active   1.15.0    30s
```

### Step 2: Create a VaultPolicy

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
kubectl create namespace my-app
kubectl apply -f app-secrets-policy.yaml
kubectl get vaultpolicy -n my-app
```

### Step 3: Create a VaultRole

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
  tokenTTL: 1h
  tokenMaxTTL: 4h
```

```bash
kubectl apply -f app-role.yaml
kubectl get vaultrole -n my-app
```

### Step 4: Test Authentication

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
kubectl exec -it vault-test -n my-app -- vault login -method=kubernetes role=my-app-app-role
```

---

## Summary

You've successfully:

1. **Installed** the Vault Access Operator
2. **Connected** to your Vault server using `VaultConnection`
3. **Created a policy** using `VaultPolicy`
4. **Created a role** using `VaultRole` to bind service accounts to policies
5. **Tested** Vault authentication from a Kubernetes pod

| Resource | Scope | Description |
|----------|-------|-------------|
| VaultConnection | Cluster | Establishes connection to Vault |
| VaultPolicy | Namespaced | Namespace-scoped Vault policy |
| VaultClusterPolicy | Cluster | Cluster-wide Vault policy |
| VaultRole | Namespaced | Namespace-scoped Kubernetes auth role |
| VaultClusterRole | Cluster | Cluster-wide Kubernetes auth role |

---

## Uninstallation

=== "Helm"

    ```bash
    helm uninstall vault-access-operator -n vault-access-operator-system

    # Optionally delete CRDs (this deletes all managed resources!)
    kubectl delete crds \
      vaultconnections.vault.platform.io \
      vaultpolicies.vault.platform.io \
      vaultclusterpolicies.vault.platform.io \
      vaultroles.vault.platform.io \
      vaultclusterroles.vault.platform.io

    kubectl delete namespace vault-access-operator-system
    ```

=== "kubectl"

    ```bash
    kubectl delete -f https://raw.githubusercontent.com/panteparak/vault-access-operator/main/dist/install.yaml
    ```

---

## Next Steps

- [Configuration](configuration.md) - Helm chart options
- [API Reference](api-reference.md) - Detailed CRD documentation
- [Examples](examples.md) - More usage examples
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
