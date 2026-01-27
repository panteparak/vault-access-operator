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

!!! warning "Security Notice: Never Use Root Token"
    The operator should **never** use the Vault root token in production. Always use a dedicated service account with the minimum required permissions as described below.

### Principle of Least Privilege

The Vault Access Operator follows the **Principle of Least Privilege**—it only requests the minimum permissions necessary to perform its job. Understanding these permissions helps you:

1. **Audit** what the operator can and cannot do
2. **Trust** that secrets are not directly accessible to the operator
3. **Comply** with security requirements in regulated environments

#### What the Operator Needs

| Path | Capabilities | Purpose |
|------|--------------|---------|
| `sys/policies/acl/*` | create, read, update, delete, list | Manage Vault policies |
| `sys/policies/acl` | list | List existing policies |
| `auth/kubernetes/role/*` | create, read, update, delete, list | Manage Kubernetes auth roles |
| `auth/kubernetes/role` | list | List existing roles |
| `auth/kubernetes/config` | read, update | Configure Kubernetes auth method |
| `sys/health` | read | Health checks for connection status |

#### What the Operator Does NOT Need

| Path | Reason |
|------|--------|
| `secret/*` | The operator manages **access** to secrets, not the secrets themselves |
| `sys/seal`, `sys/unseal` | Administrative operations only |
| `sys/init` | Vault initialization is out of scope |
| `identity/*` | Entity/alias management not required |
| Root capability | Never required for normal operation |

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

# Configure Kubernetes auth method (optional, for initial setup)
path "auth/kubernetes/config" {
  capabilities = ["create", "read", "update", "delete"]
}

# Enable/disable auth methods (optional, for bootstrapping)
path "sys/auth" {
  capabilities = ["read"]
}
path "sys/auth/*" {
  capabilities = ["sudo", "create", "read", "update", "delete", "list"]
}

# Health check
path "sys/health" {
  capabilities = ["read"]
}
EOF
```

!!! tip "Verify Token Capabilities"
    You can verify what a token can access using:
    ```bash
    # Check capabilities on a specific path
    vault token capabilities <token> sys/policies/acl/test
    # Expected: create, delete, list, read, update

    # Verify secrets are denied
    vault token capabilities <token> secret/data/test
    # Expected: deny
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

## Choosing an Authentication Method

The operator supports multiple authentication methods. Choose based on your environment:

| Method | Best For | Prerequisites |
|--------|----------|---------------|
| **Kubernetes** | Standard K8s deployments | Vault K8s auth configured |
| **JWT** | External identity providers | JWT auth mount in Vault |
| **OIDC** | EKS, AKS, GKE workload identity | OIDC provider configured in Vault |
| **AWS** | EKS with IRSA | IAM role with trust policy |
| **GCP** | GKE with Workload Identity | GCP SA with IAM bindings |
| **Token** | Development/testing | Vault token available |
| **AppRole** | Machine-to-machine | AppRole credentials |
| **Bootstrap** | Initial setup | Privileged token |

### When to Use Each Method

**Kubernetes Auth** (Recommended for most cases)

- Works with any Kubernetes cluster
- Automatic token rotation via TokenRequest API
- No external dependencies beyond Vault

```yaml
auth:
  kubernetes:
    role: vault-access-operator
```

**OIDC Auth** (Recommended for cloud providers)

- **EKS**: Use OIDC issuer URL from `aws eks describe-cluster`
- **GKE**: Use Workload Identity federation
- **AKS**: Use Azure AD integration

```yaml
auth:
  oidc:
    role: eks-workload-role
    providerURL: https://oidc.eks.us-west-2.amazonaws.com/id/CLUSTER_ID
```

**AWS Auth** (EKS-specific)

- Uses IRSA (IAM Roles for Service Accounts)
- Requires IAM role with trust policy for the service account
- Auto-detects region and credentials from environment

```yaml
auth:
  aws:
    role: eks-iam-role
    authType: iam
```

**GCP Auth** (GKE-specific)

- Uses Workload Identity for automatic credential management
- Requires GCP service account binding to K8s service account
- Auto-detects credentials from metadata server

```yaml
auth:
  gcp:
    role: gke-workload-role
    authType: iam
```

---

## Token Lifecycle Management

The operator automatically manages Vault token lifecycle:

1. **Initial Authentication** - Obtains Vault token using configured auth method
2. **Token Renewal** - Renews token before expiration (default: 75% of TTL)
3. **Re-authentication** - Falls back to full re-auth if renewal fails
4. **Token Reviewer Rotation** - Automatically rotates token_reviewer_jwt for K8s auth

### Monitoring Token Status

Check token status in VaultConnection:

```bash
kubectl get vaultconnection my-connection -o jsonpath='{.status.authStatus}'
```

Key fields:

- `tokenExpiration` - When current token expires
- `tokenLastRenewed` - Last renewal time
- `tokenRenewalCount` - Total renewals since last full auth
- `tokenReviewerExpiration` - token_reviewer_jwt expiration (K8s auth only)

### Token Reviewer JWT Rotation

!!! warning "Important for Kubernetes Auth"
    The `token_reviewer_jwt` is used by Vault to verify service account tokens.
    If it expires and isn't rotated, all Kubernetes authentication will fail.

The operator automatically rotates this JWT when `tokenReviewerRotation: true` (default).
You can monitor the rotation status via:

```bash
kubectl get vaultconnection my-connection -o jsonpath='{.status.authStatus.tokenReviewerExpiration}'
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
