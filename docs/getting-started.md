# Getting Started

This guide walks you through setting up the Vault Access Operator and creating your first Vault policies and roles.

## Prerequisites

Before installing the Vault Access Operator, ensure you have the following:

### Kubernetes Cluster

- Kubernetes v1.25 or later
- `kubectl` configured to access your cluster
- Cluster admin permissions for installing CRDs

Verify your cluster:

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
# Enable Kubernetes auth
vault auth enable kubernetes

# Configure Kubernetes auth (run from within the cluster or with appropriate access)
vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

### cert-manager

cert-manager is required for managing webhook certificates:

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml

# Wait for cert-manager to be ready
kubectl wait --for=condition=Available deployment --all -n cert-manager --timeout=300s
```

## Installation

### Option 1: Using Helm (Recommended)

```bash
# Add the Helm repository
helm repo add vault-access-operator https://panteparak.github.io/vault-access-operator
helm repo update

# Create namespace
kubectl create namespace vault-access-operator-system

# Install the operator
helm install vault-access-operator vault-access-operator/vault-access-operator \
  --namespace vault-access-operator-system \
  --set webhook.certManager.enabled=true
```

### Option 2: Using kubectl

```bash
# Apply the installation manifest
kubectl apply -f https://raw.githubusercontent.com/panteparak/vault-access-operator/main/dist/install.yaml
```

### Option 3: From Source

```bash
# Clone the repository
git clone https://github.com/panteparak/vault-access-operator.git
cd vault-access-operator

# Install CRDs
make install

# Deploy the operator
make deploy IMG=ghcr.io/panteparak/vault-access-operator:latest
```

### Verify Installation

```bash
# Check the operator is running
kubectl get pods -n vault-access-operator-system

# Check CRDs are installed
kubectl get crds | grep vault.platform.io
```

You should see output similar to:

```
vaultclusterpolicies.vault.platform.io    2024-01-15T10:00:00Z
vaultclusterroles.vault.platform.io       2024-01-15T10:00:00Z
vaultconnections.vault.platform.io        2024-01-15T10:00:00Z
vaultpolicies.vault.platform.io           2024-01-15T10:00:00Z
vaultroles.vault.platform.io              2024-01-15T10:00:00Z
```

## Creating a VaultConnection

The first step is to establish a connection to your Vault server.

### Step 1: Create Vault Role for the Operator

First, create a role in Vault that the operator will use to authenticate:

```bash
# Create a policy for the operator
vault policy write vault-access-operator - <<EOF
# Manage policies
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# List policies
path "sys/policies/acl" {
  capabilities = ["list"]
}

# Manage auth methods
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# List auth roles
path "auth/kubernetes/role" {
  capabilities = ["list"]
}

# Check Vault health
path "sys/health" {
  capabilities = ["read"]
}

# Manage KV metadata (for managed markers)
path "secret/metadata/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# Create a Kubernetes auth role for the operator
vault write auth/kubernetes/role/vault-access-operator \
    bound_service_account_names=vault-access-operator-controller-manager \
    bound_service_account_namespaces=vault-access-operator-system \
    policies=vault-access-operator \
    ttl=1h
```

### Step 2: Create VaultConnection Resource

If your Vault uses TLS with a custom CA, first create a secret with the CA certificate:

```bash
# Create secret with CA certificate (if using custom CA)
kubectl create secret generic vault-ca-cert \
  --from-file=ca.crt=/path/to/ca.crt \
  -n vault-access-operator-system
```

Create the VaultConnection:

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
      mountPath: kubernetes
  tls:
    skipVerify: false
    caSecretRef:
      name: vault-ca-cert
      namespace: vault-access-operator-system
      key: ca.crt
  healthCheckInterval: 30s
  defaults:
    authPath: auth/kubernetes
```

Apply the configuration:

```bash
kubectl apply -f vault-connection.yaml
```

### Step 3: Verify Connection

```bash
kubectl get vaultconnection vault-primary

# Check detailed status
kubectl describe vaultconnection vault-primary
```

You should see the connection in `Active` phase:

```
NAME            ADDRESS                          PHASE    VERSION   AGE
vault-primary   https://vault.example.com:8200   Active   1.15.0    1m
```

## Creating Your First Policy

### VaultClusterPolicy (Cluster-wide)

Create a cluster-wide policy that grants read access to shared secrets:

```yaml
# shared-secrets-policy.yaml
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
    - path: "secret/metadata/shared/*"
      capabilities: [read, list]
      description: "Read metadata for shared secrets"
```

Apply and verify:

```bash
kubectl apply -f shared-secrets-policy.yaml

# Check status
kubectl get vaultclusterpolicy shared-secrets-reader
kubectl describe vaultclusterpolicy shared-secrets-reader
```

### VaultPolicy (Namespace-scoped)

Create a namespace-scoped policy with namespace boundary enforcement:

```yaml
# app-secrets-policy.yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: app-secrets
  namespace: my-app
spec:
  connectionRef: vault-primary
  enforceNamespaceBoundary: true  # Explicitly enabled (default: false)
  conflictPolicy: Fail
  deletionPolicy: Delete
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read, list]
      description: "Read secrets for this namespace"
    - path: "secret/data/{{namespace}}/{{name}}/*"
      capabilities: [create, read, update, delete, list]
      description: "Full access to app-specific secrets"
```

Apply and verify:

```bash
# Create namespace if it doesn't exist
kubectl create namespace my-app

kubectl apply -f app-secrets-policy.yaml

# Check status
kubectl get vaultpolicy -n my-app
kubectl describe vaultpolicy app-secrets -n my-app
```

The policy in Vault will be named `my-app-app-secrets` and the paths will be substituted to `secret/data/my-app/*`.

## Creating Your First Role

### VaultClusterRole (Cluster-wide)

Create a cluster-wide role that binds service accounts to policies:

```yaml
# platform-services-role.yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: platform-services
spec:
  connectionRef: vault-primary
  authPath: auth/kubernetes
  conflictPolicy: Fail
  deletionPolicy: Delete
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

Apply and verify:

```bash
kubectl apply -f platform-services-role.yaml

# Check status
kubectl get vaultclusterrole platform-services
kubectl describe vaultclusterrole platform-services
```

### VaultRole (Namespace-scoped)

Create a namespace-scoped role that binds service accounts within a namespace:

```yaml
# app-role.yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: app-role
  namespace: my-app
spec:
  connectionRef: vault-primary
  conflictPolicy: Fail
  deletionPolicy: Delete
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

Apply and verify:

```bash
kubectl apply -f app-role.yaml

# Check status
kubectl get vaultrole -n my-app
kubectl describe vaultrole app-role -n my-app
```

## Testing Authentication

Test that the Vault authentication is working correctly:

### Step 1: Create Test Pod

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
    - name: test
      image: hashicorp/vault:latest
      command: ["sleep", "infinity"]
      env:
        - name: VAULT_ADDR
          value: "https://vault.example.com:8200"
```

```bash
kubectl apply -f test-pod.yaml
```

### Step 2: Authenticate to Vault

```bash
# Get into the pod
kubectl exec -it vault-test -n my-app -- /bin/sh

# Login to Vault using Kubernetes auth
vault login -method=kubernetes role=my-app-app-role

# Test reading a secret (create one in Vault first)
vault kv get secret/my-app/test-secret
```

### Step 3: Verify Policy Enforcement

Try to access secrets outside the namespace:

```bash
# This should fail with permission denied
vault kv get secret/other-namespace/secret

# This should succeed (if you have the shared-secrets-reader policy)
vault kv get secret/shared/common-config
```

## Viewing Resource Status

All resources expose their status through Kubernetes:

```bash
# List all vault resources
kubectl get vaultconnections
kubectl get vaultclusterpolicies
kubectl get vaultpolicies --all-namespaces
kubectl get vaultclusterroles
kubectl get vaultroles --all-namespaces

# Get detailed status
kubectl describe vaultconnection vault-primary
kubectl describe vaultclusterpolicy shared-secrets-reader
kubectl describe vaultpolicy app-secrets -n my-app

# Check conditions
kubectl get vaultpolicy app-secrets -n my-app -o jsonpath='{.status.conditions}'
```

## Next Steps

- Read the [CRD Reference](crd-reference.md) for detailed field documentation
- Check the [Troubleshooting Guide](troubleshooting.md) if you encounter issues
- Explore advanced features like conflict policies and deletion policies
- Set up monitoring with Prometheus using ServiceMonitor
