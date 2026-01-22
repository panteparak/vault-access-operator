# Installation

This guide covers all installation methods for the Vault Access Operator.

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
- Kubernetes authentication method enabled (recommended)

To enable the Kubernetes auth method in Vault:

```bash
# Enable Kubernetes auth
vault auth enable kubernetes

# Configure Kubernetes auth (run from within the cluster or with appropriate access)
vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

### cert-manager (Optional but Recommended)

cert-manager is recommended for managing webhook certificates:

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml

# Wait for cert-manager to be ready
kubectl wait --for=condition=Available deployment --all -n cert-manager --timeout=300s
```

!!! note "Without cert-manager"
    If you prefer not to use cert-manager, you can use self-signed certificates or disable webhooks entirely. See the [Configuration](configuration/helm-values.md) for details.

## Installation Methods

### Helm (Recommended)

Helm is the recommended installation method as it provides the most flexibility.

#### Add the Repository

```bash
helm repo add vault-access-operator https://panteparak.github.io/vault-access-operator/charts
helm repo update
```

#### Basic Installation

```bash
helm install vault-access-operator vault-access-operator/vault-access-operator \
  --namespace vault-access-operator-system \
  --create-namespace
```

#### Installation with Custom Values

```bash
# Using a values file
helm install vault-access-operator vault-access-operator/vault-access-operator \
  --namespace vault-access-operator-system \
  --create-namespace \
  -f my-values.yaml

# Or with inline values
helm install vault-access-operator vault-access-operator/vault-access-operator \
  --namespace vault-access-operator-system \
  --create-namespace \
  --set replicaCount=3 \
  --set logging.level=debug
```

#### Production Installation

For production environments, use the production values file:

```bash
helm install vault-access-operator vault-access-operator/vault-access-operator \
  --namespace vault-access-operator-system \
  --create-namespace \
  -f https://raw.githubusercontent.com/panteparak/vault-access-operator/main/charts/vault-access-operator/examples/values-production.yaml
```

See [Configuration Examples](configuration/examples.md) for more example values files.

### kubectl

For simple installations without Helm:

```bash
# Apply the installation manifest
kubectl apply -f https://raw.githubusercontent.com/panteparak/vault-access-operator/main/dist/install.yaml
```

This installs the operator with default settings. To customize, download and modify the manifest:

```bash
# Download the manifest
curl -sL https://raw.githubusercontent.com/panteparak/vault-access-operator/main/dist/install.yaml -o install.yaml

# Edit as needed
vim install.yaml

# Apply
kubectl apply -f install.yaml
```

### From Source

For development or when you need to build from source:

```bash
# Clone the repository
git clone https://github.com/panteparak/vault-access-operator.git
cd vault-access-operator

# Install CRDs
make install

# Deploy the operator
make deploy IMG=ghcr.io/panteparak/vault-access-operator:latest
```

To run locally for development:

```bash
# Run the operator locally (outside the cluster)
make run
```

## Verify Installation

After installation, verify that everything is running correctly:

### Check the Operator Pod

```bash
kubectl get pods -n vault-access-operator-system
```

Expected output:

```
NAME                                                         READY   STATUS    RESTARTS   AGE
vault-access-operator-controller-manager-xxxxxxxxxx-xxxxx    1/1     Running   0          1m
```

### Check CRDs

```bash
kubectl get crds | grep vault.platform.io
```

Expected output:

```
vaultclusterpolicies.vault.platform.io    2024-01-15T10:00:00Z
vaultclusterroles.vault.platform.io       2024-01-15T10:00:00Z
vaultconnections.vault.platform.io        2024-01-15T10:00:00Z
vaultpolicies.vault.platform.io           2024-01-15T10:00:00Z
vaultroles.vault.platform.io              2024-01-15T10:00:00Z
```

### Check Operator Logs

```bash
kubectl logs -n vault-access-operator-system -l control-plane=controller-manager
```

### Check Webhooks (if enabled)

```bash
kubectl get validatingwebhookconfigurations | grep vault
```

## Configure Vault for the Operator

Before creating resources, you need to configure Vault to allow the operator to manage policies and roles.

### Create Operator Policy in Vault

```bash
vault policy write vault-access-operator - <<EOF
# Manage policies
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# List policies
path "sys/policies/acl" {
  capabilities = ["list"]
}

# Manage Kubernetes auth roles
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

# Read auth configuration
path "auth/kubernetes/config" {
  capabilities = ["read", "update"]
}

# Manage auth methods (for bootstrap)
path "sys/auth" {
  capabilities = ["read"]
}

path "sys/auth/*" {
  capabilities = ["sudo", "create", "read", "update", "delete", "list"]
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

## Uninstallation

### Helm

```bash
# Uninstall the operator
helm uninstall vault-access-operator -n vault-access-operator-system

# Optionally delete CRDs (this will delete all managed resources!)
kubectl delete crds \
  vaultconnections.vault.platform.io \
  vaultpolicies.vault.platform.io \
  vaultclusterpolicies.vault.platform.io \
  vaultroles.vault.platform.io \
  vaultclusterroles.vault.platform.io

# Delete the namespace
kubectl delete namespace vault-access-operator-system
```

### kubectl

```bash
kubectl delete -f https://raw.githubusercontent.com/panteparak/vault-access-operator/main/dist/install.yaml
```

## Next Steps

- Follow the [Quick Start](quickstart.md) to create your first resources
- Read the [Configuration Reference](configuration/helm-values.md) for all available options
- Check the [API Reference](api-reference/index.md) for CRD documentation
