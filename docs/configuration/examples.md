# Configuration Examples

This page provides complete example configurations for various deployment scenarios.

## Helm Values Examples

### Minimal Installation

The simplest configuration to get started:

```yaml
# values-minimal.yaml
replicaCount: 1

webhook:
  certManager:
    enabled: true

logging:
  level: info
```

Install with:

```bash
helm install vault-access-operator vault-access-operator/vault-access-operator \
  --namespace vault-access-operator-system \
  --create-namespace \
  -f values-minimal.yaml
```

### Production High Availability

A production-ready configuration with high availability:

```yaml
# values-production.yaml
replicaCount: 3

resources:
  limits:
    cpu: "1"
    memory: 512Mi
  requests:
    cpu: 250m
    memory: 256Mi

# Ensure pods spread across nodes
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: vault-access-operator
          topologyKey: kubernetes.io/hostname

# Pod disruption budget for safe updates
podDisruptionBudget:
  enabled: true
  minAvailable: 2

# Priority class for critical workloads
priorityClassName: system-cluster-critical

# Leader election tuning
leaderElection:
  enabled: true
  leaseDuration: 15s
  renewDeadline: 10s
  retryPeriod: 2s

# Production logging
logging:
  level: info
  development: false
  encoder: json
  stacktraceLevel: error

# Webhook configuration
webhook:
  enabled: true
  failurePolicy: Fail
  certManager:
    enabled: true
    duration: 8760h
    renewBefore: 720h

# Metrics for observability
metrics:
  enabled: true
  secure: true

serviceMonitor:
  enabled: true
  interval: 30s
```

### With Prometheus Monitoring

Configuration for Prometheus Operator integration:

```yaml
# values-monitoring.yaml
metrics:
  enabled: true
  secure: true
  port: 8443
  service:
    type: ClusterIP
    port: 8443
    annotations:
      prometheus.io/scrape: "true"
      prometheus.io/port: "8443"

serviceMonitor:
  enabled: true
  namespace: monitoring
  labels:
    release: prometheus
  interval: 30s
  scrapeTimeout: 10s
  metricRelabelings:
    - sourceLabels: [__name__]
      regex: "controller_runtime_.*"
      action: keep
  relabelings:
    - sourceLabels: [__meta_kubernetes_pod_node_name]
      targetLabel: node
```

### Without cert-manager

If you're not using cert-manager, you can disable webhooks or use self-signed certificates:

=== "Disable Webhooks"

    ```yaml
    # values-no-webhooks.yaml
    webhook:
      enabled: false
    ```

=== "Self-signed Certificates"

    ```yaml
    # values-self-signed.yaml
    webhook:
      enabled: true
      certManager:
        enabled: false
      selfSigned:
        enabled: true
        validityDays: 365
    ```

### Air-gapped Environment

For environments without internet access:

```yaml
# values-airgapped.yaml
image:
  repository: internal-registry.example.com/vault-access-operator
  pullPolicy: IfNotPresent
  tag: "v0.1.0"

imagePullSecrets:
  - name: internal-registry-creds

# Pre-provisioned TLS certificates
webhook:
  certManager:
    enabled: false
  selfSigned:
    enabled: true
```

### Development/Testing

For local development or testing:

```yaml
# values-dev.yaml
replicaCount: 1

logging:
  level: debug
  development: true
  encoder: console

resources:
  limits:
    cpu: 200m
    memory: 128Mi
  requests:
    cpu: 50m
    memory: 64Mi

webhook:
  enabled: true
  failurePolicy: Ignore  # Don't block on webhook failures
  certManager:
    enabled: true
```

---

## CRD Examples

### VaultConnection Examples

#### Basic Kubernetes Auth

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-primary
spec:
  address: https://vault.example.com:8200
  auth:
    kubernetes:
      role: vault-access-operator
  healthCheckInterval: 30s
```

#### With TLS CA Certificate

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-with-tls
spec:
  address: https://vault.internal:8200
  auth:
    kubernetes:
      role: vault-access-operator
      authPath: kubernetes
  tls:
    skipVerify: false
    caSecretRef:
      name: vault-ca-cert
      namespace: vault-access-operator-system
      key: ca.crt
  defaults:
    authPath: auth/kubernetes
```

#### Bootstrap with Token

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-bootstrap
spec:
  address: https://vault.example.com:8200
  auth:
    bootstrap:
      secretRef:
        name: vault-bootstrap-token
        namespace: vault-access-operator-system
        key: token
      autoRevoke: true
    kubernetes:
      role: vault-access-operator
```

#### AppRole Authentication

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-approle
spec:
  address: https://vault.example.com:8200
  auth:
    appRole:
      roleId: "your-role-id"
      secretIdRef:
        name: vault-approle-secret
        namespace: vault-access-operator-system
        key: secret-id
      mountPath: approle
```

### VaultPolicy Examples

#### Simple Read Policy

```yaml
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
      description: "Read application secrets"
```

#### Full CRUD Access

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: app-full-access
  namespace: my-app
spec:
  connectionRef: vault-primary
  conflictPolicy: Fail
  deletionPolicy: Delete
  enforceNamespaceBoundary: true
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [create, read, update, delete, list]
      description: "Full access to namespace secrets"
    - path: "secret/metadata/{{namespace}}/*"
      capabilities: [read, list, delete]
      description: "Manage secret metadata"
```

#### Transit Encryption Policy

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: transit-encrypt
  namespace: my-app
spec:
  connectionRef: vault-primary
  rules:
    - path: "transit/encrypt/{{namespace}}-key"
      capabilities: [update]
      description: "Encrypt data"
    - path: "transit/decrypt/{{namespace}}-key"
      capabilities: [update]
      description: "Decrypt data"
```

### VaultClusterPolicy Examples

#### Shared Secrets Reader

```yaml
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
      description: "Read shared configuration"
    - path: "secret/data/global/config"
      capabilities: [read]
      description: "Read global config"
```

#### Platform Admin Policy

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: platform-admin
spec:
  connectionRef: vault-primary
  rules:
    - path: "secret/*"
      capabilities: [create, read, update, delete, list]
    - path: "auth/kubernetes/role/*"
      capabilities: [read, list]
    - path: "sys/policies/acl/*"
      capabilities: [read, list]
```

### VaultRole Examples

#### Basic Application Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: app-role
  namespace: my-app
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - default
    - app-sa
  policies:
    - kind: VaultPolicy
      name: app-secrets
  tokenTTL: 1h
  tokenMaxTTL: 4h
```

#### Role with Mixed Policies

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: app-with-shared
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
  tokenTTL: 30m
  tokenMaxTTL: 2h
  deletionPolicy: Delete
```

### VaultClusterRole Examples

#### Platform Services Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: platform-services
spec:
  connectionRef: vault-primary
  authPath: auth/kubernetes
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

#### CI/CD Pipeline Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: cicd-pipeline
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: tekton-pipeline
      namespace: tekton-pipelines
    - name: argo-workflow
      namespace: argo
  policies:
    - kind: VaultClusterPolicy
      name: cicd-secrets
  tokenTTL: 15m
  tokenMaxTTL: 1h
  conflictPolicy: Adopt
```

---

## Complete Application Setup

Here's a complete example for setting up Vault access for a microservices application:

```yaml
---
# 1. Shared policy for all services
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: shared-config
spec:
  connectionRef: vault-primary
  rules:
    - path: "secret/data/shared/database"
      capabilities: [read]
    - path: "secret/data/shared/messaging"
      capabilities: [read]
---
# 2. Namespace-specific policy
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: api-service
  namespace: production
spec:
  connectionRef: vault-primary
  enforceNamespaceBoundary: true
  rules:
    - path: "secret/data/{{namespace}}/api/*"
      capabilities: [read, list]
---
# 3. Role binding for API service
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: api-service
  namespace: production
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - api-service
  policies:
    - kind: VaultPolicy
      name: api-service
    - kind: VaultClusterPolicy
      name: shared-config
  tokenTTL: 1h
---
# 4. Service account for the application
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-service
  namespace: production
---
# 5. Application deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-service
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-service
  template:
    metadata:
      labels:
        app: api-service
    spec:
      serviceAccountName: api-service
      containers:
        - name: api
          image: my-api:latest
          env:
            - name: VAULT_ADDR
              value: "https://vault.example.com:8200"
            - name: VAULT_AUTH_ROLE
              value: "production-api-service"
```
