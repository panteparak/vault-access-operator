# Examples

This page provides complete CRD examples for various deployment scenarios.

---

## VaultConnection Examples

### Basic Kubernetes Auth

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

### With TLS CA Certificate

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
```

### Bootstrap with Token

Use a one-time token to bootstrap Kubernetes auth:

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

### AppRole Authentication

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

### JWT Auth with TokenRequest API

Use short-lived Kubernetes service account tokens for JWT authentication:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: jwt-tokenrequest
spec:
  address: https://vault.example.com:8200
  auth:
    jwt:
      role: my-jwt-role
      audiences: ["vault"]
      tokenDuration: 30m
      userClaim: sub
      groupsClaim: groups
```

### JWT Auth with External Provider (AWS Cognito)

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: jwt-cognito
spec:
  address: https://vault.example.com:8200
  auth:
    jwt:
      role: cognito-role
      jwtSecretRef:
        name: cognito-token
        namespace: vault-access-operator-system
        key: id_token
      expectedIssuer: "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_EXAMPLE"
      expectedAudience: "client-id"
      userClaim: "cognito:username"
      groupsClaim: "cognito:groups"
```

### OIDC Auth for EKS (Workload Identity)

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: eks-oidc
spec:
  address: https://vault.example.com:8200
  auth:
    oidc:
      role: eks-workload-role
      providerURL: https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E
      audiences: ["sts.amazonaws.com"]
      tokenDuration: 1h
```

### OIDC Auth for Azure AD

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: azure-oidc
spec:
  address: https://vault.example.com:8200
  auth:
    oidc:
      role: azure-role
      providerURL: https://login.microsoftonline.com/TENANT-ID/v2.0
      jwtSecretRef:
        name: azure-token
        namespace: vault-access-operator-system
        key: access_token
      userClaim: preferred_username
      groupsClaim: groups
```

### AWS IAM Auth (EKS with IRSA)

For EKS workloads using IAM Roles for Service Accounts:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: aws-iam
spec:
  address: https://vault.example.com:8200
  auth:
    aws:
      role: eks-iam-role
      authType: iam
      region: us-west-2
```

### AWS IAM Auth with Custom STS Endpoint

For VPC endpoints or private clusters:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: aws-iam-private
spec:
  address: https://vault.internal:8200
  auth:
    aws:
      role: eks-iam-role
      authType: iam
      region: us-west-2
      stsEndpoint: https://sts.us-west-2.amazonaws.com
      iamServerIdHeaderValue: vault.example.com
```

### GCP IAM Auth (GKE with Workload Identity)

For GKE workloads using Workload Identity:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: gcp-iam
spec:
  address: https://vault.example.com:8200
  auth:
    gcp:
      role: gke-workload-role
      authType: iam
      serviceAccountEmail: vault-auth@my-project.iam.gserviceaccount.com
```

### GCP Auth with Service Account Key

For environments without Workload Identity:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: gcp-sa-key
spec:
  address: https://vault.example.com:8200
  auth:
    gcp:
      role: gcp-role
      authType: iam
      credentialsSecretRef:
        name: gcp-credentials
        namespace: vault-access-operator-system
        key: credentials.json
```

---

## VaultPolicy Examples

### Simple Read Policy

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

### Full CRUD Access

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: app-full-access
  namespace: my-app
spec:
  connectionRef: vault-primary
  enforceNamespaceBoundary: true
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [create, read, update, delete, list]
      description: "Full access to namespace secrets"
    - path: "secret/metadata/{{namespace}}/*"
      capabilities: [read, list, delete]
      description: "Manage secret metadata"
```

### Transit Encryption Policy

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

### Retain on Delete

Keep the policy in Vault when the Kubernetes resource is deleted:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: persistent-policy
  namespace: my-app
spec:
  connectionRef: vault-primary
  deletionPolicy: Retain
  rules:
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read]
```

---

## VaultClusterPolicy Examples

### Shared Secrets Reader

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: shared-secrets-reader
spec:
  connectionRef: vault-primary
  rules:
    - path: "secret/data/shared/*"
      capabilities: [read, list]
      description: "Read shared configuration"
    - path: "secret/data/global/config"
      capabilities: [read]
      description: "Read global config"
```

### Platform Admin Policy

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

### CI/CD Pipeline Secrets

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: cicd-secrets
spec:
  connectionRef: vault-primary
  rules:
    - path: "secret/data/cicd/*"
      capabilities: [read, list]
      description: "Read CI/CD secrets"
    - path: "secret/data/docker-registry"
      capabilities: [read]
      description: "Docker registry credentials"
```

### PKI Certificate Issuer

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterPolicy
metadata:
  name: pki-issuer
spec:
  connectionRef: vault-primary
  rules:
    - path: "pki/issue/internal"
      capabilities: [create, update]
      description: "Issue internal certificates"
    - path: "pki/ca/pem"
      capabilities: [read]
      description: "Read CA certificate"
```

---

## VaultRole Examples

### Basic Application Role

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
  policies:
    - kind: VaultPolicy
      name: app-secrets
  tokenTTL: 1h
  tokenMaxTTL: 4h
```

### Multiple Service Accounts

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: backend-services
  namespace: my-app
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - api-server
    - worker
    - scheduler
  policies:
    - kind: VaultPolicy
      name: backend-secrets
  tokenTTL: 30m
```

### Mixed Policy Types

Combine namespace-scoped and cluster-wide policies:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: full-access
  namespace: my-app
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - default
  policies:
    - kind: VaultPolicy
      name: app-secrets
    - kind: VaultClusterPolicy
      name: shared-config-reader
    - kind: VaultClusterPolicy
      name: database-readonly
  tokenTTL: 1h
```

### Short-lived Tokens for Batch Jobs

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: batch-job
  namespace: batch
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - batch-runner
  policies:
    - kind: VaultPolicy
      name: batch-secrets
  tokenTTL: 5m
  tokenMaxTTL: 15m
```

---

## VaultClusterRole Examples

### Platform Services Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: platform-services
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: platform-controller
      namespace: platform-system
    - name: monitoring-agent
      namespace: monitoring
    - name: logging-collector
      namespace: logging
  policies:
    - kind: VaultClusterPolicy
      name: shared-secrets-reader
  tokenTTL: 1h
  tokenMaxTTL: 24h
```

### CI/CD Pipeline Role

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
    - name: github-actions-runner
      namespace: actions-runner-system
  policies:
    - kind: VaultClusterPolicy
      name: cicd-secrets
  tokenTTL: 15m
  tokenMaxTTL: 1h
```

### Ingress Controller Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: ingress-controller
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: nginx-ingress-controller
      namespace: ingress-nginx
  policies:
    - kind: VaultClusterPolicy
      name: pki-issuer
  tokenTTL: 30m
```

### External Secrets Operator Role

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultClusterRole
metadata:
  name: external-secrets
spec:
  connectionRef: vault-primary
  serviceAccounts:
    - name: external-secrets
      namespace: external-secrets
  policies:
    - kind: VaultClusterPolicy
      name: secrets-reader-all
  tokenTTL: 1h
  tokenMaxTTL: 4h
```

---

## Complete Application Setup

A complete example for setting up Vault access for a microservices application:

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

---

## Next Steps

- [Getting Started](getting-started.md) - Installation guide
- [API Reference](api-reference.md) - CRD field documentation
- [Configuration](configuration.md) - Helm chart options
- [Troubleshooting](troubleshooting.md) - Common issues
