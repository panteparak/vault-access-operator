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
    # "kubernetes" = auth mount name — substitute yours (vault auth list)
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

### JWT-Backed Role (ESO workloads)

When `authPath` targets a JWT auth mount (e.g. `auth/jwt`), the operator writes
a JWT role to Vault. Defaults are derived from the referenced `VaultConnection`
and `serviceAccounts`:

- `role_type=jwt`
- `user_claim=sub`
- `bound_subject=system:serviceaccount:<namespace>:<serviceAccounts[0]>`
- `bound_audiences=<VaultConnection.spec.auth.jwt.audiences>` when available,
  otherwise `["https://kubernetes.default.svc.cluster.local"]`

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: eso
  namespace: my-app
spec:
  connectionRef: vault-jwt
  authPath: auth/jwt
  serviceAccounts:
    - my-app-eso
  policies:
    - kind: VaultPolicy
      name: app-secrets-reader
  tokenTTL: 1h
  tokenMaxTTL: 4h
```

Override the derived defaults through `spec.jwt`:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: eso-custom
  namespace: my-app
spec:
  connectionRef: vault-jwt
  authPath: auth/jwt
  serviceAccounts:
    - my-app-eso
  policies:
    - kind: VaultPolicy
      name: app-secrets-reader
  jwt:
    userClaim: email
    boundAudiences:
      - https://vault.example.com
    boundClaims:
      groups: eso-writers
```

**Multi-serviceAccount caveat**: JWT's `bound_subject` holds a single value.
A JWT VaultRole with more than one `serviceAccount` must set
`spec.jwt.boundSubject`, `spec.jwt.boundClaims`, or `spec.jwt.boundClaimsList`
explicitly, otherwise the webhook rejects the resource. The three supported
patterns for a multi-SA JWT role are:

#### Pattern A — one VaultRole per ServiceAccount (recommended)

Most explicit; no shared vault role; simplest to reason about. Each role
issues a distinct Vault token with a distinct alias, so audit logs show
which SA authenticated.

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata: { name: eso-reader, namespace: my-app }
spec:
  connectionRef: vault-jwt
  authPath: auth/jwt
  serviceAccounts: [eso-reader]
  policies:
    - { kind: VaultPolicy, name: app-secrets-reader }
---
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata: { name: eso-writer, namespace: my-app }
spec:
  connectionRef: vault-jwt
  authPath: auth/jwt
  serviceAccounts: [eso-writer]
  policies:
    - { kind: VaultPolicy, name: app-secrets-writer }
```

#### Pattern B — explicit `boundSubject` to a shared value

If your SAs' JWTs all carry a shared claim (e.g. every pod mounts the
same SA after a controller swap), set the literal shared `sub` value:

```yaml
spec:
  serviceAccounts: [reader-sa, writer-sa]
  jwt:
    # Matches tokens whose `sub` equals this exact string.
    boundSubject: system:serviceaccount:my-app:shared-sa
```

This only makes sense when your workloads actually share the SA — if
each SA produces a different `sub`, Vault rejects the mismatched ones.

#### Pattern C — `boundClaimsList` on a stable identity-token claim

When your IdP issues JWTs with a claim that identifies a team or
project (not per-SA), match on that instead. `boundClaimsList` is
`map[string][]string` — any value in the list matches:

```yaml
spec:
  serviceAccounts: [reader-sa, writer-sa]  # informational only; not used in Vault match
  jwt:
    boundClaimsList:
      # Match any token whose `sub` is one of the listed SAs
      sub:
        - system:serviceaccount:my-app:reader-sa
        - system:serviceaccount:my-app:writer-sa
```

(The older scalar `boundClaims` field still works but is deprecated —
see [Binding VaultRoles to JWT claims](auth-methods/jwt.md#binding-vaultroles-to-jwt-claims).)

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

## VaultKVSecret Examples

`VaultKVSecret` pre-creates ("seeds") a KV v2 secret path so External Secrets
Operator (ESO) doesn't fail with a 404 when the path doesn't exist yet on a fresh
deployment. The operator only ever **creates** the path when it is absent — it never
overwrites or reads the values stored there.

### Seed a Truly-Empty Path

Omit `data` to seed an empty secret (`{}`) at version 1:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultKVSecret
metadata:
  name: app-config
  namespace: my-app
spec:
  connectionRef: vault-primary
  # Full KV v2 data path — must contain a "/data/" segment. Immutable.
  path: secret/data/apps/my-app/config
```

```bash
kubectl get vaultkvsecret -n my-app
# NAME         PATH                             PHASE    SEEDED   AGE
# app-config   secret/data/apps/my-app/config   Active   true     1m
```

### Seed Placeholder Keys

List keys with empty-string values when ESO references a specific `property`:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultKVSecret
metadata:
  name: app-config
  namespace: my-app
spec:
  connectionRef: vault-primary
  path: secret/data/apps/my-app/config
  # Written ONLY if the path is absent — never overwrites real data.
  data:
    username: ""
    password: ""
```

### Retain the Secret on Deletion

`deletionPolicy: Retain` never deletes the seeded secret. The default `Delete`
removes it only if it is still operator-owned and unmodified since seeding
(delete-if-untouched):

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultKVSecret
metadata:
  name: persistent-config
  namespace: my-app
spec:
  connectionRef: vault-primary
  path: secret/data/apps/my-app/persistent
  data:
    api_key: ""
  deletionPolicy: Retain
```

!!! note "Empty `{}` vs placeholder keys (for ESO)"
    A truly-empty `{}` seed is enough for an ESO `ExternalSecret` that reads the
    **whole** secret (`spec.dataFrom`). But an ESO `spec.data[].remoteRef.property`
    reference to a specific key (e.g. `password`) still fails until that key exists —
    so seed placeholder keys for `.property` references. Either way, the seed
    guarantees the path exists so ESO's first sync resolves instead of 404-ing.

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
