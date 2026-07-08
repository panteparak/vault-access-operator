# Admission Webhooks

The Vault Access Operator includes validating admission webhooks that enforce security constraints and configuration correctness before resources are created or updated.

## Overview

| Resource | Webhook Type | Purpose |
|----------|--------------|---------|
| VaultPolicy | Validating | Path syntax, capabilities, namespace boundary |
| VaultClusterPolicy | Validating | Path syntax, capabilities |
| VaultRole | Validating | Service account names, policy references, connection-derived auth mount |
| VaultClusterRole | Validating | Service account refs, policy references, connection-derived auth mount |
| VaultConnection | Validating | Auth method shape, role mount defaults, secret references |

---

## VaultPolicy Validation

### Path Validation

Paths must match the pattern: `^[a-zA-Z0-9/_*{}\-+]+$`

| Character | Allowed | Example |
|-----------|---------|---------|
| Letters | Yes | `secret/data/myapp` |
| Numbers | Yes | `secret/data/v2/app` |
| Slashes | Yes | `secret/data/namespace/key` |
| Underscores | Yes | `secret/data/my_app` |
| Asterisks | Yes | `secret/data/*` |
| Curly braces | Yes | `secret/data/{{namespace}}` |
| Hyphens | Yes | `secret/data/my-app` |
| Plus signs | Yes | `pki/issue/internal+external` |
| Spaces | **No** | `secret/data/my app` :x: |
| Special chars | **No** | `secret/data/@app` :x: |

### Capability Validation

Valid capabilities:

| Capability | Description |
|------------|-------------|
| `create` | Create new data |
| `read` | Read existing data |
| `update` | Modify existing data |
| `delete` | Remove data |
| `list` | List keys/paths |
| `sudo` | Elevated privileges |
| `deny` | Explicitly deny access |

!!! warning "Deny with Other Capabilities"
    When `deny` is combined with other capabilities, a warning is issued because `deny` takes precedence and other capabilities are ignored.

    ```yaml
    # Triggers a warning - other caps ignored
    capabilities: [deny, read, list]
    ```

### Namespace Boundary Enforcement

When `enforceNamespaceBoundary: true` is set on a VaultPolicy:

1. **All paths must contain `{{namespace}}`** - Ensures policies are scoped to their namespace
2. **No wildcards before `{{namespace}}`** - Prevents cross-namespace access

#### Valid Examples

```yaml
spec:
  enforceNamespaceBoundary: true
  rules:
    # Good: namespace variable present
    - path: "secret/data/{{namespace}}/*"
      capabilities: [read, list]

    # Good: namespace at the start
    - path: "{{namespace}}/secrets/*"
      capabilities: [read]

    # Good: fixed prefix before namespace
    - path: "tenants/{{namespace}}/config"
      capabilities: [read]
```

#### Invalid Examples

```yaml
spec:
  enforceNamespaceBoundary: true
  rules:
    # Bad: no {{namespace}} variable
    - path: "secret/data/shared/*"
      capabilities: [read]
      # Error: path must contain {{namespace}}

    # Bad: wildcard before namespace
    - path: "secret/data/*/{{namespace}}"
      capabilities: [read]
      # Error: wildcard before {{namespace}} is a security risk

    # Bad: wildcard prefix
    - path: "*/{{namespace}}/secrets"
      capabilities: [read]
      # Error: could match any tenant's path
```

!!! danger "Security Risk: Wildcards Before Namespace"
    A path like `secret/data/*/{{namespace}}` could allow access to:

    - `secret/data/other-tenant/my-namespace`
    - `secret/data/admin/my-namespace`

    This defeats the purpose of namespace isolation.

---

## VaultClusterPolicy Validation

VaultClusterPolicy follows the same path and capability validation as VaultPolicy, but:

- **No namespace boundary enforcement** - Cluster policies are not namespace-scoped
- **No `{{namespace}}` variable** - Use `{{name}}` for the resource name if needed

---

## VaultRole Validation

### Service Account Validation

Service accounts must be **simple names** without namespace prefixes:

```yaml
# Valid
serviceAccounts:
  - default
  - my-service-account
  - api-server

# Invalid - contains namespace prefix
serviceAccounts:
  - default/my-service-account  # Error!
  - my-namespace/api-server     # Error!
```

!!! note "Why Simple Names?"
    VaultRole is namespace-scoped, so all service accounts are assumed to be in the same namespace as the VaultRole. The namespace is automatically applied when creating the Vault role.

### Policy Reference Validation

| Reference Kind | Namespace Field | Behavior |
|----------------|-----------------|----------|
| `VaultPolicy` | Optional | Defaults to VaultRole's namespace |
| `VaultPolicy` | Specified | Uses the specified namespace |
| `VaultClusterPolicy` | Must be empty | Cluster-scoped, no namespace |

```yaml
policies:
  # VaultPolicy in same namespace (namespace defaults)
  - kind: VaultPolicy
    name: app-secrets

  # VaultPolicy in different namespace (explicit)
  - kind: VaultPolicy
    name: shared-secrets
    namespace: shared

  # VaultClusterPolicy (no namespace allowed)
  - kind: VaultClusterPolicy
    name: global-reader
    # namespace: xxx  # Error if specified!
```

---

## VaultClusterRole Validation

### Service Account Validation

Service accounts must include **both name and namespace**:

```yaml
# Valid
serviceAccounts:
  - name: platform-controller
    namespace: platform-system
  - name: monitoring-agent
    namespace: monitoring

# Invalid - missing fields
serviceAccounts:
  - name: my-sa
    # namespace missing - Error!
  - namespace: default
    # name missing - Error!
```

### Policy Reference Validation

| Reference Kind | Namespace Field | Behavior |
|----------------|-----------------|----------|
| `VaultPolicy` | **Required** | Must specify namespace explicitly |
| `VaultClusterPolicy` | Must be empty | Cluster-scoped, no namespace |

```yaml
policies:
  # VaultPolicy requires namespace in VaultClusterRole
  - kind: VaultPolicy
    name: app-secrets
    namespace: production  # Required!

  # VaultClusterPolicy (no namespace allowed)
  - kind: VaultClusterPolicy
    name: global-reader
```

---

## Role Auth Mount (VaultRole + VaultClusterRole)

Roles carry **no auth mount fields** — the referenced `VaultConnection` is the sole source of the auth mount and backend family (`spec.defaults.authPath` if set, otherwise the connection's own login mount). At admission, the webhook fetches the referenced connection:

- **Role-incapable connection → denied.** If the connection exists but resolves no role-capable mount (token, AppRole, AWS, GCP, or bootstrap-only auth without `defaults.authPath`), the role is rejected with `VaultConnection "..." has no role-capable auth mount`. Fix it on the connection: set `spec.defaults.authPath`.
- **Missing connection → warning, not denial.** GitOps tooling often applies roles before their connection; the role is admitted with a warning and the reconciler re-derives everything once the connection appears (a role-incapable connection then surfaces as `Reason=ValidationFailed` in status).
- **JWT constraints gate on the resolved family.** `spec.jwt` may only be set when the connection resolves to a jwt/oidc-family mount. `boundSubject` vs `boundClaims`/`boundClaimsList` exclusivity and the multi-SA explicit-binding requirement are checked against that resolved family.
- **`spec.connectionRef` is immutable** — it pins the auth mount the role is written to.

---

## VaultConnection Validation

### Role Mount Defaults

`spec.defaults.authPath` names the auth mount that dependent roles are written to. When the mount name doesn't start with a recognizable backend family (`kubernetes` or `jwt`, exact or `-`/`_`-separated), `spec.defaults.authType` is **required**:

```yaml
spec:
  defaults:
    authPath: team-a-cluster   # name alone can't be classified
    authType: kubernetes       # required: kubernetes or jwt
```

```yaml
spec:
  defaults:
    authPath: kubernetes-prod  # classifiable by name — authType optional
```

### Role Mount Change Warning

Updating a connection so its **resolved role mount changes** while dependent roles exist emits a warning (with the dependent-role count): every dependent role re-targets the new mount on its next sync, and Vault roles already written at the old mount are orphaned there (their recorded status bindings still pin deletion to the old mount). Deliberate mount migrations are allowed — the warning is informational.

---

## Webhook Configuration

### Enabling Webhooks

Webhooks are enabled by default when installing via Helm:

```bash
helm install vault-access-operator \
  oci://ghcr.io/panteparak/vault-access-operator/charts/vault-access-operator \
  --set webhook.enabled=true
```

### Disabling Webhooks

For development or testing environments:

```bash
helm install vault-access-operator \
  oci://ghcr.io/panteparak/vault-access-operator/charts/vault-access-operator \
  --set webhook.enabled=false
```

!!! warning "Production Recommendation"
    Always keep webhooks enabled in production to prevent invalid configurations from being applied.

### Certificate Management

Webhooks require TLS certificates. Options:

=== "cert-manager (Recommended)"

    ```yaml
    webhook:
      certManager:
        enabled: true
        issuerRef:
          name: selfsigned-issuer
          kind: ClusterIssuer
    ```

=== "Self-signed"

    ```yaml
    webhook:
      certManager:
        enabled: false
      selfSigned:
        enabled: true
    ```

---

## Troubleshooting

### Common Errors

**"path contains invalid characters"**

```
Error: validation failed: rule[0]: path "secret/data/my app" contains invalid characters
```

Fix: Remove spaces and special characters from the path.

**"path must contain {{namespace}}"**

```
Error: validation failed: rule[0]: path "secret/data/*" must contain {{namespace}} when namespace boundary enforcement is enabled
```

Fix: Add `{{namespace}}` to the path or disable `enforceNamespaceBoundary`.

**"wildcard before {{namespace}} is a security risk"**

```
Error: validation failed: rule[0]: path "*/{{namespace}}/secrets" contains wildcard (*) before {{namespace}}
```

Fix: Move the wildcard after `{{namespace}}` or use a fixed prefix.

**"must be a simple name without namespace prefix"**

```
Error: validation failed: serviceAccounts[0]: must be a simple name without namespace prefix (got "default/my-sa")
```

Fix: Use just the service account name without the namespace prefix.

**"has no role-capable auth mount"**

```
Error: validation failed: VaultConnection "vault-main" has no role-capable auth mount: auth method token has no role-capable mount; roles require a connection using kubernetes, jwt, or oidc auth, or an explicit defaults.authPath
```

Fix: Set `spec.defaults.authPath` (and `defaults.authType` if the name isn't classifiable) on the VaultConnection — the role CRs themselves carry no mount fields.

---

## Next Steps

- [API Reference](api-reference.md) - Detailed CRD documentation
- [Examples](examples.md) - Configuration examples
- [Troubleshooting](troubleshooting.md) - Common issues
