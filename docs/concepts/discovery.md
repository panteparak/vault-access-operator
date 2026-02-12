# Resource Discovery

Resource discovery scans Vault to find policies and roles that aren't yet managed by Kubernetes Custom Resources. This helps you migrate existing Vault configurations to declarative management.

## What is Discovery?

When adopting Vault Access Operator in an existing environment, you likely have:

- Policies created manually via `vault policy write`
- Kubernetes auth roles configured directly
- Resources created by other tools or scripts

**Discovery** finds these unmanaged resources so you can:

1. **Audit** what exists in Vault
2. **Adopt** resources into Kubernetes management
3. **Detect** configuration drift

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Discovery Process                                 │
│                                                                         │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────┐ │
│  │ VaultConnection │    │   List Vault    │    │  Filter by Pattern  │ │
│  │ (discovery.     │───►│   Resources     │───►│  & Exclude System   │ │
│  │  enabled=true)  │    │   (policies,    │    │  Policies           │ │
│  └─────────────────┘    │    roles)       │    └──────────┬──────────┘ │
│                         └─────────────────┘               │            │
│                                                           ▼            │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────┐ │
│  │ Update Status   │◄───│  Compare with   │◄───│ Unmanaged Resources │ │
│  │ (discovered     │    │  K8s Resources  │    │ (no matching CR)    │ │
│  │  resources)     │    └─────────────────┘    └─────────────────────┘ │
│  └─────────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Enabling Discovery

Enable discovery on your VaultConnection:

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

  discovery:
    enabled: true
    interval: 1h               # How often to scan
    policyPatterns:            # Only discover matching policies
      - "app-*"
      - "team-*"
    rolePatterns:              # Only discover matching roles
      - "*-service"
    excludeSystemPolicies: true  # Skip root, default, etc.
```

## Configuration Reference

### Discovery Fields

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable resource discovery |
| `interval` | `1h` | How often to scan Vault |
| `policyPatterns` | `[]` (all) | Glob patterns for policy names |
| `rolePatterns` | `[]` (all) | Glob patterns for role names |
| `excludeSystemPolicies` | `true` | Skip built-in Vault policies |

### System Policies

By default, these built-in policies are excluded:

- `root` - Superuser policy
- `default` - Default policy for all tokens
- `response-wrapping` - Used for wrapped responses

## Viewing Discovered Resources

### Via kubectl

```bash
kubectl get vaultconnection vault-primary -o yaml
```

```yaml
status:
  phase: Active
  discoveryStatus:
    lastScanAt: "2026-01-15T10:00:00Z"
    unmanagedPolicies: 3
    unmanagedRoles: 2
    discoveredResources:
      - type: policy
        name: app-database-read
        discoveredAt: "2026-01-15T10:00:00Z"
        suggestedCRName: app-database-read
        adoptionStatus: discovered
      - type: policy
        name: team-platform-admin
        discoveredAt: "2026-01-15T10:00:00Z"
        suggestedCRName: team-platform-admin
        adoptionStatus: discovered
      - type: role
        name: api-service
        discoveredAt: "2026-01-15T10:00:00Z"
        suggestedCRName: api-service
        adoptionStatus: discovered
```

### Via Prometheus Metrics

```
vault_access_operator_discovered_resources{connection="vault-primary", type="policy"} 3
vault_access_operator_discovered_resources{connection="vault-primary", type="role"} 2
vault_access_operator_discovery_scans_total{connection="vault-primary", status="success"} 10
```

## Adopting Discovered Resources

Once you've identified unmanaged resources, you can adopt them into Kubernetes management.

### Step 1: Review the Resource

```bash
# Check what the policy contains
vault policy read app-database-read

# Check what the role contains
vault read auth/kubernetes/role/api-service
```

### Step 2: Create a Kubernetes CR

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: app-database-read
  namespace: production
  annotations:
    vault.platform.io/adopt: "true"  # Adopt existing resource
spec:
  vaultConnectionRef:
    name: vault-primary
  rules:
    - path: "database/creds/readonly"
      capabilities: ["read"]
```

### Step 3: Apply and Verify

```bash
kubectl apply -f policy.yaml

# Check adoption status
kubectl get vaultpolicy app-database-read -o yaml
```

```yaml
status:
  phase: Active
  managed: true
  message: "Adopted existing Vault resource"
```

## Adoption Modes

### Adopt Existing (`vault.platform.io/adopt: "true"`)

- Takes ownership of existing Vault resource
- Does NOT modify the resource (initially)
- Future updates to the CR will sync to Vault

### Fail on Conflict (default)

Without the adopt annotation:
- If resource exists in Vault, CR enters `Conflict` phase
- Resource is NOT overwritten
- Requires explicit adoption or deletion

## Pattern Matching

Discovery uses glob patterns (shell-style wildcards):

| Pattern | Matches | Doesn't Match |
|---------|---------|---------------|
| `app-*` | `app-frontend`, `app-backend` | `my-app`, `frontend` |
| `*-prod` | `api-prod`, `web-prod` | `prod-api`, `production` |
| `team-*-*` | `team-platform-admin` | `team-platform` |

### Multiple Patterns

Multiple patterns are OR'd together:

```yaml
discovery:
  policyPatterns:
    - "app-*"      # OR
    - "service-*"  # OR
    - "team-*"
```

## Best Practices

### 1. Start with Detection Only

Don't adopt everything immediately:

```yaml
discovery:
  enabled: true
  interval: 24h  # Daily scan
```

Review discovered resources, understand their purpose, then adopt selectively.

### 2. Use Specific Patterns

Avoid discovering resources you don't want to manage:

```yaml
discovery:
  policyPatterns:
    - "myteam-*"  # Only our team's resources
  excludeSystemPolicies: true
```

### 3. Document Before Adopting

Before adoption:
1. Export current Vault config
2. Document the resource's purpose
3. Identify who/what created it
4. Confirm no other automation manages it

### 4. Test Adoption in Non-Production

1. Enable discovery in staging
2. Adopt a resource
3. Verify no disruption
4. Then proceed to production

## Troubleshooting

### Discovery Not Running

**Symptoms:** `lastScanAt` not updating

**Check:**
1. `discovery.enabled` is `true`
2. VaultConnection is in `Active` phase
3. Operator has permission to list policies/roles

### Missing Expected Resources

**Symptoms:** Known resources not appearing in discovery

**Check:**
1. Pattern filters aren't excluding them
2. `excludeSystemPolicies` isn't filtering them
3. Resources aren't already managed by a CR

### "Permission Denied" on Scan

**Symptoms:** Discovery fails with permission error

**Required Vault permissions:**
```hcl
# For policy discovery
path "sys/policies/acl" {
  capabilities = ["list"]
}

# For role discovery
path "auth/kubernetes/role" {
  capabilities = ["list"]
}
```

## Use Cases

### Migration from CLI to GitOps

1. Enable discovery to audit existing resources
2. Generate CRs for each discovered resource
3. Add `adopt` annotation
4. Apply via GitOps pipeline
5. Disable direct CLI access

### Multi-Cluster Vault

When multiple clusters share Vault:

```yaml
# Cluster A
discovery:
  policyPatterns:
    - "cluster-a-*"

# Cluster B
discovery:
  policyPatterns:
    - "cluster-b-*"
```

### Compliance Audit

Use discovery to regularly check for unmanaged resources:

```yaml
discovery:
  enabled: true
  interval: 4h
```

Alert on `vault_access_operator_discovered_resources > 0` to catch configuration drift.

## See Also

- [Drift Detection](drift-detection.md) - Detect changes to managed resources
- [Architecture](architecture.md) - How discovery fits in the operator
- [Getting Started](../getting-started.md) - Initial setup guide
