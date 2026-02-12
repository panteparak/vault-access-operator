# Drift Detection

Drift detection identifies when Vault resources differ from their declared Kubernetes state. This is critical for maintaining configuration integrity and audit compliance.

## What is Drift?

**Drift** occurs when the actual state of a Vault resource differs from the desired state declared in Kubernetes. This can happen due to:

- Manual changes via `vault` CLI or UI
- Automation scripts modifying Vault directly
- Other operators or tools managing the same resources
- Vault being restored from backup with stale data

## Drift Modes

The operator supports three drift modes, configurable per-resource or as a connection default:

### `ignore` Mode

**Behavior:** Skip drift detection entirely.

**Use when:**
- Performance is critical and drift is unlikely
- Resources are managed by multiple systems
- You're migrating and want to avoid conflicts

```yaml
spec:
  driftMode: ignore
```

### `detect` Mode (Default)

**Behavior:** Detect and report drift, but do NOT auto-correct.

**Use when:**
- You want visibility into unauthorized changes
- Manual review is required before corrections
- Compliance requires audit trails before changes

```yaml
spec:
  driftMode: detect
```

Status shows drift:
```yaml
status:
  driftDetected: true
  lastDriftCheckAt: "2026-01-15T10:30:00Z"
  driftSummary: "policy content differs"
```

### `correct` Mode

**Behavior:** Detect drift AND automatically overwrite Vault to match Kubernetes.

**Use when:**
- Kubernetes is the source of truth
- GitOps requires automatic reconciliation
- You want self-healing configuration

```yaml
spec:
  driftMode: correct
```

Status shows correction:
```yaml
status:
  driftDetected: false
  driftCorrectedAt: "2026-01-15T10:30:00Z"
```

## Configuration

### Per-Resource Configuration

Set drift mode on individual resources:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: critical-policy
spec:
  vaultConnectionRef:
    name: vault-primary
  driftMode: detect  # Override for this resource
  rules:
    - path: "secret/data/critical/*"
      capabilities: ["read"]
```

### Connection Defaults

Set default drift mode for all resources using a connection:

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
  defaults:
    driftMode: correct  # Default for all resources using this connection
```

### Resolution Order

When determining drift mode:

1. **Resource-level** `driftMode` takes precedence
2. **Connection-level** `defaults.driftMode` used if resource doesn't specify
3. **System default** `detect` used if neither specifies

## Status Fields

### Drift-Related Status

| Field | Type | Description |
|-------|------|-------------|
| `driftDetected` | bool | Whether drift exists |
| `lastDriftCheckAt` | time | When drift was last checked |
| `effectiveDriftMode` | string | Resolved drift mode |
| `driftSummary` | string | Human-readable drift description |
| `driftCorrectedAt` | time | When drift was last corrected |

### Example Status

```yaml
status:
  phase: Active
  driftDetected: true
  effectiveDriftMode: detect
  lastDriftCheckAt: "2026-01-15T10:30:00Z"
  driftSummary: "fields differ: policies, bound_service_account_names"
  conditions:
    - type: Synced
      status: "True"
      reason: Succeeded
    - type: DriftDetected
      status: "True"
      reason: DriftFound
      message: "Vault resource differs from desired state"
```

## Drift Detection Logic

### For Policies

Compares the HCL content:

```
Kubernetes VaultPolicy:              Vault Policy:
  path "secret/data/*" {             path "secret/data/*" {
    capabilities = ["read"]            capabilities = ["read", "list"]  ← DRIFT
  }                                  }
```

### For Roles

Compares key configuration fields:

| Field | Checked |
|-------|---------|
| `policies` | List of attached policies |
| `bound_service_account_names` | Bound service accounts |
| `bound_service_account_namespaces` | Bound namespaces |
| `token_ttl` | Token TTL |
| `token_max_ttl` | Max token TTL |

## Safety Controls

### Allow Destructive Annotation

For `correct` mode, destructive changes require explicit opt-in:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: existing-policy
  annotations:
    vault.platform.io/allow-destructive: "true"  # Required for correction
spec:
  driftMode: correct
```

Without this annotation, the operator will:
1. Detect drift
2. Log a warning
3. NOT overwrite the Vault resource
4. Set status to `Conflict`

### Conflict Resolution

When a resource enters `Conflict` phase:

1. **Review the drift** using `kubectl describe`
2. **Decide on action:**
   - Add `allow-destructive` annotation to correct
   - Update Kubernetes spec to match Vault
   - Delete and recreate with `adopt` annotation

## Monitoring Drift

### Prometheus Metrics

```
# Drift detection gauge
vault_access_operator_drift_detected{
  resource="VaultPolicy",
  namespace="production",
  name="my-policy"
} 1

# Drift correction counter
vault_access_operator_drift_corrections_total{
  resource="VaultPolicy",
  status="success"
}
```

### Alerting Example

```yaml
groups:
  - name: vault-access-operator
    rules:
      - alert: VaultDriftDetected
        expr: vault_access_operator_drift_detected == 1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Drift detected in {{ $labels.resource }}/{{ $labels.name }}"
```

### Kubernetes Events

The operator emits events for drift:

```bash
kubectl get events --field-selector reason=DriftDetected
```

## Use Cases

### GitOps with ArgoCD

```yaml
# VaultConnection with correct mode for full GitOps
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
spec:
  defaults:
    driftMode: correct

# Individual policy
kind: VaultPolicy
metadata:
  annotations:
    vault.platform.io/allow-destructive: "true"
spec:
  # ...omit driftMode to inherit from connection
```

### Audit-Only Mode

```yaml
# Detect drift but require manual approval
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
spec:
  defaults:
    driftMode: detect
```

Then review drift with:
```bash
kubectl get vaultpolicies -o custom-columns=\
NAME:.metadata.name,\
DRIFT:.status.driftDetected,\
SUMMARY:.status.driftSummary
```

### High-Performance Mode

```yaml
# Skip drift checks for frequently updated resources
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
spec:
  driftMode: ignore
```

## Troubleshooting

### Drift Never Detected

**Symptoms:** `driftDetected` always false despite manual changes

**Check:**
1. Verify drift mode is not `ignore`
2. Confirm reconciliation is happening (check `lastSyncedAt`)
3. Check operator logs for errors

### Drift Corrections Failing

**Symptoms:** `driftCorrectedAt` not updating, status shows `Conflict`

**Check:**
1. Verify `allow-destructive` annotation is set
2. Check operator has write permissions to Vault
3. Review operator logs for specific errors

### Frequent Drift Detection

**Symptoms:** Drift constantly detected and corrected

**Possible causes:**
1. Another system modifying the same resources
2. Race condition with multiple operators
3. Vault policy syntax normalization differences

**Solutions:**
1. Identify and disable conflicting automation
2. Use `ignore` mode for contested resources
3. Ensure only one system manages each resource

## See Also

- [Architecture](architecture.md) - How drift detection fits in reconciliation
- [Discovery](discovery.md) - Find unmanaged resources before adopting
- [API Reference](../api-reference.md) - Complete field reference
