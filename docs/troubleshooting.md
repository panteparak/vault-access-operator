# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the Vault Access Operator.

## Table of Contents

- [Common Issues](#common-issues)
  - [VaultConnection Issues](#vaultconnection-issues)
  - [VaultPolicy Issues](#vaultpolicy-issues)
  - [VaultRole Issues](#vaultrole-issues)
  - [Webhook Issues](#webhook-issues)
- [Debugging Techniques](#debugging-techniques)
- [Log Analysis](#log-analysis)
- [Status Conditions Explained](#status-conditions-explained)

---

## Common Issues

### VaultConnection Issues

#### Connection Stuck in "Pending" Phase

**Symptoms:**
```bash
kubectl get vaultconnection
NAME            ADDRESS                          PHASE     VERSION   AGE
vault-primary   https://vault.example.com:8200   Pending             5m
```

**Possible Causes:**

1. **Operator not running**: Check if the operator pod is running.
   ```bash
   kubectl get pods -n vault-access-operator-system
   ```

2. **Invalid Vault address**: Verify the address is correct and reachable.
   ```bash
   kubectl describe vaultconnection vault-primary
   ```

3. **Network connectivity**: The operator cannot reach Vault.
   ```bash
   # Test from a pod in the same namespace as the operator
   kubectl run -it --rm debug --image=curlimages/curl -- curl -k https://vault.example.com:8200/v1/sys/health
   ```

#### Connection in "Error" Phase

**Symptoms:**
```bash
kubectl get vaultconnection
NAME            ADDRESS                          PHASE   VERSION   AGE
vault-primary   https://vault.example.com:8200   Error             5m
```

**Check the error message:**
```bash
kubectl describe vaultconnection vault-primary
```

**Common error causes:**

1. **TLS Certificate Issues**
   - Error: `x509: certificate signed by unknown authority`
   - Solution: Provide the correct CA certificate or set `skipVerify: true` (not recommended for production).
   ```yaml
   spec:
     tls:
       caSecretRef:
         name: vault-ca-cert
         namespace: vault-access-operator-system
         key: ca.crt
   ```

2. **Authentication Failure**
   - Error: `permission denied` or `invalid role`
   - Solution: Verify the Vault role exists and the service account is bound correctly.
   ```bash
   # Check if the role exists in Vault
   vault read auth/kubernetes/role/vault-access-operator

   # Verify the operator service account
   kubectl get sa -n vault-access-operator-system
   ```

3. **Vault Sealed**
   - Error: `Vault is sealed`
   - Solution: Unseal the Vault server.
   ```bash
   vault status
   vault operator unseal
   ```

#### Connection Authentication Failures

**Symptoms:**
```
Error: failed to authenticate: permission denied
```

**Debugging steps:**

1. **Verify Kubernetes auth is enabled:**
   ```bash
   vault auth list
   ```

2. **Check the Vault role configuration:**
   ```bash
   vault read auth/kubernetes/role/vault-access-operator
   ```

3. **Verify service account binding:**
   ```bash
   # The role should allow:
   # - bound_service_account_names: vault-access-operator-controller-manager
   # - bound_service_account_namespaces: vault-access-operator-system
   ```

4. **Test authentication manually:**
   ```bash
   # Get a shell in the operator pod
   kubectl exec -it deploy/vault-access-operator-controller-manager \
     -n vault-access-operator-system -- /bin/sh

   # Check the service account token
   cat /var/run/secrets/kubernetes.io/serviceaccount/token
   ```

---

### VaultPolicy Issues

#### Policy Stuck in "Syncing" Phase

**Symptoms:**
```bash
kubectl get vaultpolicy -n my-app
NAME          VAULT NAME         PHASE     RULES   AGE
app-secrets   my-app-app-secrets Syncing   3       5m
```

**Possible causes:**

1. **VaultConnection not ready:**
   ```bash
   kubectl get vaultconnection
   # Ensure the referenced connection is in "Active" phase
   ```

2. **Insufficient Vault permissions:**
   ```bash
   # Check operator logs
   kubectl logs -n vault-access-operator-system deploy/vault-access-operator-controller-manager

   # Ensure the Vault policy allows policy management
   vault policy read vault-access-operator
   ```

#### Policy in "Conflict" Phase

**Symptoms:**
```bash
kubectl get vaultpolicy -n my-app
NAME          VAULT NAME         PHASE      RULES   AGE
app-secrets   my-app-app-secrets Conflict   3       5m
```

**Explanation:** A policy with the same name already exists in Vault and is either:
- Managed by a different Kubernetes resource
- Not managed by the operator at all

**Solutions:**

1. **Use Adopt conflict policy:**
   ```yaml
   spec:
     conflictPolicy: Adopt  # Take over the existing policy
   ```

2. **Delete the existing policy from Vault:**
   ```bash
   vault policy delete my-app-app-secrets
   ```

3. **Rename your VaultPolicy resource:**
   ```yaml
   metadata:
     name: app-secrets-v2  # Will create: my-app-app-secrets-v2
   ```

#### Namespace Boundary Validation Error

**Symptoms:**
```
Error: validation failed: rule[0]: path "secret/data/*" must contain {{namespace}} when namespace boundary enforcement is enabled
```

**Solution:** Add the `{{namespace}}` variable to your paths, or disable namespace boundary enforcement:

**Option 1: Add namespace variable (recommended for multi-tenant environments):**
```yaml
spec:
  enforceNamespaceBoundary: true  # Explicitly enabled (default is false)
  rules:
    - path: "secret/data/{{namespace}}/*"  # Correct
      capabilities: [read, list]
```

**Option 2: Disable enforcement (default behavior):**
```yaml
spec:
  enforceNamespaceBoundary: false  # This is the default
  rules:
    - path: "secret/data/*"
      capabilities: [read, list]
```

#### Wildcard Before Namespace Error

**Symptoms:**
```
Error: validation failed: rule[0]: path "secret/*/{{namespace}}/data" contains wildcard (*) before {{namespace}} which is a security risk
```

**Explanation:** Having a wildcard before `{{namespace}}` could allow access to secrets in other namespaces.

**Solution:** Restructure your path:
```yaml
# Bad
- path: "secret/*/{{namespace}}/data"

# Good
- path: "secret/data/{{namespace}}/*"
- path: "kv/{{namespace}}/data/*"
```

---

### VaultRole Issues

#### Role in "Error" Phase with PolicyNotFound

**Symptoms:**
```bash
kubectl describe vaultrole app-role -n my-app
# Status shows: policy VaultPolicy "missing-policy" not found in namespace "my-app"
```

**Solutions:**

1. **Create the missing policy:**
   ```yaml
   apiVersion: vault.platform.io/v1alpha1
   kind: VaultPolicy
   metadata:
     name: missing-policy
     namespace: my-app
   spec:
     # ... policy configuration
   ```

2. **Fix the policy reference:**
   ```yaml
   spec:
     policies:
       - kind: VaultPolicy
         name: correct-policy-name
   ```

3. **If referencing a policy in another namespace:**
   ```yaml
   spec:
     policies:
       - kind: VaultPolicy
         name: shared-policy
         namespace: shared-namespace
   ```

#### Service Account Not Authorized

**Symptoms:**
- Application pods cannot authenticate to Vault
- Error: `role not found` or `service account not authorized`

**Debugging steps:**

1. **Check the VaultRole status:**
   ```bash
   kubectl get vaultrole app-role -n my-app -o yaml
   # Verify boundServiceAccounts in status
   ```

2. **Verify the service account exists:**
   ```bash
   kubectl get sa -n my-app
   ```

3. **Check the role in Vault:**
   ```bash
   vault read auth/kubernetes/role/my-app-app-role
   ```

4. **Test authentication:**
   ```bash
   kubectl run -it --rm debug \
     --image=hashicorp/vault \
     --serviceaccount=app-service-account \
     -n my-app -- \
     vault login -method=kubernetes role=my-app-app-role
   ```

---

### Webhook Issues

#### Webhook Certificate Errors

**Symptoms:**
```
Error creating: Internal error occurred: failed calling webhook:
x509: certificate signed by unknown authority
```

**Solutions:**

1. **If using cert-manager, verify the certificate:**
   ```bash
   kubectl get certificate -n vault-access-operator-system
   kubectl describe certificate vault-access-operator-webhook-cert \
     -n vault-access-operator-system
   ```

2. **Check cert-manager is working:**
   ```bash
   kubectl get pods -n cert-manager
   kubectl logs -n cert-manager deploy/cert-manager
   ```

3. **Restart the operator to pick up new certificate:**
   ```bash
   kubectl rollout restart deployment vault-access-operator-controller-manager \
     -n vault-access-operator-system
   ```

#### Webhook Timeout

**Symptoms:**
```
Error: context deadline exceeded (Client.Timeout exceeded while awaiting headers)
```

**Solutions:**

1. **Check operator health:**
   ```bash
   kubectl get pods -n vault-access-operator-system
   kubectl logs -n vault-access-operator-system deploy/vault-access-operator-controller-manager
   ```

2. **Increase webhook timeout:**
   ```yaml
   # In Helm values
   webhook:
     timeoutSeconds: 30
   ```

3. **Check network policies:**
   ```bash
   kubectl get networkpolicy -n vault-access-operator-system
   ```

---

## Debugging Techniques

### Enable Debug Logging

Increase log verbosity for more detailed output:

```yaml
# Helm values
logging:
  level: debug
```

Or set environment variable:
```bash
kubectl set env deployment/vault-access-operator-controller-manager \
  -n vault-access-operator-system \
  -- ZAP_LOG_LEVEL=debug
```

### Check Resource Events

```bash
kubectl get events --field-selector involvedObject.name=app-secrets -n my-app
```

### Inspect Resource Details

```bash
# Full resource with status
kubectl get vaultpolicy app-secrets -n my-app -o yaml

# Just the status
kubectl get vaultpolicy app-secrets -n my-app -o jsonpath='{.status}'

# Just conditions
kubectl get vaultpolicy app-secrets -n my-app \
  -o jsonpath='{.status.conditions}' | jq .
```

### Test Vault Connectivity from Operator

```bash
# Get a shell in the operator pod
kubectl exec -it deploy/vault-access-operator-controller-manager \
  -n vault-access-operator-system -- /bin/sh

# Test Vault health
wget -qO- https://vault.example.com:8200/v1/sys/health

# Check environment
env | grep VAULT
```

### Verify CRD Installation

```bash
# List CRDs
kubectl get crds | grep vault.platform.io

# Check CRD details
kubectl describe crd vaultpolicies.vault.platform.io
```

---

## Log Analysis

### Operator Log Locations

```bash
# Stream logs from the operator
kubectl logs -f -n vault-access-operator-system deploy/vault-access-operator-controller-manager

# Get logs from the last hour
kubectl logs -n vault-access-operator-system deploy/vault-access-operator-controller-manager \
  --since=1h

# Get logs from a crashed pod
kubectl logs -n vault-access-operator-system deploy/vault-access-operator-controller-manager \
  --previous
```

### Common Log Patterns

#### Successful Reconciliation
```json
{"level":"info","ts":"...","msg":"Reconciling VaultPolicy","namespace":"my-app","name":"app-secrets"}
{"level":"info","ts":"...","msg":"VaultPolicy reconciled successfully","namespace":"my-app","name":"app-secrets","vaultName":"my-app-app-secrets"}
```

#### Connection Error
```json
{"level":"error","ts":"...","msg":"Failed to get Vault client","error":"connection \"vault-primary\" not ready: VaultConnection is in Pending phase"}
```

#### Conflict Detection
```json
{"level":"error","ts":"...","msg":"Conflict detected","error":"conflict: policy \"my-app-app-secrets\": already managed by other-namespace/other-policy"}
```

#### Retry Scheduling
```json
{"level":"info","ts":"...","msg":"Scheduling retry","retryCount":2,"nextRetryIn":"20s"}
```

### Filtering Logs

```bash
# Only errors
kubectl logs -n vault-access-operator-system deploy/vault-access-operator-controller-manager \
  | grep '"level":"error"'

# Specific resource
kubectl logs -n vault-access-operator-system deploy/vault-access-operator-controller-manager \
  | grep '"name":"app-secrets"'

# Using jq for JSON logs
kubectl logs -n vault-access-operator-system deploy/vault-access-operator-controller-manager \
  | jq 'select(.level == "error")'
```

---

## Status Conditions Explained

### Condition Types

| Type | Description | Healthy State |
|------|-------------|---------------|
| `Ready` | Resource is fully reconciled and operational | `True` |
| `Synced` | Resource has been successfully synced to Vault | `True` |
| `ConnectionReady` | Referenced VaultConnection is available | `True` |
| `PoliciesResolved` | All referenced policies have been found and resolved | `True` |

### Condition Reasons

| Reason | Description | Action |
|--------|-------------|--------|
| `Succeeded` | Operation completed successfully | None needed |
| `Failed` | Operation failed | Check message and logs |
| `InProgress` | Operation is ongoing | Wait for completion |
| `Conflict` | Conflict with existing Vault resource | Use Adopt policy or resolve manually |
| `ValidationFailed` | Resource spec validation failed | Fix spec according to error |
| `ConnectionNotReady` | VaultConnection is not active | Fix VaultConnection |
| `PolicyNotFound` | Referenced policy doesn't exist | Create the policy |

### Reading Conditions

```bash
# Get all conditions
kubectl get vaultpolicy app-secrets -n my-app \
  -o jsonpath='{range .status.conditions[*]}{.type}: {.status} ({.reason}) - {.message}{"\n"}{end}'

# Example output:
# Ready: False (ConnectionNotReady) - connection "vault-primary" not ready: VaultConnection is in Error phase
# Synced: False (Failed) - failed to sync policy to Vault
```

### Interpreting Multiple Conditions

**Healthy resource:**
```
Ready: True (Succeeded) - Policy synced to Vault
Synced: True (Succeeded) - Policy synced successfully
```

**Connection issue:**
```
Ready: False (ConnectionNotReady) - connection "vault-primary" not ready
Synced: False (Failed) - cannot sync without connection
```

**Conflict detected:**
```
Ready: False (Conflict) - policy already exists and is managed by other-ns/other-policy
Synced: False (Conflict) - cannot sync due to conflict
```

---

## Getting Help

If you're still experiencing issues:

1. **Check the GitHub Issues**: [github.com/panteparak/vault-access-operator/issues](https://github.com/panteparak/vault-access-operator/issues)

2. **Collect diagnostic information:**
   ```bash
   # Export all vault resources
   kubectl get vaultconnections,vaultclusterpolicies,vaultpolicies,vaultclusterroles,vaultroles \
     -A -o yaml > vault-resources.yaml

   # Get operator logs
   kubectl logs -n vault-access-operator-system deploy/vault-access-operator-controller-manager \
     --since=1h > operator-logs.txt

   # Get events
   kubectl get events -A --field-selector reason!=Normal > events.txt
   ```

3. **Open an issue** with the diagnostic information (remove any sensitive data like tokens or secrets).
