# Configuration

This page documents all available Helm chart configuration options.

## Installation

```bash
helm install vault-access-operator \
  oci://ghcr.io/panteparak/vault-access-operator/charts/vault-access-operator \
  --namespace vault-access-operator-system \
  --create-namespace \
  -f values.yaml
```

---

## Values Reference

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of operator replicas | `1` |
| `nameOverride` | Override the chart name | `""` |
| `fullnameOverride` | Override the full release name | `""` |

### Image Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Image repository | `ghcr.io/panteparak/vault-access-operator` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.tag` | Image tag (defaults to chart appVersion) | `""` |
| `imagePullSecrets` | Image pull secrets for private registries | `[]` |

### Service Account

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create a service account | `true` |
| `serviceAccount.annotations` | Annotations for the service account | `{}` |
| `serviceAccount.name` | Service account name | `""` |
| `serviceAccount.automountServiceAccountToken` | Automount service account token | `true` |

### Resources

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |

### Security Context

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podSecurityContext.runAsNonRoot` | Run as non-root user | `true` |
| `podSecurityContext.seccompProfile.type` | Seccomp profile | `RuntimeDefault` |
| `securityContext.allowPrivilegeEscalation` | Allow privilege escalation | `false` |
| `securityContext.capabilities.drop` | Dropped capabilities | `["ALL"]` |
| `securityContext.readOnlyRootFilesystem` | Read-only root filesystem | `true` |

### Webhooks

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhook.enabled` | Enable admission webhooks | `true` |
| `webhook.port` | Webhook server port | `9443` |
| `webhook.failurePolicy` | Webhook failure policy | `Fail` |
| `webhook.timeoutSeconds` | Webhook timeout | `10` |

### Webhook Certificates

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhook.certManager.enabled` | Use cert-manager for certificates | `true` |
| `webhook.certManager.issuerName` | Cert-manager issuer name | `""` |
| `webhook.certManager.duration` | Certificate duration | `8760h` |
| `webhook.selfSigned.enabled` | Generate self-signed certificates | `false` |
| `webhook.selfSigned.validityDays` | Certificate validity (days) | `365` |

### Metrics

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metrics.enabled` | Enable metrics endpoint | `true` |
| `metrics.secure` | Use HTTPS for metrics | `true` |
| `metrics.port` | Metrics port | `8443` |

### ServiceMonitor (Prometheus)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.enabled` | Create ServiceMonitor resource | `false` |
| `serviceMonitor.namespace` | Namespace for ServiceMonitor | `""` |
| `serviceMonitor.labels` | Labels for ServiceMonitor | `{}` |
| `serviceMonitor.interval` | Scrape interval | `30s` |

### Logging

| Parameter | Description | Default |
|-----------|-------------|---------|
| `logging.level` | Log level (debug, info, error) | `info` |
| `logging.development` | Development mode | `false` |
| `logging.encoder` | Log encoder (json, console) | `json` |
| `logging.stacktraceLevel` | Stack trace log level | `error` |

These values render to the operator's `--zap-log-level`, `--zap-devel`, `--zap-encoder`, and `--zap-stacktrace-level` flags. The binary itself defaults to production logging (JSON, info) when the flags are absent; pass `--zap-devel=true` (or set `logging.development=true` + `logging.encoder=console`) for human-readable local output. Every reconcile log line carries `reconcileID`, `vaultConnection`, and — for auth-mount resources — `authPath` for failure-source tracing.

### Pod Disruption Budget

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podDisruptionBudget.enabled` | Enable PDB | `false` |
| `podDisruptionBudget.minAvailable` | Minimum available pods | `1` |
| `podDisruptionBudget.maxUnavailable` | Maximum unavailable pods (alternative to minAvailable) | - |

### Scheduling

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nodeSelector` | Node selector for scheduling | `{}` |
| `tolerations` | Tolerations for scheduling | `[]` |
| `affinity` | Affinity rules for scheduling | `{}` |
| `priorityClassName` | Priority class name | `""` |

### Leader Election

| Parameter | Description | Default |
|-----------|-------------|---------|
| `leaderElection.enabled` | Enable leader election | `true` |
| `leaderElection.leaseDuration` | Lease duration | `15s` |
| `leaderElection.renewDeadline` | Renew deadline | `10s` |
| `leaderElection.retryPeriod` | Retry period | `2s` |

### Health Probe

| Parameter | Description | Default |
|-----------|-------------|---------|
| `healthProbe.bindAddress` | Health probe bind address | `:8081` |

### Metrics Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metrics.service.type` | Metrics service type | `ClusterIP` |
| `metrics.service.port` | Metrics service port | `8443` |
| `metrics.service.annotations` | Metrics service annotations | `{}` |

### ServiceMonitor (Additional Fields)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `serviceMonitor.metricRelabelings` | Metric relabelings | `[]` |
| `serviceMonitor.relabelings` | Relabelings | `[]` |
| `serviceMonitor.honorLabels` | Honor labels | `false` |

### Webhook Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhook.service.type` | Webhook service type | `ClusterIP` |
| `webhook.service.port` | Webhook service port | `443` |
| `webhook.service.targetPort` | Webhook target port | `9443` |

### Webhook Certificate (Additional Fields)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhook.certManager.issuerKind` | Cert-manager issuer kind (Issuer or ClusterIssuer) | `""` |
| `webhook.certManager.issuerGroup` | Cert-manager issuer group | `""` |
| `webhook.certManager.renewBefore` | Certificate renewal before expiry | `360h` |

### Network Policy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `networkPolicy.enabled` | Enable network policy | `false` |
| `networkPolicy.ingress` | Ingress rules | `[]` |
| `networkPolicy.egress` | Egress rules | `[]` |

### Vault Connection Defaults

| Parameter | Description | Default |
|-----------|-------------|---------|
| `vaultConnection.address` | Default Vault address | `""` |
| `vaultConnection.authPath` | Default auth mount path | `auth/kubernetes` |
| `vaultConnection.role` | Default Kubernetes auth role | `""` |
| `vaultConnection.tls.skipVerify` | Skip TLS verification | `false` |
| `vaultConnection.tls.caSecretName` | Secret name containing CA certificate | `""` |
| `vaultConnection.tls.caSecretKey` | Key in secret containing CA certificate | `ca.crt` |

### Operator Vault Policy (KV secret seeding)

The capabilities the operator needs **inside Vault** are governed by the Vault
policy attached to its auth role (configured during [bootstrap](auth-methods/bootstrap.md),
not by a Helm value). If you use the [`VaultKVSecret`](api-reference.md#vaultkvsecret)
CRD to pre-seed KV v2 paths for External Secrets Operator, the operator needs a
**very small** set of capabilities — it only ever *creates* a secret when the
path is absent, and it never reads, lists, updates, or deletes secret **data**:

```hcl
# Data path: CREATE ONLY. The operator writes to the exact spec.path of each
# VaultKVSecret. It never reads, lists, updates, or deletes secret data — Vault
# itself then enforces the never-clobber guarantee.
path "secret/data/*" {
  capabilities = ["create"]
}

# Metadata path: read + patch + delete only. These back the existence check,
# the custom_metadata ownership stamp, and delete-if-untouched cleanup.
path "secret/metadata/*" {
  capabilities = ["read", "patch", "delete"]
}
```

| Capability | Path | Why the operator needs it |
|------------|------|---------------------------|
| `create` | `secret/data/*` | Seed a new secret (KV v2 `cas=0` write) when the path is absent |
| `read` | `secret/metadata/*` | Existence check before seeding, and the untouched-check on delete (reads `current_version` + `custom_metadata`) |
| `patch` | `secret/metadata/*` | Stamp operator ownership into `custom_metadata` (requires Vault **≥ 1.9**) |
| `delete` | `secret/metadata/*` | `DeleteMetadata` removes an untouched seeded secret on cleanup |

**Do you need `list`? No.** Neither `secret/data/*` nor `secret/metadata/*` needs
`list`. The operator never enumerates KV paths — it acts only on the explicit
`spec.path` of each `VaultKVSecret`. The data path likewise needs **no** `read`,
`update`, or `delete`.

**Least privilege:** scope both prefixes to the paths you actually seed (e.g.
`secret/data/apps/*` and `secret/metadata/apps/*`) rather than the broad
`secret/*`. Omit these grants entirely if you don't use `VaultKVSecret`. See
[Bootstrap Authentication](auth-methods/bootstrap.md) for where this fits in the
operator policy.

### Extensibility

| Parameter | Description | Default |
|-----------|-------------|---------|
| `extraEnv` | Additional environment variables | `[]` |
| `extraVolumeMounts` | Additional volume mounts | `[]` |
| `extraVolumes` | Additional volumes | `[]` |
| `extraArgs` | Additional arguments for the operator | `[]` |

### Pod Metadata

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podAnnotations` | Annotations to add to the pod | `{}` |
| `podLabels` | Labels to add to the pod | `{}` |

---

## Environment Variables

The operator supports the following environment variables for runtime configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPERATOR_REQUEUE_SUCCESS_INTERVAL` | `5m` | Requeue interval after successful reconciliation |
| `OPERATOR_REQUEUE_ERROR_INTERVAL` | `30s` | Requeue interval after failed reconciliation |
| `OPERATOR_MIN_SCAN_INTERVAL` | `5m` | Minimum interval between discovery scans |
| `OPERATOR_NAMESPACE` | (from downward API) | Namespace where the operator is running |
| `OPERATOR_SERVICE_ACCOUNT` | (from downward API) | Service account name used by the operator |
| `CLUSTER_NAME` | `""` | Per-cluster prefix for all Vault resource names (see [`--cluster-name`](#cli-flags) and [Sharing one Vault across clusters](#sharing-one-vault-across-clusters)). The `--cluster-name` flag takes precedence. |
| `MANAGED_MARKERS` | `false` | Enable in-band ownership tracking, discovery, and orphan detection (see [`--managed-markers`](#cli-flags) and [Managed markers](#managed-markers)). The `--managed-markers` flag takes precedence. |

These can be set via the `extraEnv` Helm value:

```yaml
extraEnv:
  - name: OPERATOR_REQUEUE_SUCCESS_INTERVAL
    value: "2m"
  - name: OPERATOR_MIN_SCAN_INTERVAL
    value: "10m"
```

---

## CLI Flags

The operator binary accepts the following command-line flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--metrics-bind-address` | `0` | Address for the metrics endpoint (`:8443` for HTTPS, `:8080` for HTTP, `0` to disable) |
| `--health-probe-bind-address` | `:8081` | Address for the health probe endpoint |
| `--leader-elect` | `false` | Enable leader election for HA deployments |
| `--metrics-secure` | `true` | Serve metrics over HTTPS |
| `--webhook-cert-path` | `""` | Directory containing webhook TLS certificate |
| `--webhook-cert-name` | `tls.crt` | Webhook certificate file name |
| `--webhook-cert-key` | `tls.key` | Webhook key file name |
| `--metrics-cert-path` | `""` | Directory containing metrics server TLS certificate |
| `--metrics-cert-name` | `tls.crt` | Metrics certificate file name |
| `--metrics-cert-key` | `tls.key` | Metrics key file name |
| `--enable-http2` | `false` | Enable HTTP/2 for metrics and webhook servers |
| `--enable-webhooks` | `false` | Enable admission webhooks (requires certificate configuration) |
| `--cluster-name` | `""` | Per-cluster prefix for all Vault resource names (policies, roles). Set a unique value per cluster when multiple operators share one Vault server; empty disables prefixing. Also settable via the `CLUSTER_NAME` env var. See [Sharing one Vault across clusters](#sharing-one-vault-across-clusters). |
| `--managed-markers` | `false` | Enable in-band ownership tracking, discovery, and orphan detection (ADR 0008). Default OFF: the operator skips conflict/ownership detection (write-and-forget) and does not run the discovery or orphan controllers. When ON, ownership travels on the managed objects themselves — no extra Vault grant. Also settable via the `MANAGED_MARKERS` env var. See [Managed markers](#managed-markers). |

---

## Sharing one Vault across clusters

Vault Community Edition has no [namespaces](https://developer.hashicorp.com/vault/docs/enterprise/namespaces) (an Enterprise feature), so ACL policies live in a single global store (`sys/policies/acl/`). If you run **one operator per Kubernetes cluster against the same Vault server**, two clusters that define a policy with the same name (e.g. `default/admin`) would otherwise derive the same Vault object name.

Two settings work together (see [ADR 0008](adr/0008-in-band-ownership-markers.md)):

1. **One auth mount per cluster — hard requirement.** Each cluster's operator MUST authenticate through its own auth mount (e.g. `auth/k8s-east`, `auth/k8s-west`). The mount path is the operator's **ownership identity**: it is stamped into every in-band ownership record, so cross-cluster fights are *detected and blocked* (conflict instead of silent overwrite) even when names collide. Roles are additionally isolated structurally — they live under their cluster's own mount.
2. **`--cluster-name`** (or `CLUSTER_NAME` env / `clusterName` Helm value) — a unique per-cluster prefix on every derived Vault resource name that *prevents* the collision in the first place:

| Setting | `VaultPolicy` `default/admin` → Vault policy |
|---------|----------------------------------------------|
| `clusterName: east` | `east-default-admin` |
| `clusterName: west` | `west-default-admin` |

Both clusters then coexist on one Vault with no collisions. Notes:

- **Empty (default) = no prefix** — existing single-cluster installs are unaffected.
- The prefix also applies to the policy names a `VaultRole` binds (`token_policies`), so role→policy references stay consistent automatically.
- Enabling the prefix on an **existing** install renames the Vault objects: the operator creates the new prefixed policies/roles and the old unprefixed ones become orphaned. Plan a cutover (create prefixed → repoint external consumers → delete the old names).
- Valid characters: `^[a-zA-Z0-9._-]+$` (the prefix becomes part of Vault policy names and KV paths).

---

## Managed markers

A **managed marker** is the operator's in-band ownership record, stored **on
the managed Vault object itself** ([ADR 0008](adr/0008-in-band-ownership-markers.md)).
Markers back three features: ownership/conflict detection (so two operators
don't silently overwrite each other), discovery (adopting pre-existing Vault
resources into CRs), and orphan detection (spotting resources whose K8s owner
has vanished).

Where the record lives:

| Object | In-band record |
|--------|----------------|
| ACL policy | Structured comment header inside the policy document (`# managed-by`, `# auth-mount`, `# cluster`, `# k8s-resource`, `# k8s-kind`) |
| KV secret (`VaultKVSecret`) | `custom_metadata` on the secret's own path (`managed-by`, `k8s-resource`, `auth-mount`, `cluster`, `managed-at`, `last-updated`) |
| Auth role | None — Vault auth roles have no metadata surface. Ownership memory is the owning CR's status plus the one-cluster-per-auth-mount invariant |

The operator's **identity** is the auth mount path its connection logged in
through. Ownership requires the sentinel **+ the same identity + the same
owning CR** — a record naming another operator's mount is *foreign*: it
conflicts, cannot be adopted, is never deleted by cleanup, and is excluded
from discovery.

**The whole mechanism is OFF by default** and gated behind a single toggle:

| Setting | Default | Effect |
|---------|---------|--------|
| `--managed-markers` flag | `false` | See below |
| `MANAGED_MARKERS` env var | `false` | Same; the flag takes precedence |
| `managedMarkers.enabled` Helm value | `false` | Renders the flag |

**When OFF (default):** the operator skips conflict/ownership detection
entirely (write-and-forget) and does **not** run the discovery or
orphan-detection controllers.

**When ON:** full ownership tracking, discovery, and orphan detection —
**no additional Vault grant is required**; the records live inside objects the
operator already reads and writes.

A static-token `VaultConnection` has no auth mount and therefore no ownership
identity; with markers on it emits a `Warning` event
`OwnershipIdentityUnavailable` (unsupported for multi-operator Vaults).

!!! warning "Used but not activated"
    If markers are OFF and a CR sets `conflictPolicy: Adopt` (or the annotation
    `vault.platform.io/adopt=true`), that CR is expressing ownership intent the
    operator cannot honor. The controller emits a `Warning` event
    `ManagedMarkersDisabled` (reconcile still proceeds), and — when
    `--enable-webhooks` is set — the validating webhook **rejects the create at
    admission**. A plain or defaulted `conflictPolicy: Fail` is allowed silently.

!!! danger "Migration — breaking changes"
    1. **Default-off.** Deployments that relied on always-on markers (pre-0.8)
       **silently lose** ownership tracking, discovery, and orphan detection after
       upgrade unless they set `--managed-markers=true`.
    2. **The marker subtree is gone.** The operator no longer uses
       `secret/metadata/vault-access-operator/managed/*` (nor the older
       `secret/data/…` variant) — remove that grant from the operator's Vault
       policy and delete the inert subtree manually
       (`vault kv metadata delete` per path). Policies written by earlier
       versions read as **unmanaged** → conflict under the default `Fail`
       policy. The Vault policies/roles themselves are **untouched** (no data
       loss); only ownership tracking resets. **Remedy:** set
       `ConflictPolicy: Adopt` (or annotate `vault.platform.io/adopt=true`)
       while enabling; each policy is then rewritten once with the in-band
       header.

    See [ADR 0008](adr/0008-in-band-ownership-markers.md).

---

## Example Values Files

### Minimal

```yaml
# values-minimal.yaml
replicaCount: 1

webhook:
  certManager:
    enabled: true

logging:
  level: info
```

### Production

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

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: vault-access-operator
          topologyKey: kubernetes.io/hostname

podDisruptionBudget:
  enabled: true
  minAvailable: 2

priorityClassName: system-cluster-critical

logging:
  level: info
  encoder: json

webhook:
  enabled: true
  failurePolicy: Fail
  certManager:
    enabled: true

metrics:
  enabled: true

serviceMonitor:
  enabled: true
  interval: 30s
```

### Development

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
  failurePolicy: Ignore
  certManager:
    enabled: true
```

### Without Webhooks

```yaml
# values-no-webhooks.yaml
webhook:
  enabled: false
```

### Without cert-manager

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

=== "Disable Webhooks"

    ```yaml
    # values-no-webhooks.yaml
    webhook:
      enabled: false
    ```

### With Prometheus Monitoring

```yaml
# values-monitoring.yaml
metrics:
  enabled: true
  secure: true
  port: 8443

serviceMonitor:
  enabled: true
  namespace: monitoring
  labels:
    release: prometheus
  interval: 30s
  scrapeTimeout: 10s
```

### Air-gapped Environment

```yaml
# values-airgapped.yaml
image:
  repository: internal-registry.example.com/vault-access-operator
  pullPolicy: IfNotPresent
  tag: "v0.1.0"

imagePullSecrets:
  - name: internal-registry-creds

webhook:
  certManager:
    enabled: false
  selfSigned:
    enabled: true
```

---

## Next Steps

- [Getting Started](getting-started.md) - Installation guide
- [API Reference](api-reference.md) - CRD documentation
- [Examples](examples.md) - CRD usage examples
