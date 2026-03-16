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
