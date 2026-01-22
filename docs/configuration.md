# Configuration

This page documents all available Helm chart configuration options.

## Installation

```bash
helm repo add vault-access-operator https://panteparak.github.io/vault-access-operator/charts
helm install vault-access-operator vault-access-operator/vault-access-operator \
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

### Pod Disruption Budget

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podDisruptionBudget.enabled` | Enable PDB | `false` |
| `podDisruptionBudget.minAvailable` | Minimum available pods | `1` |

### Scheduling

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nodeSelector` | Node selector for scheduling | `{}` |
| `tolerations` | Tolerations for scheduling | `[]` |
| `affinity` | Affinity rules for scheduling | `{}` |
| `priorityClassName` | Priority class name | `""` |

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
