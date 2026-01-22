# Helm Chart Values

This page documents all available Helm chart values for the Vault Access Operator.

## Installation

```bash
helm repo add vault-access-operator https://panteparak.github.io/vault-access-operator/charts
helm install vault-access-operator vault-access-operator/vault-access-operator \
  --namespace vault-access-operator-system \
  --create-namespace \
  -f values.yaml
```

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

### Pod Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podAnnotations` | Annotations for the pod | `{}` |
| `podLabels` | Labels for the pod | `{}` |
| `nodeSelector` | Node selector for scheduling | `{}` |
| `tolerations` | Tolerations for scheduling | `[]` |
| `affinity` | Affinity rules for scheduling | `{}` |
| `priorityClassName` | Priority class name | `""` |

### Security Context

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podSecurityContext.runAsNonRoot` | Run as non-root user | `true` |
| `podSecurityContext.seccompProfile.type` | Seccomp profile | `RuntimeDefault` |
| `securityContext.allowPrivilegeEscalation` | Allow privilege escalation | `false` |
| `securityContext.capabilities.drop` | Dropped capabilities | `["ALL"]` |
| `securityContext.readOnlyRootFilesystem` | Read-only root filesystem | `true` |
| `securityContext.runAsNonRoot` | Run as non-root | `true` |

### Resources

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |

### Leader Election

| Parameter | Description | Default |
|-----------|-------------|---------|
| `leaderElection.enabled` | Enable leader election | `true` |
| `leaderElection.leaseDuration` | Lease duration | `15s` |
| `leaderElection.renewDeadline` | Renew deadline | `10s` |
| `leaderElection.retryPeriod` | Retry period | `2s` |

### Metrics

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metrics.enabled` | Enable metrics endpoint | `true` |
| `metrics.secure` | Use HTTPS for metrics | `true` |
| `metrics.port` | Metrics port | `8443` |
| `metrics.service.type` | Metrics service type | `ClusterIP` |
| `metrics.service.port` | Metrics service port | `8443` |
| `metrics.service.annotations` | Metrics service annotations | `{}` |

### ServiceMonitor (Prometheus Operator)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.enabled` | Create ServiceMonitor resource | `false` |
| `serviceMonitor.namespace` | Namespace for ServiceMonitor | `""` |
| `serviceMonitor.labels` | Labels for ServiceMonitor | `{}` |
| `serviceMonitor.interval` | Scrape interval | `30s` |
| `serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `serviceMonitor.metricRelabelings` | Metric relabelings | `[]` |
| `serviceMonitor.relabelings` | Relabelings | `[]` |
| `serviceMonitor.honorLabels` | Honor labels | `false` |
| `serviceMonitor.additionalEndpoints` | Additional endpoints | `[]` |

### Health Probes

| Parameter | Description | Default |
|-----------|-------------|---------|
| `healthProbe.bindAddress` | Health probe bind address | `:8081` |

### Webhooks

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhook.enabled` | Enable admission webhooks | `true` |
| `webhook.port` | Webhook server port | `9443` |
| `webhook.failurePolicy` | Webhook failure policy | `Fail` |
| `webhook.timeoutSeconds` | Webhook timeout | `10` |
| `webhook.service.type` | Webhook service type | `ClusterIP` |
| `webhook.service.port` | Webhook service port | `443` |
| `webhook.service.targetPort` | Webhook target port | `9443` |

### Webhook Certificates (cert-manager)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhook.certManager.enabled` | Use cert-manager for certificates | `true` |
| `webhook.certManager.issuerName` | Cert-manager issuer name | `""` |
| `webhook.certManager.issuerKind` | Issuer kind (Issuer/ClusterIssuer) | `""` |
| `webhook.certManager.issuerGroup` | Issuer group | `""` |
| `webhook.certManager.duration` | Certificate duration | `8760h` |
| `webhook.certManager.renewBefore` | Renew before expiry | `360h` |

### Webhook Certificates (Self-signed)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhook.selfSigned.enabled` | Generate self-signed certificates | `false` |
| `webhook.selfSigned.validityDays` | Certificate validity (days) | `365` |

### Vault Connection Defaults

| Parameter | Description | Default |
|-----------|-------------|---------|
| `vaultConnection.address` | Default Vault address | `""` |
| `vaultConnection.authPath` | Default auth mount path | `auth/kubernetes` |
| `vaultConnection.role` | Default Kubernetes auth role | `""` |
| `vaultConnection.tls.skipVerify` | Skip TLS verification | `false` |
| `vaultConnection.tls.caSecretName` | CA certificate secret name | `""` |
| `vaultConnection.tls.caSecretKey` | CA certificate key | `ca.crt` |

### Logging

| Parameter | Description | Default |
|-----------|-------------|---------|
| `logging.level` | Log level (debug, info, error) | `info` |
| `logging.development` | Development mode | `false` |
| `logging.encoder` | Log encoder (json, console) | `json` |
| `logging.stacktraceLevel` | Stacktrace level | `error` |

### Extra Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `extraEnv` | Additional environment variables | `[]` |
| `extraVolumeMounts` | Additional volume mounts | `[]` |
| `extraVolumes` | Additional volumes | `[]` |
| `extraArgs` | Additional command-line arguments | `[]` |

### Network Policy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `networkPolicy.enabled` | Enable network policy | `false` |
| `networkPolicy.ingress` | Ingress rules | `[]` |
| `networkPolicy.egress` | Egress rules | `[]` |

### Pod Disruption Budget

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podDisruptionBudget.enabled` | Enable PDB | `false` |
| `podDisruptionBudget.minAvailable` | Minimum available pods | `1` |
| `podDisruptionBudget.maxUnavailable` | Maximum unavailable pods | `""` |

## Examples

See the [Configuration Examples](examples.md) page for complete example values files.

### Minimal Installation

```yaml
# values-minimal.yaml
replicaCount: 1
webhook:
  certManager:
    enabled: true
```

### Production Installation

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
podDisruptionBudget:
  enabled: true
  minAvailable: 2
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: vault-access-operator
          topologyKey: kubernetes.io/hostname
```

### Without Webhooks

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
serviceMonitor:
  enabled: true
  interval: 30s
  labels:
    release: prometheus
```
