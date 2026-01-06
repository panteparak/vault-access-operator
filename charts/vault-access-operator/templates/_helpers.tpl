{{/*
Expand the name of the chart.
*/}}
{{- define "vault-access-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "vault-access-operator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "vault-access-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "vault-access-operator.labels" -}}
helm.sh/chart: {{ include "vault-access-operator.chart" . }}
{{ include "vault-access-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: {{ include "vault-access-operator.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "vault-access-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vault-access-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
control-plane: controller-manager
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "vault-access-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vault-access-operator.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name for the leader election role
*/}}
{{- define "vault-access-operator.leaderElectionRoleName" -}}
{{- printf "%s-leader-election" (include "vault-access-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the manager role
*/}}
{{- define "vault-access-operator.managerRoleName" -}}
{{- printf "%s-manager" (include "vault-access-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the metrics reader role
*/}}
{{- define "vault-access-operator.metricsReaderRoleName" -}}
{{- printf "%s-metrics-reader" (include "vault-access-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the metrics auth role
*/}}
{{- define "vault-access-operator.metricsAuthRoleName" -}}
{{- printf "%s-metrics-auth" (include "vault-access-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the webhook service
*/}}
{{- define "vault-access-operator.webhookServiceName" -}}
{{- printf "%s-webhook" (include "vault-access-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the metrics service
*/}}
{{- define "vault-access-operator.metricsServiceName" -}}
{{- printf "%s-metrics" (include "vault-access-operator.fullname" .) }}
{{- end }}

{{/*
Create the name for the webhook certificate
*/}}
{{- define "vault-access-operator.webhookCertName" -}}
{{- printf "%s-webhook-cert" (include "vault-access-operator.fullname" .) }}
{{- end }}

{{/*
Create the webhook certificate secret name
*/}}
{{- define "vault-access-operator.webhookCertSecretName" -}}
{{- printf "%s-webhook-tls" (include "vault-access-operator.fullname" .) }}
{{- end }}

{{/*
Generate the webhook service DNS name
*/}}
{{- define "vault-access-operator.webhookServiceDNS" -}}
{{- printf "%s.%s.svc" (include "vault-access-operator.webhookServiceName" .) .Release.Namespace }}
{{- end }}

{{/*
Generate the webhook service DNS names for certificate
*/}}
{{- define "vault-access-operator.webhookCertDNSNames" -}}
- {{ include "vault-access-operator.webhookServiceName" . }}
- {{ include "vault-access-operator.webhookServiceName" . }}.{{ .Release.Namespace }}
- {{ include "vault-access-operator.webhookServiceName" . }}.{{ .Release.Namespace }}.svc
- {{ include "vault-access-operator.webhookServiceName" . }}.{{ .Release.Namespace }}.svc.cluster.local
{{- end }}

{{/*
Return the image name
*/}}
{{- define "vault-access-operator.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
Return the appropriate apiVersion for network policy
*/}}
{{- define "vault-access-operator.networkPolicy.apiVersion" -}}
networking.k8s.io/v1
{{- end }}

{{/*
Return the appropriate apiVersion for pod disruption budget
*/}}
{{- define "vault-access-operator.pdb.apiVersion" -}}
policy/v1
{{- end }}
