{{/*
Expand the name of the chart.
*/}}
{{- define "kubernetes-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kubernetes-operator.fullname" -}}
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
{{- define "kubernetes-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kubernetes-operator.labels" -}}
helm.sh/chart: {{ include "kubernetes-operator.chart" . }}
{{ include "kubernetes-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kubernetes-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubernetes-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kubernetes-operator.serviceAccountName" -}}
{{- if .Values.operator.serviceAccount.create }}
{{- default (include "kubernetes-operator.fullname" .) .Values.operator.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.operator.serviceAccount.name }}
{{- end }}
{{- end }}


{{/*
Create the name of the webhook service
*/}}
{{- define "kubernetes-operator.webhookService" -}}
{{- printf "%s-webhook-service" (include "kubernetes-operator.fullname" .) -}}
{{- end -}}

{{/*
Create the name of the webhook cert secret
*/}}
{{- define "kubernetes-operator.webhookCertSecret" -}}
{{- printf "%s-tls" (include "kubernetes-operator.fullname" .) -}}
{{- end -}}

{{/*
Generate certificates for webhook
*/}}
{{- define "kubernetes-operator.webhookCerts" -}}
{{- $serviceName := (include "kubernetes-operator.webhookService" .) -}}
{{- $secretName := (include "kubernetes-operator.webhookCertSecret" .) -}}
{{- $secret := lookup "v1" "Secret" .Release.Namespace $secretName -}}
{{- if (and .Values.webhook.tls.caCert .Values.webhook.tls.cert .Values.webhook.tls.key) -}}
caCert: {{ .Values.webhook.tls.caCert | b64enc }}
clientCert: {{ .Values.webhook.tls.cert | b64enc }}
clientKey: {{ .Values.webhook.tls.key | b64enc }}
{{- else if and .Values.keepTLSSecret $secret -}}
caCert: {{ index $secret.data "ca.crt" }}
clientCert: {{ index $secret.data "tls.crt" }}
clientKey: {{ index $secret.data "tls.key" }}
{{- else -}}
{{- $altNames := list (printf "%s.%s" $serviceName .Release.Namespace) (printf "%s.%s.svc" $serviceName .Release.Namespace) (printf "%s.%s.svc.%s" $serviceName .Release.Namespace .Values.webhook.cluster.dnsDomain) -}}
{{- $ca := genCA "kubernetes-operator-ca" 3650 -}}
{{- $cert := genSignedCert (include "kubernetes-operator.fullname" .) nil $altNames 3650 $ca -}}
caCert: {{ $ca.Cert | b64enc }}
clientCert: {{ $cert.Cert | b64enc }}
clientKey: {{ $cert.Key | b64enc }}
{{- end -}}
{{- end -}}