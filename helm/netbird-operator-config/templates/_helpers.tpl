{{/*
Expand the name of the chart.
*/}}
{{- define "netbird-operator-config.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "netbird-operator-config.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "netbird-operator-config.labels" -}}
helm.sh/chart: {{ include "netbird-operator-config.chart" . }}
{{ include "netbird-operator-config.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "netbird-operator-config.selectorLabels" -}}
app.kubernetes.io/name: {{ include "netbird-operator-config.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
