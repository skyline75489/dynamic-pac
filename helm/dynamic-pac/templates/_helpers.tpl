{{- define "dynamic-pac.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "dynamic-pac.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "dynamic-pac.labels" -}}
app.kubernetes.io/name: {{ include "dynamic-pac.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "dynamic-pac.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dynamic-pac.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
