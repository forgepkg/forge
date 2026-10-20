{{- define "forge-postgresql.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* The forge chart computes the same name (forge.dependencyFullname). */}}
{{- define "forge-postgresql.fullname" -}}
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

{{- define "forge-postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "forge-postgresql.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: database
{{- end }}

{{- define "forge-postgresql.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "forge-postgresql.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: envisia-forge
{{- end }}

{{- define "forge-postgresql.image" -}}
{{- $repository := .Values.image.repository }}
{{- with .Values.image.registry }}{{ $repository = printf "%s/%s" . $repository }}{{ end }}
{{- printf "%s:%s" $repository .Values.image.tag }}
{{- with .Values.image.digest }}@{{ . }}{{ end }}
{{- end }}
