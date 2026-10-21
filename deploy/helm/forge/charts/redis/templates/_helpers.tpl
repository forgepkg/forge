{{- define "forge-redis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* The forge chart computes the same name (forge.dependencyFullname). */}}
{{- define "forge-redis.fullname" -}}
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

{{- define "forge-redis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "forge-redis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: cache
{{- end }}

{{- define "forge-redis.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "forge-redis.selectorLabels" . }}
app.kubernetes.io/version: {{ include "forge-redis.imageVersion" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: envisia-forge
{{- end }}

{{/* image.tag without the digest it is pinned by. */}}
{{- define "forge-redis.imageVersion" -}}
{{- regexReplaceAll "@.*$" (toString .Values.image.tag) "" }}
{{- end }}

{{/* registry/repository:tag@digest: image.tag carries its digest
(`<tag>@sha256:…`); image.digest, when set, replaces it. */}}
{{- define "forge-redis.image" -}}
{{- $repository := .Values.image.repository }}
{{- with .Values.image.registry }}{{ $repository = printf "%s/%s" . $repository }}{{ end }}
{{- if .Values.image.digest }}
{{- printf "%s:%s@%s" $repository (include "forge-redis.imageVersion" .) .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" $repository (toString .Values.image.tag) }}
{{- end }}
{{- end }}
