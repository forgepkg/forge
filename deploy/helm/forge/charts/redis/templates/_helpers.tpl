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

{{/* The salt of the checksum/auth annotation: auth.checksumSalt if set, else
the one kept in the chart's Secret (key checksum-salt, looked up in the
cluster), else a new random one. Chosen once per render and cached in
.Values, so the Secret and the annotation agree on the first install. */}}
{{- define "forge-redis.checksumSalt" -}}
{{- if not (hasKey .Values "__checksumSalt") }}
{{- $salt := .Values.auth.checksumSalt }}
{{- if not $salt }}
{{- $existing := lookup "v1" "Secret" .Release.Namespace (include "forge-redis.fullname" .) }}
{{- if and $existing $existing.data (hasKey $existing.data "checksum-salt") }}
{{- $salt = index $existing.data "checksum-salt" | b64dec }}
{{- else }}
{{- $salt = randAlphaNum 32 }}
{{- end }}
{{- end }}
{{- $_ := set .Values "__checksumSalt" (toString $salt) }}
{{- end }}
{{- index .Values "__checksumSalt" }}
{{- end }}

{{/* The checksum/auth pod annotation, which restarts Redis when its auth
settings change. Anyone who can read the pods can read it, and a plain hash
of a password can be tested against guesses, so a password set in
auth.password goes in hashed with forge-redis.checksumSalt. */}}
{{- define "forge-redis.authChecksum" -}}
{{- $auth := omit .Values.auth "password" "checksumSalt" }}
{{- if and .Values.auth.enabled (not .Values.auth.existingSecret) .Values.auth.password }}
{{- $_ := set $auth "password" (printf "%s\n%s" (include "forge-redis.checksumSalt" .) (toString .Values.auth.password) | sha256sum) }}
{{- end }}
{{- toJson $auth | sha256sum }}
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
