{{/* ── Names and labels ─────────────────────────────────────────────────── */}}

{{- define "forge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "forge.fullname" -}}
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

{{- define "forge.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* The Forge server pods. The dependencies' NetworkPolicies admit pods with
this release's instance label and component "server". */}}
{{- define "forge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "forge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end }}

{{- define "forge.labels" -}}
helm.sh/chart: {{ include "forge.chart" . }}
{{ include "forge.selectorLabels" . }}
app.kubernetes.io/version: {{ include "forge.imageTag" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: envisia-forge
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/* An object's annotations: commonAnnotations plus its own (dict "ctx" $
"annotations" <map>), as YAML; empty when there are none. */}}
{{- define "forge.annotations" -}}
{{- $annotations := merge (deepCopy (default dict .annotations)) (deepCopy (default dict .ctx.Values.commonAnnotations)) }}
{{- with $annotations }}{{ toYaml . }}{{ end }}
{{- end }}

{{- define "forge.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "forge.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* ── Image ────────────────────────────────────────────────────────────── */}}

{{- define "forge.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag }}
{{- end }}

{{/* registry/repository:tag[@digest]. Without image.tag and image.digest, the
digest the release workflow recorded for appVersion (Chart.yaml annotation). */}}
{{- define "forge.image" -}}
{{- $repository := .Values.image.repository }}
{{- with .Values.image.registry }}
{{- $repository = printf "%s/%s" . $repository }}
{{- end }}
{{- $digest := .Values.image.digest }}
{{- if and (not $digest) (not .Values.image.tag) }}
{{- $digest = index (default dict .Chart.Annotations) "forge.envisia.de/image-digest" | default "" }}
{{- end }}
{{- printf "%s:%s" $repository (include "forge.imageTag" .) }}
{{- with $digest }}@{{ . }}{{ end }}
{{- end }}

{{/* ── Configuration (forge.toml) ──────────────────────────────────────── */}}

{{/* The URL clients use: config.server.public_base_url, else https://<host>,
else http://localhost:<containerPort> (kubectl port-forward). */}}
{{- define "forge.publicBaseUrl" -}}
{{- $server := default dict .Values.config.server }}
{{- if $server.public_base_url }}
{{- $server.public_base_url }}
{{- else if .Values.host }}
{{- printf "https://%s" .Values.host }}
{{- else }}
{{- printf "http://localhost:%d" (int .Values.containerPort) }}
{{- end }}
{{- end }}

{{/* .Values.config with the settings the chart derives (server.bind, the
public URL, the in-cluster S3 gateway); a value set in .Values.config wins. */}}
{{- define "forge.config" -}}
{{- $server := dict "bind" (printf "0.0.0.0:%d" (int .Values.containerPort)) "public_base_url" (include "forge.publicBaseUrl" .) }}
{{- $derived := dict "server" $server }}
{{- if .Values.versitygw.enabled }}
{{- $_ := set $derived "s3" (dict
      "endpoint" (printf "http://%s:%d" (include "forge.versitygw.fullname" .) (int .Values.versitygw.service.port))
      "bucket" .Values.versitygw.bucket
      "force_path_style" true) }}
{{- end }}
{{- include "forge.toml" (mergeOverwrite $derived (deepCopy .Values.config)) }}
{{- end }}

{{/* A map as a TOML document. Helm's toToml would print the YAML integers of
values.yaml (float64) as 5.36870912e+08, which Forge's integer settings
refuse; numbers here are printed by toJson (536870912). Null values are left
out. */}}
{{- define "forge.toml" -}}
{{- include "forge.toml.table" (dict "path" (list) "table" .) | trim }}
{{- end }}

{{/* One table: its header (left out for a table that only holds tables),
its keys, then its tables. */}}
{{- define "forge.toml.table" -}}
{{- $path := .path }}
{{- $scalars := dict }}
{{- $tables := dict }}
{{- range $key, $value := .table }}
{{- if kindIs "map" $value }}
{{- $_ := set $tables $key $value }}
{{- else if not (kindIs "invalid" $value) }}
{{- $_ := set $scalars $key $value }}
{{- end }}
{{- end }}
{{- if and $path (or $scalars (not $tables)) }}
{{- $keys := list }}
{{- range $path }}{{ $keys = append $keys (include "forge.toml.key" .) }}{{ end }}
{{- printf "\n\n[%s]" (join "." $keys) }}
{{- end }}
{{- range $key, $value := $scalars }}
{{- printf "\n%s = %s" (include "forge.toml.key" $key) (include "forge.toml.value" $value) }}
{{- end }}
{{- range $key, $value := $tables }}
{{- include "forge.toml.table" (dict "path" (append $path $key) "table" $value) }}
{{- end }}
{{- end }}

{{- define "forge.toml.key" -}}
{{- if regexMatch "^[A-Za-z0-9_-]+$" . }}{{ . }}{{ else }}{{ toJson . }}{{ end }}
{{- end }}

{{- define "forge.toml.value" -}}
{{- if kindIs "slice" . }}
{{- $items := list }}
{{- range . }}{{ $items = append $items (include "forge.toml.value" .) }}{{ end }}
{{- printf "[%s]" (join ", " $items) }}
{{- else if kindIs "map" . }}
{{- $items := list }}
{{- range $key, $value := . }}
{{- if not (kindIs "invalid" $value) }}
{{- $items = append $items (printf "%s = %s" (include "forge.toml.key" $key) (include "forge.toml.value" $value)) }}
{{- end }}
{{- end }}
{{- printf "{ %s }" (join ", " $items) }}
{{- else if kindIs "invalid" . }}
{{- fail "forge.toml: null inside a list cannot be written as TOML" }}
{{- else }}
{{- toJson . }}
{{- end }}
{{- end }}

{{/* ── Optional dependencies (charts/) ─────────────────────────────────── */}}

{{/* The fullname a dependency gives itself (the same rule as forge.fullname,
with the dependency's name and values): dict "ctx" $ "name" <chart name>. */}}
{{- define "forge.dependencyFullname" -}}
{{- $values := index .ctx.Values .name }}
{{- if $values.fullnameOverride }}
{{- $values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .name $values.nameOverride }}
{{- if contains $name .ctx.Release.Name }}
{{- .ctx.Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .ctx.Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "forge.postgresql.fullname" -}}
{{- include "forge.dependencyFullname" (dict "ctx" . "name" "postgresql") }}
{{- end }}

{{- define "forge.redis.fullname" -}}
{{- include "forge.dependencyFullname" (dict "ctx" . "name" "redis") }}
{{- end }}

{{- define "forge.versitygw.fullname" -}}
{{- include "forge.dependencyFullname" (dict "ctx" . "name" "versitygw") }}
{{- end }}

{{/* The container's env: the chart's variables, then .Values.env. A chart
variable that .Values.env also names is left out, so the value set there
wins without a duplicate entry. */}}
{{- define "forge.env" -}}
{{- $env := list }}
{{- $env = append $env (dict "name" "FORGE_CONFIG" "value" "/etc/forge/forge.toml") }}
{{- $env = append $env (dict "name" "RUST_LOG" "value" (toString .Values.logLevel)) }}
{{- if .Values.postgresql.enabled }}
{{- $pg := .Values.postgresql }}
{{- $env = append $env (dict "name" "POSTGRES_PASSWORD" "valueFrom" (dict "secretKeyRef" (dict
      "name" (default (include "forge.postgresql.fullname" .) $pg.auth.existingSecret)
      "key" $pg.auth.secretKey))) }}
{{- /* $(POSTGRES_PASSWORD) is expanded by the kubelet; the password must be URL-safe. */}}
{{- $env = append $env (dict "name" "FORGE_DATABASE__URL" "value" (printf "postgres://%s:$(POSTGRES_PASSWORD)@%s:%d/%s"
      $pg.auth.username (include "forge.postgresql.fullname" .) (int $pg.service.port) $pg.auth.database)) }}
{{- end }}
{{- if .Values.redis.enabled }}
{{- $redis := .Values.redis }}
{{- if $redis.auth.enabled }}
{{- $env = append $env (dict "name" "REDIS_PASSWORD" "valueFrom" (dict "secretKeyRef" (dict
      "name" (default (include "forge.redis.fullname" .) $redis.auth.existingSecret)
      "key" $redis.auth.secretKey))) }}
{{- $env = append $env (dict "name" "FORGE_REDIS__URL" "value" (printf "redis://:$(REDIS_PASSWORD)@%s:%d"
      (include "forge.redis.fullname" .) (int $redis.service.port))) }}
{{- else }}
{{- $env = append $env (dict "name" "FORGE_REDIS__URL" "value" (printf "redis://%s:%d"
      (include "forge.redis.fullname" .) (int $redis.service.port))) }}
{{- end }}
{{- end }}
{{- if .Values.versitygw.enabled }}
{{- $s3 := .Values.versitygw }}
{{- $secret := default (include "forge.versitygw.fullname" .) $s3.auth.existingSecret }}
{{- $env = append $env (dict "name" "FORGE_S3__ACCESS_KEY" "valueFrom" (dict "secretKeyRef" (dict "name" $secret "key" $s3.auth.accessKeyKey))) }}
{{- $env = append $env (dict "name" "FORGE_S3__SECRET_KEY" "valueFrom" (dict "secretKeyRef" (dict "name" $secret "key" $s3.auth.secretKeyKey))) }}
{{- end }}
{{- $userNames := list }}
{{- range .Values.env }}{{ $userNames = append $userNames .name }}{{ end }}
{{- $merged := list }}
{{- range $env }}
{{- if not (has .name $userNames) }}{{ $merged = append $merged . }}{{ end }}
{{- end }}
{{- toYaml (concat $merged .Values.env) }}
{{- end }}
