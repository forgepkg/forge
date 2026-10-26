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
app.kubernetes.io/part-of: forge
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

{{/* "true" when the chart renders its NetworkPolicy: networkPolicy.enabled,
or, while that is null, as soon as networkPolicy.from lists a peer. */}}
{{- define "forge.networkPolicyEnabled" -}}
{{- $np := .Values.networkPolicy }}
{{- if kindIs "invalid" $np.enabled }}
{{- if $np.from }}true{{ end }}
{{- else if $np.enabled }}true
{{- end }}
{{- end }}

{{/* The Secret the chart creates from secretEnv. Reserved: existingSecret
may not name it (deployment.yaml fails), or Helm would refuse to take over a
Secret created outside the release. */}}
{{- define "forge.secretEnvName" -}}
{{- printf "%s-secret-env" (include "forge.fullname" .) }}
{{- end }}

{{/* The Secret that keeps the salt of the checksum/secret-env annotation. */}}
{{- define "forge.checksumSaltName" -}}
{{- printf "%s-checksum-salt" (include "forge.fullname" .) }}
{{- end }}

{{/* The salt of the checksum/secret-env annotation: secretEnvChecksumSalt if
set, else the one kept in the Secret forge.checksumSaltName (looked up in the
cluster), else a new random one. Chosen once per render and cached in
.Values, so the Secret and the annotation agree on the first install. */}}
{{- define "forge.checksumSalt" -}}
{{- if not (hasKey .Values "__checksumSalt") }}
{{- $salt := .Values.secretEnvChecksumSalt }}
{{- if not $salt }}
{{- $existing := lookup "v1" "Secret" .Release.Namespace (include "forge.checksumSaltName" .) }}
{{- if and $existing $existing.data (hasKey $existing.data "salt") }}
{{- $salt = $existing.data.salt | b64dec }}
{{- else }}
{{- $salt = randAlphaNum 32 }}
{{- end }}
{{- end }}
{{- $_ := set .Values "__checksumSalt" (toString $salt) }}
{{- end }}
{{- index .Values "__checksumSalt" }}
{{- end }}

{{/* The checksum/secret-env pod annotation, which rolls the pods when
secretEnv changes. Anyone who can read the pods can read it, and a plain hash
of a password can be tested against guesses, so secretEnv is hashed with
forge.checksumSalt. */}}
{{- define "forge.secretEnvChecksum" -}}
{{- if .Values.secretEnv }}
{{- printf "%s\n%s" (include "forge.checksumSalt" .) (toJson .Values.secretEnv) | sha256sum }}
{{- else }}
{{- toJson .Values.secretEnv | sha256sum }}
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
{{- $digest = index (default dict .Chart.Annotations) "forge/image-digest" | default "" }}
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
{{- include "forge.requireRootKey" . }}
{{- $server := dict "bind" (printf "0.0.0.0:%d" (int .Values.containerPort)) "public_base_url" (include "forge.publicBaseUrl" .) }}
{{- if .Values.metrics.enabled }}
{{- $_ := set $server "metrics_bind" (printf "0.0.0.0:%d" (int .Values.metrics.port)) }}
{{- end }}
{{- $derived := dict "server" $server }}
{{- if .Values.versitygw.enabled }}
{{- $_ := set $derived "s3" (dict
      "endpoint" (printf "http://%s:%d" (include "forge.versitygw.fullname" .) (int .Values.versitygw.service.port))
      "bucket" .Values.versitygw.bucket
      "force_path_style" true) }}
{{- end }}
{{- $credentials := include "forge.s3Credentials" . | fromYaml }}
{{- if $credentials }}
{{- $_ := set $derived "s3" (mergeOverwrite (default dict $derived.s3) $credentials) }}
{{- end }}
{{- include "forge.toml" (mergeOverwrite $derived (deepCopy .Values.config)) }}
{{- end }}

{{/* Fail unless Forge gets the root key its secret encryption needs
(docs/deployment.md, "Secret encryption at rest"): the env provider's
variable (FORGE_ROOT_KEY) in secretEnv or env, existingSecret or envFrom
(whose keys the chart cannot see), or the file provider's root_key_path. */}}
{{- define "forge.requireRootKey" -}}
{{- $root := default dict (default dict .Values.config.crypto).root }}
{{- $var := default "FORGE_ROOT_KEY" $root.root_key_env }}
{{- $found := or .Values.existingSecret .Values.envFrom (and (eq (toString $root.provider) "file") $root.root_key_path) }}
{{- range $name := list $var "FORGE_CRYPTO__ROOT__ROOT_KEY_PATH" }}
{{- if hasKey $.Values.secretEnv $name }}{{ $found = true }}{{ end }}
{{- range $.Values.env }}
{{- if eq (toString .name) $name }}{{ $found = true }}{{ end }}
{{- end }}
{{- end }}
{{- if not $found }}
{{- fail (printf "Forge needs a root key for its secret encryption: set %s in secretEnv (generate one with `openssl rand -base64 32` and keep it with your backups), or provide it through existingSecret or env (docs/deployment.md, \"Secret encryption at rest\")" $var) }}
{{- end }}
{{- end }}

{{/* The s3.credentials settings of .Values.s3 (YAML; empty for the default
`static`), after checking them. */}}
{{- define "forge.s3Credentials" -}}
{{- $s3 := .Values.s3 }}
{{- $mode := $s3.credentials }}
{{- if not (has $mode (list "static" "default_chain" "web_identity")) }}
{{- fail (printf "s3.credentials must be static, default_chain or web_identity, not %q" $mode) }}
{{- end }}
{{- if ne $mode "static" }}
{{- if .Values.versitygw.enabled }}
{{- fail (printf "s3.credentials %s: the in-cluster versitygw (versitygw.enabled) has only static root credentials" $mode) }}
{{- end }}
{{- range $key := list "FORGE_S3__ACCESS_KEY" "FORGE_S3__SECRET_KEY" }}
{{- if hasKey $.Values.secretEnv $key }}
{{- fail (printf "s3.credentials %s does not use %s: remove it from secretEnv" $mode $key) }}
{{- end }}
{{- end }}
{{- $settings := dict "credentials" $mode }}
{{- if eq $mode "web_identity" }}
{{- $wi := $s3.webIdentity }}
{{- $tokenFile := $wi.tokenFile }}
{{- if $wi.projectedToken.enabled }}
{{- $tokenFile = include "forge.s3TokenPath" . }}
{{- end }}
{{- if not $tokenFile }}
{{- fail "s3.credentials web_identity needs s3.webIdentity.projectedToken.enabled or s3.webIdentity.tokenFile" }}
{{- end }}
{{- $table := dict "token_file" $tokenFile "session_name" $wi.sessionName }}
{{- with $wi.roleArn }}{{ $_ := set $table "role_arn" . }}{{ end }}
{{- with $wi.stsEndpoint }}{{ $_ := set $table "sts_endpoint" . }}{{ end }}
{{- if not (kindIs "invalid" $wi.durationSeconds) }}{{ $_ := set $table "duration_seconds" $wi.durationSeconds }}{{ end }}
{{- $_ := set $settings "web_identity" $table }}
{{- end }}
{{- toYaml $settings }}
{{- end }}
{{- end }}

{{/* Whether the chart mounts a projected token for s3.credentials
web_identity. */}}
{{- define "forge.s3ProjectedToken" -}}
{{- if and (eq .Values.s3.credentials "web_identity") .Values.s3.webIdentity.projectedToken.enabled }}true{{ end }}
{{- end }}

{{- define "forge.s3TokenDir" -}}
/var/run/secrets/forge/s3
{{- end }}

{{- define "forge.s3TokenPath" -}}
{{ include "forge.s3TokenDir" . }}/token
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

{{- define "forge.valkey.fullname" -}}
{{- include "forge.dependencyFullname" (dict "ctx" . "name" "valkey") }}
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
{{- if .Values.valkey.enabled }}
{{- $valkey := .Values.valkey }}
{{- /* Valkey speaks the Redis protocol: Forge reaches it with a redis:// URL. */}}
{{- if $valkey.auth.enabled }}
{{- $env = append $env (dict "name" "VALKEY_PASSWORD" "valueFrom" (dict "secretKeyRef" (dict
      "name" (default (include "forge.valkey.fullname" .) $valkey.auth.existingSecret)
      "key" $valkey.auth.secretKey))) }}
{{- $env = append $env (dict "name" "FORGE_REDIS__URL" "value" (printf "redis://:$(VALKEY_PASSWORD)@%s:%d"
      (include "forge.valkey.fullname" .) (int $valkey.service.port))) }}
{{- else }}
{{- $env = append $env (dict "name" "FORGE_REDIS__URL" "value" (printf "redis://%s:%d"
      (include "forge.valkey.fullname" .) (int $valkey.service.port))) }}
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

{{/* The scrape settings of a ServiceMonitor endpoint or a PodMonitor's
podMetricsEndpoint, from metrics.serviceMonitor / metrics.podMonitor. */}}
{{- define "forge.metricsEndpoint" -}}
path: /metrics
scheme: http
{{- with .interval }}
interval: {{ . }}
{{- end }}
{{- with .scrapeTimeout }}
scrapeTimeout: {{ . }}
{{- end }}
{{- with .bearerTokenSecret }}
authorization:
  type: Bearer
  credentials:
    {{- toYaml . | nindent 4 }}
{{- end }}
{{- with .relabelings }}
relabelings:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .metricRelabelings }}
metricRelabelings:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
