import { useState, type ReactNode } from 'react'

import type {
  CreateRepo,
  DeploymentPolicy,
  FormatView,
  RepoKind,
  RepoView,
  UpdateRepo,
} from '~/api/repositories'
import {
  Button,
  Code,
  FormActions,
  Icon,
  Notice,
  Panel,
  SelectField,
  Switch,
  TextField,
  type IconName,
} from '~/components/ui'

/**
 * Shared repository create/edit form. Kind-conditional fields:
 *
 *  - **hosted** → `allow_redeploy` (NuGet) / `immutable_tags` +
 *                 `latest_mutable` (docker), and the upload limit
 *                 (`max_upload_bytes`, entered in MiB; empty = the format's
 *                 default)
 *  - **proxy**  → `remote_url`, `package_delay_seconds` (not docker),
 *                 metadata/not-found TTLs, and **write-only** upstream creds
 *                 (the password is never populated from a GET; the form
 *                 offers a "set new password" affordance and only sends it
 *                 when the admin types one)
 *  - **group**  → `prefer_hosted`, `reserved_prefixes`, and for docker the
 *                 optional `writable_member`; members are managed on a
 *                 separate screen (`GroupMembers`)
 *  - **docker** (any kind) → the optional `host` the repository also answers
 *                 on at the root
 *  - **raw** → instead of the NuGet options: the deployment policy (hosted),
 *                 whether files display in the browser (any kind), and the
 *                 maximum age of a proxy's cached files; a raw group has no
 *                 dependency-confusion options
 *
 * On **create** `format` and `kind` are selectable (the kinds the format
 * supports: format plugins have no proxies); on **edit** both are fixed
 * (identity columns, not updatable server-side) and shown read-only. The form
 * emits its values; `toCreateBody` / `toUpdateBody` turn them into the request
 * bodies, sending only the options that apply to the format and kind (the
 * server rejects docker options on a NuGet repository and NuGet-only ones on a
 * docker repository). An update carries only the fields the admin changed
 * (absent = keep); the nullable fields are sent as `null` only when explicitly
 * cleared (an emptied TTL reverts to the server default, "Remove stored
 * credentials" clears both upstream credentials, an emptied host / writable
 * member is removed).
 *
 * Validation is inline/controlled (matching the codebase's Login form pattern):
 * the name must match the server's rule ({@link validateRepoName}; stricter
 * for docker), a proxy requires a `remote_url`, and a docker host must be a
 * plain DNS name.
 */

/**
 * The server's repository-name rule: 1–64 characters, letters, digits, `.`,
 * `_`, `-`, starting with a letter or digit (the name is a URL path segment of
 * the feed, `/v3/<name>/index.json`).
 */
export const REPO_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

/**
 * A docker repository name is also the first component of every image name
 * (`<registry>/<name>/<image>`), so it must be a lowercase OCI name component:
 * lowercase letters and digits, separated by `.`, `_`, `__` or `-` runs.
 */
export const DOCKER_REPO_NAME_PATTERN = /^[a-z0-9]+(?:(?:\.|__?|-+)[a-z0-9]+)*$/

/**
 * Validate a repository name; returns the inline error, or `null` when valid.
 * `new` (any case) is reserved: it is the create screen's path segment
 * (`/manage/repositories/new`), so a repository with that name could never
 * be opened for editing. A docker repository's name must in addition be a
 * lowercase OCI name component ({@link DOCKER_REPO_NAME_PATTERN}).
 */
export function validateRepoName(
  raw: string,
  format: string = 'nuget',
): string | null {
  const name = raw.trim()
  if (name === '') return 'A repository name is required.'
  if (name.toLowerCase() === 'new') {
    return '"new" is reserved and cannot be used as a repository name.'
  }
  if (!REPO_NAME_PATTERN.test(name)) {
    return name.length > 64
      ? 'A repository name can be at most 64 characters long.'
      : 'Use only letters, digits, ".", "_" and "-", starting with a letter or digit (no spaces).'
  }
  if (format === DOCKER_FORMAT.id && !DOCKER_REPO_NAME_PATTERN.test(name)) {
    return name !== name.toLowerCase()
      ? 'A docker repository name must be lowercase (it starts every image name).'
      : 'A docker repository name must start and end with a letter or digit, with single ".", "_", "__" or "-" separators between them.'
  }
  return null
}

/**
 * Validate a docker repository's optional `host`: a DNS name such as
 * `docker.example.com` — no scheme, port or path. Returns the inline error,
 * or `null` when valid (or empty: no host).
 */
export function validateDockerHost(raw: string): string | null {
  const host = raw.trim()
  if (host === '') return null
  const label = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/
  const labels = host.replace(/\.$/, '').split('.')
  if (host.length > 253 || labels.length < 2 || !labels.every((l) => label.test(l))) {
    return 'Give a DNS name such as docker.example.com (no scheme, port or path).'
  }
  return null
}

/** `scheme://host[:port]` of a URL, or `null` when it does not parse. */
function originOf(url: string | null | undefined): string | null {
  if (!url) return null
  try {
    return new URL(url.trim()).origin
  } catch {
    return null
  }
}

/** The NuGet format: what the form offers when the format list is unavailable. */
export const NUGET_FORMAT: FormatView = {
  id: 'nuget',
  name: 'NuGet',
  builtin: true,
  kinds: ['hosted', 'proxy', 'group'],
  mount: '/v3',
}

/**
 * The Docker / OCI registry format, built in like NuGet. Its repositories
 * carry their own options (`host`, immutable tags, a group's writable member).
 */
export const DOCKER_FORMAT: FormatView = {
  id: 'docker',
  name: 'Docker / OCI',
  builtin: true,
  kinds: ['hosted', 'proxy', 'group'],
  mount: '/v2',
}

/**
 * Raw (generic file) repositories, built in: files under arbitrary paths,
 * served under `/raw`. They carry their own options (deployment policy,
 * content disposition, a proxy's maximum age).
 */
export const RAW_FORMAT: FormatView = {
  id: 'raw',
  name: 'Raw files',
  builtin: true,
  kinds: ['hosted', 'proxy', 'group'],
  mount: '/raw',
}

/** Default maximum age of a raw proxy's cached files: a day. */
export const DEFAULT_RAW_MAX_AGE_SECONDS = 86400

/** Where a repository of `format` named `name` is served. */
export function feedPath(format: FormatView, name: string): string {
  return format.id === NUGET_FORMAT.id
    ? `${format.mount}/${name}/index.json`
    : `${format.mount}/${name}/`
}

/** A draft mirrors the form fields; numbers are kept as strings while editing. */
export interface RepoFormValues {
  name: string
  /** The format id (`nuget` or a format plugin's). */
  format: string
  kind: RepoKind
  anonymous_read: boolean
  online: boolean
  allow_redeploy: boolean
  prefer_hosted: boolean
  /** Comma- or newline-separated id prefixes (group). */
  reserved_prefixes: string
  remote_url: string
  package_delay_seconds: string
  upstream_username: string
  /** Newly-typed password; blank ⇒ "leave unchanged" on edit / "none" on create. */
  upstream_password: string
  /** Edit only: "Remove stored credentials" — clear username and password. */
  clear_credentials: boolean
  metadata_ttl_seconds: string
  not_found_ttl_seconds: string
  /** Docker: host the repository also answers on; blank = none. */
  host: string
  /** Hosted docker: pushed tags may not be moved. */
  immutable_tags: boolean
  /** Hosted docker with immutable tags: `latest` may still be moved. */
  latest_mutable: boolean
  /** Docker group: hosted member pushes go to; blank = pushes refused. */
  writable_member: string
  /** Hosted: the upload limit in MiB; blank = the format's default. */
  max_upload_mib: string
  /** Hosted raw: what an upload to an existing path does. */
  deployment_policy: DeploymentPolicy
  /** Raw: files display in the browser instead of downloading. */
  inline_content: boolean
  /** Raw proxy: seconds before a cached file is re-validated; blank = a day. */
  max_age_seconds: string
}

export interface RepositoryFormProps {
  /** Edit mode locks the format + kind; create mode is open. */
  mode: 'create' | 'edit'
  /** Existing repo (edit mode) used to seed defaults; absent in create mode. */
  existing?: RepoView
  /**
   * The installed formats (`GET /admin/formats`); NuGet alone when absent
   * (e.g. while they load, or when the request failed).
   */
  formats?: FormatView[]
  /** Disabled while a mutation is in flight. */
  submitting: boolean
  /** Server-side error to surface above the submit button. */
  serverError?: string | null
  /** Emits the validated form values for the caller to turn into an API body. */
  onSubmit: (values: RepoFormValues) => void
  /** Cancel affordance (navigates back to the list). */
  onCancel: () => void
}

function seed(existing?: RepoView): RepoFormValues {
  return {
    name: existing?.name ?? '',
    format: existing?.format ?? 'nuget',
    kind: (existing?.kind as RepoKind) ?? 'hosted',
    anonymous_read: existing?.anonymous_read ?? false,
    online: existing?.online ?? true,
    allow_redeploy: existing?.allow_redeploy ?? false,
    prefer_hosted: existing?.prefer_hosted ?? true,
    reserved_prefixes: (existing?.reserved_prefixes ?? []).join(', '),
    remote_url: existing?.remote_url ?? '',
    package_delay_seconds: String(existing?.package_delay_seconds ?? 0),
    upstream_username: existing?.upstream_username ?? '',
    // Never seed the password — it is write-only and redacted on read.
    upstream_password: '',
    clear_credentials: false,
    metadata_ttl_seconds:
      existing?.metadata_ttl_seconds != null
        ? String(existing.metadata_ttl_seconds)
        : '',
    not_found_ttl_seconds:
      existing?.not_found_ttl_seconds != null
        ? String(existing.not_found_ttl_seconds)
        : '',
    host: existing?.host ?? '',
    immutable_tags: existing?.immutable_tags ?? false,
    latest_mutable: existing?.latest_mutable ?? false,
    writable_member: existing?.writable_member ?? '',
    max_upload_mib:
      existing?.max_upload_bytes != null ? bytesToMib(existing.max_upload_bytes) : '',
    deployment_policy: existing?.deployment_policy ?? 'disable_redeploy',
    inline_content: existing?.content_disposition === 'inline',
    max_age_seconds:
      existing?.max_age_seconds != null &&
      existing.max_age_seconds !== DEFAULT_RAW_MAX_AGE_SECONDS
        ? String(existing.max_age_seconds)
        : '',
  }
}

const MIB = 1024 * 1024

/** Bytes as MiB for the upload-limit field: whole MiB, or up to 6 decimals. */
export function bytesToMib(bytes: number): string {
  return String(Number((bytes / MIB).toFixed(6)))
}

/** The upload-limit field in bytes; `null` when blank or not a number. */
export function mibToBytes(raw: string): number | null {
  if (raw.trim() === '') return null
  const mib = Number(raw)
  return Number.isFinite(mib) ? Math.round(mib * MIB) : null
}

/**
 * A validation error for a field's `error`, announced as it appears: the
 * field's note under the control is not a live region of its own.
 */
function announced(message: string | undefined): ReactNode {
  return message ? <span role="alert">{message}</span> : undefined
}

/**
 * A warning that appears while the admin types, announced politely
 * (`role="status"`); the kit's warn `Notice` is an alert, too loud for it.
 */
function WarnStatus({ children }: { children: ReactNode }) {
  return (
    <div className="fg-notice fg-notice--warn" role="status">
      <Icon name="Alert" size={16} />
      <div className="fg-notice-text">
        <div className="fg-notice-body">{children}</div>
      </div>
    </div>
  )
}

/** What a format is, for the Format field on create. */
function formatHelp(format: FormatView): string {
  if (format.description) return format.description
  if (format.id === NUGET_FORMAT.id) return 'NuGet packages, served as a NuGet V3 feed.'
  if (format.id === DOCKER_FORMAT.id) {
    return 'Container images and other OCI artifacts, served by the registry under /v2.'
  }
  if (format.id === RAW_FORMAT.id) {
    return 'Files under arbitrary paths (binaries, installers, fixtures), served under /raw.'
  }
  return 'A format plugin.'
}

/** What a kind does, for the Kind field on create. */
function kindHelp(kind: RepoKind, things: string): string {
  switch (kind) {
    case 'hosted':
      return `You push ${things} here; Forge stores them.`
    case 'proxy':
      return `Caches ${things} from an upstream on demand.`
    case 'group':
      return 'One URL over several repositories, asked in order of priority.'
  }
}

/**
 * The form, as panels: General (name, format, kind, the switches every
 * repository has), then the options of its format and kind (Registry host,
 * Hosted options, Proxy upstream, Group options), then the buttons. Its fields
 * stay within the design system's form width.
 */
export function RepositoryForm({
  mode,
  existing,
  formats,
  submitting,
  serverError,
  onSubmit,
  onCancel,
}: RepositoryFormProps) {
  const [values, setValues] = useState<RepoFormValues>(() => seed(existing))
  const [errors, setErrors] = useState<Record<string, string>>({})

  function set<K extends keyof RepoFormValues>(key: K, value: RepoFormValues[K]) {
    setValues((v) => ({ ...v, [key]: value }))
  }

  // `latest_mutable` only means something with immutable tags: clearing
  // immutability clears it too, so the disabled box never shows a stale tick.
  function setImmutableTags(immutable: boolean) {
    setValues((v) => ({
      ...v,
      immutable_tags: immutable,
      latest_mutable: immutable && v.latest_mutable,
    }))
  }

  function validate(): boolean {
    const next: Record<string, string> = {}
    // On edit only a *changed* name is checked, so a repository created
    // before the rule existed can still be edited without renaming it.
    const nameError =
      mode === 'edit' && values.name.trim() === existing?.name
        ? null
        : validateRepoName(values.name, values.format)
    if (nameError) {
      next.name = nameError
    }
    if (values.kind === 'proxy' && values.remote_url.trim() === '') {
      next.remote_url = 'A proxy repository requires a remote URL.'
    }
    if (values.kind === 'proxy' && values.format === RAW_FORMAT.id) {
      const maxAge = values.max_age_seconds.trim()
      if (maxAge !== '' && !(Number.isInteger(Number(maxAge)) && Number(maxAge) >= 0)) {
        next.max_age_seconds = 'The maximum age must be a whole number of seconds (0: never).'
      }
    }
    if (
      values.kind === 'proxy' &&
      values.format !== DOCKER_FORMAT.id &&
      values.format !== RAW_FORMAT.id
    ) {
      const delay = Number(values.package_delay_seconds)
      if (!Number.isFinite(delay) || delay < 0) {
        next.package_delay_seconds = 'Delay must be a non-negative number.'
      }
    }
    if (values.format === DOCKER_FORMAT.id) {
      const hostError = validateDockerHost(values.host)
      if (hostError) next.host = hostError
    }
    if (values.kind === 'hosted' && values.max_upload_mib.trim() !== '') {
      const bytes = mibToBytes(values.max_upload_mib)
      const ceiling = format.max_upload_bytes_limit
      if (bytes == null || bytes <= 0) {
        next.max_upload_mib = 'The upload limit must be a positive number of MiB.'
      } else if (ceiling != null && bytes > ceiling) {
        next.max_upload_mib = `At most ${bytesToMib(ceiling)} MiB: larger pushes do not fit the server's staging space.`
      }
    }
    setErrors(next)
    return Object.keys(next).length === 0
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!validate()) return
    onSubmit(values)
  }

  const available = formats && formats.length > 0 ? formats : [NUGET_FORMAT]
  // An edited repository's format may not be listed (the list failed to
  // load, or a plugin is not installed any more): the built-in formats are
  // known; any other one must have been a plugin format.
  const format: FormatView = available.find((f) => f.id === values.format) ??
    [NUGET_FORMAT, DOCKER_FORMAT, RAW_FORMAT].find((f) => f.id === values.format) ?? {
    id: values.format,
    name: values.format,
    builtin: false,
    kinds: ['hosted', 'group'],
    mount: '/repository',
  }

  function setFormat(id: string) {
    const next = available.find((f) => f.id === id) ?? NUGET_FORMAT
    setValues((v) => ({
      ...v,
      format: next.id,
      kind: next.kinds.includes(v.kind) ? v.kind : 'hosted',
    }))
  }

  const isProxy = values.kind === 'proxy'
  const isHosted = values.kind === 'hosted'
  const isGroup = values.kind === 'group'
  const isDocker = values.format === DOCKER_FORMAT.id
  const isRaw = values.format === RAW_FORMAT.id
  // What the repository holds, for the help texts.
  const things = isDocker ? 'images' : isRaw ? 'files' : 'packages'

  // Edit only: what is stored server-side for the upstream credentials.
  const hasStoredCredentials =
    mode === 'edit' &&
    (!!existing?.has_upstream_password || !!existing?.upstream_username)
  // The server drops stored credentials when the remote URL moves to a
  // different origin without a new password (they belong to the old host).
  const credentialsWillDrop =
    hasStoredCredentials &&
    !values.clear_credentials &&
    values.upstream_password === '' &&
    values.remote_url.trim() !== (existing?.remote_url ?? '') &&
    originOf(values.remote_url) !== originOf(existing?.remote_url)

  return (
    <form onSubmit={handleSubmit} className="flex min-w-0 flex-col gap-6">
      <Panel title="General">
        <div className="fg-form">
          <TextField
            label="Name"
            type="text"
            mono
            value={values.name}
            onChange={(e) => set('name', e.target.value)}
            autoFocus={mode === 'create'}
            error={announced(errors.name)}
            description={
              isDocker ? (
                <>
                  Starts every image name (<Code>&lt;registry&gt;/&lt;name&gt;/&lt;image&gt;</Code>):
                  lowercase letters and digits, separated by ".", "_", "__" or "-",
                  up to 64 characters.
                </>
              ) : (
                <>
                  Part of the feed URL (<Code>{feedPath(format, '<name>')}</Code>): letters,
                  digits, ".", "_" and "-", up to 64 characters.
                </>
              )
            }
          />

          <div className="fg-fieldrow">
            {mode === 'create' ? (
              <SelectField
                label="Format"
                value={values.format}
                onChange={(e) => setFormat(e.target.value)}
                description={formatHelp(format)}
              >
                {available.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.builtin ? f.name : `${f.name} (plugin ${f.id})`}
                  </option>
                ))}
              </SelectField>
            ) : (
              <TextField
                label="Format"
                type="text"
                value={format.builtin ? format.name : format.id}
                readOnly
                aria-readonly="true"
                description="The format cannot be changed after creation."
              />
            )}

            {mode === 'create' ? (
              <SelectField
                label="Kind"
                value={values.kind}
                onChange={(e) => set('kind', e.target.value as RepoKind)}
                description={kindHelp(values.kind, things)}
              >
                {(['hosted', 'proxy', 'group'] as const)
                  .filter((kind) => format.kinds.includes(kind))
                  .map((kind) => (
                    <option key={kind} value={kind}>
                      {kind}
                    </option>
                  ))}
              </SelectField>
            ) : (
              <TextField
                label="Kind"
                type="text"
                value={values.kind}
                readOnly
                aria-readonly="true"
                description="The kind cannot be changed after creation."
              />
            )}
          </div>

          <Switch
            label="Online"
            checked={values.online}
            onChange={(c) => set('online', c)}
            description={
              isProxy
                ? `Offline, the proxy serves only ${things} it has already cached and never contacts the upstream.`
                : `Offline, the repository answers every ${isDocker ? 'registry' : 'feed'} request with 503 (a maintenance window); in a group it counts as a failing member.`
            }
          />
          <Switch
            label="Allow anonymous read"
            checked={values.anonymous_read}
            onChange={(c) => set('anonymous_read', c)}
            description="Callers who do not sign in may read it, as far as the server-wide anonymous access lets them in."
          />
          {isRaw && (
            <Switch
              label="Display files in the browser"
              checked={values.inline_content}
              onChange={(c) => set('inline_content', c)}
              description={
                <>
                  Files are served for display (<Code>Content-Disposition: inline</Code>)
                  rather than as downloads. They stay sandboxed: an HTML or SVG file
                  cannot run script on this server&apos;s origin.
                </>
              }
            />
          )}
        </div>
      </Panel>

      {isDocker && (
        <Panel title="Registry host">
          <div className="fg-form">
            <TextField
              label="Host"
              type="text"
              mono
              autoComplete="off"
              value={values.host}
              onChange={(e) => set('host', e.target.value)}
              placeholder="docker.example.com"
              error={announced(errors.host)}
              description={
                <>
                  Optional. A DNS name pointed at this server that serves this
                  repository at its root (<Code>&lt;host&gt;/&lt;image&gt;</Code>), in
                  addition to{' '}
                  <Code>&lt;server&gt;/{values.name.trim() || '<name>'}/&lt;image&gt;</Code>.
                </>
              }
            />
          </div>
        </Panel>
      )}

      {isHosted && (
        <Panel title="Hosted options">
          <div className="fg-form">
            {isDocker ? (
              <>
                <Switch
                  label="Immutable tags"
                  checked={values.immutable_tags}
                  onChange={(c) => setImmutableTags(c)}
                  description="A pushed tag can never be moved to another manifest; pushing an existing tag again with different content is refused."
                />
                <Switch
                  label="Allow moving latest"
                  checked={values.latest_mutable}
                  disabled={!values.immutable_tags}
                  onChange={(c) => set('latest_mutable', c)}
                  description={
                    <>
                      With immutable tags, <Code>latest</Code> may still be re-pointed to
                      a newer image.
                    </>
                  }
                />
              </>
            ) : isRaw ? (
              <SelectField
                label="Deployment policy"
                value={values.deployment_policy}
                onChange={(e) =>
                  set('deployment_policy', e.target.value as DeploymentPolicy)
                }
                description="What an upload to a path that holds a file does: refused (uploading the same content again is accepted), replaces it (which needs the delete permission too), or every upload and delete is refused."
              >
                <option value="disable_redeploy">Disable redeploy</option>
                <option value="allow_redeploy">Allow redeploy</option>
                <option value="read_only">Read-only</option>
              </SelectField>
            ) : (
              <Switch
                label="Allow redeploy (re-push an existing version)"
                checked={values.allow_redeploy}
                onChange={(c) => set('allow_redeploy', c)}
              />
            )}
            <TextField
              label="Maximum upload size (MiB)"
              type="number"
              mono
              min={0}
              step="any"
              value={values.max_upload_mib}
              onChange={(e) => set('max_upload_mib', e.target.value)}
              placeholder={
                format.default_max_upload_bytes != null
                  ? `Default: ${bytesToMib(format.default_max_upload_bytes)}`
                  : 'Server default'
              }
              error={announced(errors.max_upload_mib)}
              description={
                <>
                  {isDocker
                    ? 'The largest layer (blob) a push to this repository may carry.'
                    : isRaw
                      ? 'The largest file an upload to this repository may carry.'
                      : 'The largest package a push to this repository may carry.'}{' '}
                  Empty: the server default
                  {format.default_max_upload_bytes != null
                    ? ` (${bytesToMib(format.default_max_upload_bytes)} MiB)`
                    : ''}
                  .
                  {format.max_upload_bytes_limit != null &&
                    ` At most ${bytesToMib(format.max_upload_bytes_limit)} MiB.`}{' '}
                  The reverse proxy in front of Forge must allow request bodies
                  this large.
                </>
              }
            />
          </div>
        </Panel>
      )}

      {isProxy && (
        <Panel
          title="Proxy upstream"
          description={`Where the ${things} come from, and how long Forge trusts what the upstream said.`}
        >
          <div className="fg-form">
            <TextField
              label="Remote URL"
              type="url"
              mono
              value={values.remote_url}
              onChange={(e) => set('remote_url', e.target.value)}
              placeholder={
                isDocker
                  ? 'https://registry-1.docker.io'
                  : isRaw
                    ? 'https://github.com/bblanchon/pdfium-binaries/releases/download/'
                    : values.format === NUGET_FORMAT.id
                      ? 'https://api.nuget.org/v3/index.json'
                      : 'https://charts.example.com/stable'
              }
              error={announced(errors.remote_url)}
              description={
                isDocker ? (
                  <>
                    The upstream registry&apos;s base URL, e.g.{' '}
                    <Code>https://registry-1.docker.io</Code> (Docker Hub) or{' '}
                    <Code>https://ghcr.io</Code>.
                  </>
                ) : isRaw ? (
                  <>
                    The base URL files are under: a request for <Code>&lt;path&gt;</Code>{' '}
                    fetches <Code>&lt;remote URL&gt;/&lt;path&gt;</Code>, following
                    redirects. Credentials below are sent to this URL&apos;s host only.
                  </>
                ) : undefined
              }
            />

            {isRaw && (
              <TextField
                label="Maximum age (seconds)"
                type="number"
                mono
                min={0}
                value={values.max_age_seconds}
                onChange={(e) => set('max_age_seconds', e.target.value)}
                placeholder={`Default: ${DEFAULT_RAW_MAX_AGE_SECONDS} (a day)`}
                error={announced(errors.max_age_seconds)}
                description="How long a cached file is served before the upstream is asked whether it changed. 0: never (the upstream's files do not change, as release assets)."
              />
            )}

            {!isDocker && !isRaw && (
              <TextField
                label="Package delay (seconds)"
                type="number"
                mono
                min={0}
                value={values.package_delay_seconds}
                onChange={(e) => set('package_delay_seconds', e.target.value)}
                error={announced(errors.package_delay_seconds)}
                description="New upstream releases stay hidden for this long after the upstream published them (or, when the upstream does not say when, after this proxy first saw them). Older versions are served at once."
              />
            )}

            <div className="fg-fieldrow">
              {!isRaw && (
                <TextField
                  label="Metadata TTL (seconds)"
                  type="number"
                  mono
                  min={0}
                  value={values.metadata_ttl_seconds}
                  onChange={(e) => set('metadata_ttl_seconds', e.target.value)}
                  placeholder="server default"
                />
              )}
              <TextField
                label="Not-found TTL (seconds)"
                type="number"
                mono
                min={0}
                value={values.not_found_ttl_seconds}
                onChange={(e) => set('not_found_ttl_seconds', e.target.value)}
                placeholder="server default"
              />
            </div>

            {credentialsWillDrop && (
              <WarnStatus>
                The remote URL now points to a different host. The stored
                upstream credentials will be dropped when you save, unless you
                enter a new password for the new host.
              </WarnStatus>
            )}

            <div className="fg-fieldrow">
              <TextField
                label="Upstream username"
                type="text"
                autoComplete="off"
                value={values.upstream_username}
                disabled={values.clear_credentials}
                onChange={(e) => set('upstream_username', e.target.value)}
              />
              <TextField
                label="Upstream password"
                type="password"
                autoComplete="new-password"
                value={values.upstream_password}
                disabled={values.clear_credentials}
                onChange={(e) => set('upstream_password', e.target.value)}
                placeholder={
                  mode === 'edit' && existing?.has_upstream_password
                    ? '•••••••• (set to replace)'
                    : 'Optional'
                }
                description={
                  mode === 'edit' && existing?.has_upstream_password
                    ? 'A password is stored. Leave blank to keep it; type a new one to replace it.'
                    : 'Write-only. The stored secret is never shown after saving.'
                }
              />
            </div>

            {hasStoredCredentials &&
              (values.clear_credentials ? (
                <Notice
                  tone="info"
                  action={
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() =>
                        setValues((v) => ({
                          ...v,
                          clear_credentials: false,
                          upstream_username: existing?.upstream_username ?? '',
                        }))
                      }
                    >
                      Keep them
                    </Button>
                  }
                >
                  The stored upstream username and password will be removed
                  when you save.
                </Notice>
              ) : (
                <div>
                  <Button
                    icon="Trash"
                    onClick={() =>
                      setValues((v) => ({
                        ...v,
                        clear_credentials: true,
                        upstream_username: '',
                        upstream_password: '',
                      }))
                    }
                  >
                    Remove stored credentials
                  </Button>
                </div>
              ))}
          </div>
        </Panel>
      )}

      {isGroup && (
        <Panel
          title="Group options"
          description={
            mode === 'edit'
              ? 'Group members and their priorities are managed on the Members screen.'
              : 'Create the group first, then add members from its Members screen.'
          }
        >
          {isRaw ? (
            <p className="fg-text">
              A path is served by the first member, by priority, that has it.
            </p>
          ) : (
            <div className="fg-form">
              <Switch
                label={`Prefer hosted ${isDocker ? 'images' : 'packages'}`}
                checked={values.prefer_hosted}
                onChange={(c) => set('prefer_hosted', c)}
                description={
                  isDocker
                    ? 'When an image exists in a hosted member, its tags from proxy members are hidden. Protects internal image names against dependency confusion from public registries.'
                    : 'When a package exists in a hosted member, versions of it from proxy members are hidden. Protects internal package names against dependency confusion from public feeds.'
                }
              />
              <TextField
                label="Reserved prefixes"
                name="reserved_prefixes"
                mono
                value={values.reserved_prefixes}
                onChange={(e) => set('reserved_prefixes', e.target.value)}
                placeholder={isDocker ? 'acme/, team/' : 'Acme., Contoso.Internal.'}
                description={
                  isDocker ? (
                    <>
                      Image names starting with one of these — namespaces such as{' '}
                      <Code>acme/</Code> — are never served from proxy members, also
                      before the first internal image is pushed. Comma separated.
                    </>
                  ) : (
                    <>
                      Package ids starting with one of these (e.g. <Code>Acme.</Code>) are
                      never served from proxy members — also before the first internal
                      version is published. Comma separated.
                    </>
                  )
                }
              />
              {isDocker && (
                <TextField
                  label="Writable member"
                  name="writable_member"
                  mono
                  autoComplete="off"
                  value={values.writable_member}
                  onChange={(e) => set('writable_member', e.target.value)}
                  placeholder="docker-hosted"
                  description={
                    <>
                      Optional. The hosted docker repository that <Code>docker push</Code>{' '}
                      to this group stores images in (make it a member too). Leave empty
                      to refuse pushes to the group.
                    </>
                  }
                />
              )}
            </div>
          )}
        </Panel>
      )}

      {serverError && (
        <Notice
          tone="danger"
          title={
            mode === 'create'
              ? 'Could not create the repository'
              : 'Could not save the repository'
          }
        >
          {serverError}
        </Notice>
      )}

      <FormActions>
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          type="submit"
          variant="primary"
          icon={mode === 'create' ? 'Plus' : undefined}
          disabled={submitting}
        >
          {submitting
            ? 'Saving…'
            : mode === 'create'
              ? 'Create repository'
              : 'Save changes'}
        </Button>
      </FormActions>
    </form>
  )
}

/** The icon of a repository kind, for page headers. */
export function kindIcon(kind: string): IconName {
  return kind === 'proxy' ? 'Globe' : kind === 'group' ? 'Layers' : 'Repository'
}

/** `host` of a URL (the URL itself when it does not parse). */
function hostOf(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}

/** A duration in seconds the short way: `48 h`, `30 min`, `90 s`. */
function shortDuration(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} h`
  if (seconds % 60 === 0) return `${seconds / 60} min`
  return `${seconds} s`
}

const DEPLOYMENT_POLICY_FACTS: Record<DeploymentPolicy, string | null> = {
  disable_redeploy: null,
  allow_redeploy: 'redeploy allowed',
  read_only: 'read-only',
}

/**
 * A repository's notable settings as short facts, lowercase ("caches
 * api.nuget.org", "48 h package delay", "immutable tags"): the list's
 * sub-line under a name and the edit screen's header. Only what differs from
 * the defaults, and only the options of its format and kind.
 */
export function repositoryFacts(repo: RepoView): string[] {
  const docker = repo.format === DOCKER_FORMAT.id
  const raw = repo.format === RAW_FORMAT.id
  const facts: string[] = []
  if (repo.kind === 'proxy' && repo.remote_url) {
    facts.push(`caches ${hostOf(repo.remote_url)}`)
    if (!docker && !raw && repo.package_delay_seconds > 0) {
      facts.push(`${shortDuration(repo.package_delay_seconds)} package delay`)
    }
  }
  if (repo.kind === 'hosted') {
    if (docker && repo.immutable_tags) {
      facts.push('immutable tags')
      if (repo.latest_mutable) facts.push('latest may move')
    } else if (raw) {
      const policy = DEPLOYMENT_POLICY_FACTS[repo.deployment_policy ?? 'disable_redeploy']
      if (policy) facts.push(policy)
    } else if (!docker && repo.allow_redeploy) {
      facts.push('redeploy allowed')
    }
    if (repo.max_upload_bytes != null) {
      facts.push(`${bytesToMib(repo.max_upload_bytes)} MiB max. upload`)
    }
  }
  if (repo.kind === 'group' && !raw) {
    if (repo.prefer_hosted) facts.push(`prefers hosted ${docker ? 'images' : 'packages'}`)
    const n = repo.reserved_prefixes.length
    if (n > 0) facts.push(`${n} reserved ${n === 1 ? 'prefix' : 'prefixes'}`)
    if (docker && repo.writable_member) facts.push(`pushes go to ${repo.writable_member}`)
  }
  if (docker && repo.host) facts.push(`also at ${repo.host}`)
  return facts
}

/** The first letter in upper case: a fact that starts a line. */
export function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1)
}

/**
 * Build a `CreateRepo` body from validated form values. Sends the format and
 * only the fields relevant to it and the kind — docker options never for a
 * NuGet repository, `allow_redeploy` / `package_delay_seconds` never for a
 * docker one (the server refuses both combinations); an empty TTL becomes
 * `null` (server default), and an empty proxy password, docker host or
 * writable member is omitted (none set). Exported so create + edit map
 * consistently.
 */
export function toCreateBody(values: RepoFormValues): CreateRepo {
  const docker = values.format === DOCKER_FORMAT.id
  const raw = values.format === RAW_FORMAT.id
  const body: CreateRepo = {
    name: values.name.trim(),
    kind: values.kind,
    anonymous_read: values.anonymous_read,
    online: values.online,
  }
  // Absent means NuGet, the server's default.
  if (values.format !== 'nuget') body.format = values.format
  if (docker && values.host.trim() !== '') {
    body.host = values.host.trim()
  }
  if (raw && values.inline_content) body.content_disposition = 'inline'
  if (values.kind === 'hosted') {
    if (docker) {
      body.immutable_tags = values.immutable_tags
      body.latest_mutable = values.immutable_tags && values.latest_mutable
    } else if (raw) {
      body.deployment_policy = values.deployment_policy
    } else {
      body.allow_redeploy = values.allow_redeploy
    }
    const maxUpload = mibToBytes(values.max_upload_mib)
    if (maxUpload != null) body.max_upload_bytes = maxUpload
  }
  if (values.kind === 'group' && !raw) {
    body.prefer_hosted = values.prefer_hosted
    const prefixes = parsePrefixes(values.reserved_prefixes)
    if (prefixes.length > 0) body.reserved_prefixes = prefixes
    if (docker && values.writable_member.trim() !== '') {
      body.writable_member = values.writable_member.trim()
    }
  }
  if (values.kind === 'proxy') {
    body.remote_url = values.remote_url.trim()
    if (!docker && !raw) {
      body.package_delay_seconds = Number(values.package_delay_seconds) || 0
    }
    if (raw) {
      const maxAge = parseTtl(values.max_age_seconds)
      if (maxAge != null) body.max_age_seconds = maxAge
    } else {
      body.metadata_ttl_seconds = parseTtl(values.metadata_ttl_seconds)
    }
    body.not_found_ttl_seconds = parseTtl(values.not_found_ttl_seconds)
    if (values.upstream_username.trim() !== '') {
      body.upstream_username = values.upstream_username.trim()
    }
    if (values.upstream_password !== '') {
      body.upstream_password = values.upstream_password
    }
  }
  return body
}

/** Split the reserved-prefixes field on commas, whitespace and newlines. */
export function parsePrefixes(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter((p) => p !== '')
}

/**
 * Build the partial `UpdateRepo` body for an edit: only fields that differ
 * from `existing` are sent (absent = keep). `kind` / `format` are identity
 * columns and never sent; options of the other format are never sent either.
 * For the nullable fields:
 *
 *  - a TTL emptied by the admin is sent as `null` (revert to the server
 *    default); an untouched TTL is omitted;
 *  - the username is sent when changed (`null` when emptied); the password
 *    only when a new one was typed (it is write-only, so blank = keep);
 *  - "Remove stored credentials" sends both as `null`;
 *  - a docker `host` / `writable_member` is sent when changed, `null` when
 *    emptied (removes it);
 *  - the upload limit is sent when changed, `null` when emptied (back to the
 *    format's default).
 *
 * Changing `remote_url` to another origin without a new password makes the
 * server drop the stored credentials (the form warns about it).
 */
export function toUpdateBody(
  values: RepoFormValues,
  existing: RepoView,
): UpdateRepo {
  const before = seed(existing)
  const docker = before.format === DOCKER_FORMAT.id
  const raw = before.format === RAW_FORMAT.id
  const body: UpdateRepo = {}
  const name = values.name.trim()
  if (name !== existing.name) body.name = name
  if (values.anonymous_read !== before.anonymous_read) {
    body.anonymous_read = values.anonymous_read
  }
  if (values.online !== before.online) body.online = values.online
  if (
    !docker &&
    !raw &&
    values.kind === 'hosted' &&
    values.allow_redeploy !== before.allow_redeploy
  ) {
    body.allow_redeploy = values.allow_redeploy
  }
  if (raw) {
    if (values.inline_content !== before.inline_content) {
      body.content_disposition = values.inline_content ? 'inline' : 'attachment'
    }
    if (
      values.kind === 'hosted' &&
      values.deployment_policy !== before.deployment_policy
    ) {
      body.deployment_policy = values.deployment_policy
    }
    if (
      values.kind === 'proxy' &&
      values.max_age_seconds.trim() !== before.max_age_seconds.trim()
    ) {
      body.max_age_seconds = parseTtl(values.max_age_seconds)
    }
  }
  if (docker) {
    const host = values.host.trim()
    if (host !== before.host.trim()) body.host = host === '' ? null : host
  }
  if (docker && values.kind === 'hosted') {
    if (values.immutable_tags !== before.immutable_tags) {
      body.immutable_tags = values.immutable_tags
    }
    const latestMutable = values.immutable_tags && values.latest_mutable
    if (latestMutable !== before.latest_mutable) {
      body.latest_mutable = latestMutable
    }
  }
  if (
    values.kind === 'hosted' &&
    values.max_upload_mib.trim() !== before.max_upload_mib.trim()
  ) {
    body.max_upload_bytes = mibToBytes(values.max_upload_mib)
  }
  if (docker && values.kind === 'group') {
    const member = values.writable_member.trim()
    if (member !== before.writable_member.trim()) {
      body.writable_member = member === '' ? null : member
    }
  }
  if (
    !raw &&
    values.kind === 'group' &&
    values.prefer_hosted !== before.prefer_hosted
  ) {
    body.prefer_hosted = values.prefer_hosted
  }
  if (values.kind === 'group' && !raw) {
    const prefixes = parsePrefixes(values.reserved_prefixes)
    if (prefixes.join(',') !== parsePrefixes(before.reserved_prefixes).join(',')) {
      body.reserved_prefixes = prefixes
    }
  }
  if (values.kind === 'proxy') {
    const remoteUrl = values.remote_url.trim()
    if (remoteUrl !== before.remote_url) body.remote_url = remoteUrl
    const delay = Number(values.package_delay_seconds) || 0
    if (!docker && !raw && delay !== existing.package_delay_seconds) {
      body.package_delay_seconds = delay
    }
    const ttls = raw
      ? (['not_found_ttl_seconds'] as const)
      : (['metadata_ttl_seconds', 'not_found_ttl_seconds'] as const)
    for (const key of ttls) {
      if (values[key].trim() !== before[key].trim()) {
        body[key] = parseTtl(values[key])
      }
    }
    if (values.clear_credentials) {
      body.upstream_username = null
      body.upstream_password = null
    } else {
      const username = values.upstream_username.trim()
      if (username !== before.upstream_username.trim()) {
        body.upstream_username = username === '' ? null : username
      }
      if (values.upstream_password !== '') {
        body.upstream_password = values.upstream_password
      }
    }
  }
  return body
}

/** Empty string ⇒ null (server default); otherwise the parsed integer. */
function parseTtl(raw: string): number | null {
  if (raw.trim() === '') return null
  const n = Number(raw)
  return Number.isFinite(n) ? n : null
}
