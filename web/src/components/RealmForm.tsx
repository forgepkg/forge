import { useState } from 'react'
import clsx from 'clsx'

import type {
  CredentialForwardingConfig,
  OidcRealmConfig,
  RealmConfig,
  RealmKind,
  RealmView,
} from '~/api/realms'

/**
 * Shared auth-realm create/edit form (§12.7). Kind-conditional fields:
 *
 *  - **oidc** → issuer / client / write-only secret / claims / provisioning /
 *    login domains / button label
 *  - **credential_forwarding** → upstream URL / acceptance criteria /
 *    timeouts / groups / caching TTLs / write-only key pepper
 *  - **local** → no config; only name + enabled are editable (built-in realm)
 *
 * On **create** the kind is selectable (local is built-in and cannot be
 * created); on **edit** it is fixed and shown read-only. Secrets follow the
 * RepositoryForm `upstream_password` pattern: never seeded from the (redacted)
 * GET, placeholder shows "set to replace" when `<key>_set` is true, and a
 * blank field keeps the stored secret on edit.
 *
 * String-array fields (scopes, login domains, groups, status lists) are
 * comma-separated text inputs parsed on submit; status lists parse to numbers.
 * Blank numeric fields are omitted so the server defaults apply.
 */

/** A draft mirrors the form fields; numbers/lists stay strings while editing. */
export interface RealmFormValues {
  kind: RealmKind
  name: string
  enabled: boolean
  // Shared (oidc + credential_forwarding)
  auto_provision: boolean
  // oidc
  issuer: string
  client_id: string
  /** Newly-typed secret; blank ⇒ "leave unchanged" on edit / invalid on create. */
  client_secret: string
  scopes: string
  clock_skew_seconds: string
  allow_http_issuer: boolean
  username_claim: string
  email_claim: string
  display_name_claim: string
  link_existing_by_username: boolean
  admin_groups: string
  admin_claim: string
  login_domains: string
  button_label: string
  // credential_forwarding
  url: string
  method: string
  success_status: string
  reject_status: string
  connect_timeout_ms: string
  request_timeout_ms: string
  required_groups: string
  groups_path: string
  admin_group: string
  positive_ttl_secs: string
  negative_ttl_secs: string
  /** Newly-typed pepper; blank ⇒ "leave unchanged" on edit / invalid on create. */
  key_pepper: string
}

export interface RealmFormProps {
  /** Edit mode locks the kind; create mode offers oidc/credential_forwarding. */
  mode: 'create' | 'edit'
  /** Existing realm (edit mode) used to seed defaults; absent in create mode. */
  existing?: RealmView
  /** Disabled while a mutation is in flight. */
  submitting: boolean
  /** Server-side error (e.g. 400 invalid config, 409 duplicate name). */
  serverError?: string | null
  /** Emits the validated form values for the caller to turn into an API body. */
  onSubmit: (values: RealmFormValues) => void
  /** Cancel affordance (navigates back to the list). */
  onCancel: () => void
}

function joinList(list?: (string | number)[]): string {
  return (list ?? []).join(', ')
}

function seed(existing?: RealmView): RealmFormValues {
  const oidc = (existing?.kind === 'oidc' ? existing.config : {}) as OidcRealmConfig
  const fwd = (
    existing?.kind === 'credential_forwarding' ? existing.config : {}
  ) as CredentialForwardingConfig
  return {
    kind: existing?.kind ?? 'oidc',
    name: existing?.name ?? '',
    enabled: existing?.enabled ?? true,
    auto_provision:
      (existing?.kind === 'oidc' ? oidc.auto_provision : fwd.auto_provision) ?? true,
    issuer: oidc.issuer ?? '',
    client_id: oidc.client_id ?? '',
    // Never seed secrets — they are write-only and redacted on read.
    client_secret: '',
    scopes: joinList(oidc.scopes),
    clock_skew_seconds: oidc.clock_skew_seconds != null ? String(oidc.clock_skew_seconds) : '',
    allow_http_issuer: oidc.allow_http_issuer ?? false,
    username_claim: oidc.username_claim ?? '',
    email_claim: oidc.email_claim ?? '',
    display_name_claim: oidc.display_name_claim ?? '',
    link_existing_by_username: oidc.link_existing_by_username ?? false,
    admin_groups: joinList(oidc.admin_groups),
    admin_claim: oidc.admin_claim ?? '',
    login_domains: joinList(oidc.login_domains),
    button_label: oidc.button_label ?? '',
    url: fwd.url ?? '',
    method: fwd.method ?? '',
    success_status: joinList(fwd.success_status),
    reject_status: joinList(fwd.reject_status),
    connect_timeout_ms: fwd.connect_timeout_ms != null ? String(fwd.connect_timeout_ms) : '',
    request_timeout_ms: fwd.request_timeout_ms != null ? String(fwd.request_timeout_ms) : '',
    required_groups: joinList(fwd.required_groups),
    groups_path: fwd.groups_path ?? '',
    admin_group: fwd.admin_group ?? '',
    positive_ttl_secs: fwd.positive_ttl_secs != null ? String(fwd.positive_ttl_secs) : '',
    negative_ttl_secs: fwd.negative_ttl_secs != null ? String(fwd.negative_ttl_secs) : '',
    key_pepper: '',
  }
}

export function RealmForm({
  mode,
  existing,
  submitting,
  serverError,
  onSubmit,
  onCancel,
}: RealmFormProps) {
  const [values, setValues] = useState<RealmFormValues>(() => seed(existing))
  const [errors, setErrors] = useState<Record<string, string>>({})

  function set<K extends keyof RealmFormValues>(key: K, value: RealmFormValues[K]) {
    setValues((v) => ({ ...v, [key]: value }))
  }

  function validate(): boolean {
    const next: Record<string, string> = {}
    if (values.name.trim() === '') {
      next.name = 'A realm name is required.'
    }
    if (values.kind === 'oidc') {
      if (values.issuer.trim() === '') {
        next.issuer = 'An issuer URL is required.'
      }
      if (values.client_id.trim() === '') {
        next.client_id = 'A client ID is required.'
      }
      if (mode === 'create' && values.client_secret === '') {
        next.client_secret = 'A client secret is required.'
      }
      if (!isBlankNumber(values.clock_skew_seconds)) {
        next.clock_skew_seconds = 'Clock skew must be a non-negative number.'
      }
    }
    if (values.kind === 'credential_forwarding') {
      if (values.url.trim() === '') {
        next.url = 'An upstream URL is required.'
      }
      if (mode === 'create' && values.key_pepper === '') {
        next.key_pepper = 'A key pepper is required.'
      }
      if (!isBlankNumberList(values.success_status)) {
        next.success_status = 'Status codes must be comma-separated numbers.'
      }
      if (!isBlankNumberList(values.reject_status)) {
        next.reject_status = 'Status codes must be comma-separated numbers.'
      }
      for (const key of [
        'connect_timeout_ms',
        'request_timeout_ms',
        'positive_ttl_secs',
        'negative_ttl_secs',
      ] as const) {
        if (!isBlankNumber(values[key])) {
          next[key] = 'Must be a non-negative number.'
        }
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

  const isLocal = values.kind === 'local'
  const isOidc = values.kind === 'oidc'
  const isForwarding = values.kind === 'credential_forwarding'

  return (
    <form onSubmit={handleSubmit} className="max-w-2xl space-y-6">
      <Field label="Name" htmlFor="realm-name" error={errors.name}>
        <input
          id="realm-name"
          type="text"
          value={values.name}
          onChange={(e) => set('name', e.target.value)}
          autoFocus={mode === 'create'}
          className={inputClass}
        />
      </Field>

      <Field label="Kind" htmlFor="realm-kind">
        {mode === 'create' ? (
          <select
            id="realm-kind"
            value={values.kind}
            onChange={(e) => set('kind', e.target.value as RealmKind)}
            className={inputClass}
          >
            <option value="oidc">oidc</option>
            <option value="credential_forwarding">credential_forwarding</option>
          </select>
        ) : (
          <input
            id="realm-kind"
            type="text"
            value={values.kind}
            readOnly
            aria-readonly="true"
            className={clsx(inputClass, 'bg-slate-50 text-slate-500')}
          />
        )}
        {mode === 'edit' && (
          <p className="mt-1 text-xs text-slate-500">
            The kind cannot be changed after creation.
          </p>
        )}
      </Field>

      <Checkbox
        id="realm-enabled"
        checked={values.enabled}
        onChange={(c) => set('enabled', c)}
        label="Enabled (used for sign-in / credential checks)"
      />

      {isLocal && (
        <p className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600">
          The local realm is built in (argon2 passwords); it has no
          configuration beyond its name and enabled flag.
        </p>
      )}

      {isOidc && (
        <fieldset className="space-y-4 border-t border-slate-100 pt-4">
          <legend className="text-sm font-medium text-slate-700">
            OIDC provider
          </legend>

          <Field label="Issuer URL" htmlFor="realm-issuer" error={errors.issuer}>
            <input
              id="realm-issuer"
              type="text"
              value={values.issuer}
              onChange={(e) => set('issuer', e.target.value)}
              placeholder="https://idp.example.com/realms/main"
              className={inputClass}
            />
          </Field>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Client ID" htmlFor="realm-client-id" error={errors.client_id}>
              <input
                id="realm-client-id"
                type="text"
                autoComplete="off"
                value={values.client_id}
                onChange={(e) => set('client_id', e.target.value)}
                className={inputClass}
              />
            </Field>
            <SecretField
              id="realm-client-secret"
              label="Client secret"
              error={errors.client_secret}
              value={values.client_secret}
              onChange={(v) => set('client_secret', v)}
              stored={mode === 'edit' && hasStoredSecret(existing, 'client_secret_set')}
            />
          </div>

          <Field label="Scopes" htmlFor="realm-scopes">
            <input
              id="realm-scopes"
              type="text"
              value={values.scopes}
              onChange={(e) => set('scopes', e.target.value)}
              placeholder="openid, profile, email"
              className={inputClass}
            />
            <ListHint />
          </Field>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label="Clock skew (seconds)"
              htmlFor="realm-clock-skew"
              error={errors.clock_skew_seconds}
            >
              <input
                id="realm-clock-skew"
                type="number"
                min={0}
                value={values.clock_skew_seconds}
                onChange={(e) => set('clock_skew_seconds', e.target.value)}
                placeholder="60"
                className={inputClass}
              />
            </Field>
            <Field label="Button label" htmlFor="realm-button-label">
              <input
                id="realm-button-label"
                type="text"
                value={values.button_label}
                onChange={(e) => set('button_label', e.target.value)}
                placeholder="Login with SSO"
                className={inputClass}
              />
            </Field>
          </div>

          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Username claim" htmlFor="realm-username-claim">
              <input
                id="realm-username-claim"
                type="text"
                value={values.username_claim}
                onChange={(e) => set('username_claim', e.target.value)}
                placeholder="preferred_username"
                className={inputClass}
              />
            </Field>
            <Field label="Email claim" htmlFor="realm-email-claim">
              <input
                id="realm-email-claim"
                type="text"
                value={values.email_claim}
                onChange={(e) => set('email_claim', e.target.value)}
                placeholder="email"
                className={inputClass}
              />
            </Field>
            <Field label="Display-name claim" htmlFor="realm-display-claim">
              <input
                id="realm-display-claim"
                type="text"
                value={values.display_name_claim}
                onChange={(e) => set('display_name_claim', e.target.value)}
                placeholder="name"
                className={inputClass}
              />
            </Field>
          </div>

          <Field label="Login domains" htmlFor="realm-login-domains">
            <input
              id="realm-login-domains"
              type="text"
              value={values.login_domains}
              onChange={(e) => set('login_domains', e.target.value)}
              placeholder="example.com, corp.example.com"
              className={inputClass}
            />
            <p className="mt-1 text-xs text-slate-500">
              Email domains routed to this IdP by identifier-first login.
              Comma-separated.
            </p>
          </Field>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Admin groups" htmlFor="realm-admin-groups">
              <input
                id="realm-admin-groups"
                type="text"
                value={values.admin_groups}
                onChange={(e) => set('admin_groups', e.target.value)}
                placeholder="forge-admins"
                className={inputClass}
              />
              <ListHint />
            </Field>
            <Field label="Admin claim" htmlFor="realm-admin-claim">
              <input
                id="realm-admin-claim"
                type="text"
                value={values.admin_claim}
                onChange={(e) => set('admin_claim', e.target.value)}
                placeholder="roles"
                className={inputClass}
              />
            </Field>
          </div>

          <div className="space-y-2">
            <Checkbox
              id="realm-auto-provision"
              checked={values.auto_provision}
              onChange={(c) => set('auto_provision', c)}
              label="Auto-provision users on first login"
            />
            <Checkbox
              id="realm-link-existing"
              checked={values.link_existing_by_username}
              onChange={(c) => set('link_existing_by_username', c)}
              label="Link existing users by username"
            />
            <Checkbox
              id="realm-allow-http"
              checked={values.allow_http_issuer}
              onChange={(c) => set('allow_http_issuer', c)}
              label="Allow plain-HTTP issuer (testing only)"
            />
          </div>
        </fieldset>
      )}

      {isForwarding && (
        <fieldset className="space-y-4 border-t border-slate-100 pt-4">
          <legend className="text-sm font-medium text-slate-700">
            Credential-forwarding upstream
          </legend>

          <Field label="Upstream URL" htmlFor="realm-url" error={errors.url}>
            <input
              id="realm-url"
              type="text"
              value={values.url}
              onChange={(e) => set('url', e.target.value)}
              placeholder="https://auth.example.com/check"
              className={inputClass}
            />
          </Field>

          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Method" htmlFor="realm-method">
              <input
                id="realm-method"
                type="text"
                value={values.method}
                onChange={(e) => set('method', e.target.value)}
                placeholder="GET"
                className={inputClass}
              />
            </Field>
            <Field
              label="Success statuses"
              htmlFor="realm-success-status"
              error={errors.success_status}
            >
              <input
                id="realm-success-status"
                type="text"
                value={values.success_status}
                onChange={(e) => set('success_status', e.target.value)}
                placeholder="200"
                className={inputClass}
              />
            </Field>
            <Field
              label="Reject statuses"
              htmlFor="realm-reject-status"
              error={errors.reject_status}
            >
              <input
                id="realm-reject-status"
                type="text"
                value={values.reject_status}
                onChange={(e) => set('reject_status', e.target.value)}
                placeholder="401, 403"
                className={inputClass}
              />
            </Field>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label="Connect timeout (ms)"
              htmlFor="realm-connect-timeout"
              error={errors.connect_timeout_ms}
            >
              <input
                id="realm-connect-timeout"
                type="number"
                min={0}
                value={values.connect_timeout_ms}
                onChange={(e) => set('connect_timeout_ms', e.target.value)}
                placeholder="2000"
                className={inputClass}
              />
            </Field>
            <Field
              label="Request timeout (ms)"
              htmlFor="realm-request-timeout"
              error={errors.request_timeout_ms}
            >
              <input
                id="realm-request-timeout"
                type="number"
                min={0}
                value={values.request_timeout_ms}
                onChange={(e) => set('request_timeout_ms', e.target.value)}
                placeholder="5000"
                className={inputClass}
              />
            </Field>
          </div>

          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Required groups" htmlFor="realm-required-groups">
              <input
                id="realm-required-groups"
                type="text"
                value={values.required_groups}
                onChange={(e) => set('required_groups', e.target.value)}
                placeholder="developers"
                className={inputClass}
              />
              <ListHint />
            </Field>
            <Field label="Groups path" htmlFor="realm-groups-path">
              <input
                id="realm-groups-path"
                type="text"
                value={values.groups_path}
                onChange={(e) => set('groups_path', e.target.value)}
                placeholder="user.groups"
                className={inputClass}
              />
            </Field>
            <Field label="Admin group" htmlFor="realm-admin-group">
              <input
                id="realm-admin-group"
                type="text"
                value={values.admin_group}
                onChange={(e) => set('admin_group', e.target.value)}
                className={inputClass}
              />
            </Field>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label="Positive cache TTL (seconds)"
              htmlFor="realm-positive-ttl"
              error={errors.positive_ttl_secs}
            >
              <input
                id="realm-positive-ttl"
                type="number"
                min={0}
                value={values.positive_ttl_secs}
                onChange={(e) => set('positive_ttl_secs', e.target.value)}
                placeholder="300"
                className={inputClass}
              />
            </Field>
            <Field
              label="Negative cache TTL (seconds)"
              htmlFor="realm-negative-ttl"
              error={errors.negative_ttl_secs}
            >
              <input
                id="realm-negative-ttl"
                type="number"
                min={0}
                value={values.negative_ttl_secs}
                onChange={(e) => set('negative_ttl_secs', e.target.value)}
                placeholder="30"
                className={inputClass}
              />
            </Field>
          </div>

          <SecretField
            id="realm-key-pepper"
            label="Key pepper"
            error={errors.key_pepper}
            value={values.key_pepper}
            onChange={(v) => set('key_pepper', v)}
            stored={mode === 'edit' && hasStoredSecret(existing, 'key_pepper_set')}
          />

          <Checkbox
            id="realm-auto-provision"
            checked={values.auto_provision}
            onChange={(c) => set('auto_provision', c)}
            label="Auto-provision users on first successful check"
          />
        </fieldset>
      )}

      {serverError && (
        <p role="alert" className="text-sm text-red-600">
          {serverError}
        </p>
      )}

      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={submitting}
          className="rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-60"
        >
          {submitting
            ? 'Saving…'
            : mode === 'create'
              ? 'Create realm'
              : 'Save changes'}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100"
        >
          Cancel
        </button>
      </div>
    </form>
  )
}

function hasStoredSecret(
  existing: RealmView | undefined,
  flag: 'client_secret_set' | 'key_pepper_set',
): boolean {
  const config = existing?.config as Record<string, unknown> | undefined
  return config?.[flag] === true
}

/** Write-only secret input mirroring RepositoryForm's upstream-password UX. */
function SecretField({
  id,
  label,
  error,
  value,
  onChange,
  stored,
}: {
  id: string
  label: string
  error?: string
  value: string
  onChange: (value: string) => void
  stored: boolean
}) {
  return (
    <Field label={label} htmlFor={id} error={error}>
      <input
        id={id}
        type="password"
        autoComplete="new-password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={stored ? '•••••••• (set to replace)' : 'Required'}
        className={inputClass}
      />
      <p className="mt-1 text-xs text-slate-500">
        {stored
          ? 'A secret is stored. Leave blank to keep it; type a new one to replace it.'
          : 'Write-only. The stored secret is never shown after saving.'}
      </p>
    </Field>
  )
}

const inputClass =
  'mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500'

function ListHint() {
  return <p className="mt-1 text-xs text-slate-500">Comma-separated.</p>
}

function Field({
  label,
  htmlFor,
  error,
  children,
}: {
  label: string
  htmlFor: string
  error?: string
  children: React.ReactNode
}) {
  return (
    <div>
      <label htmlFor={htmlFor} className="block text-sm font-medium text-slate-700">
        {label}
      </label>
      {children}
      {error && (
        <p role="alert" className="mt-1 text-xs text-red-600">
          {error}
        </p>
      )}
    </div>
  )
}

function Checkbox({
  id,
  checked,
  onChange,
  label,
}: {
  id: string
  checked: boolean
  onChange: (checked: boolean) => void
  label: string
}) {
  return (
    <label htmlFor={id} className="flex items-center gap-2 text-sm text-slate-700">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="rounded border-slate-300"
      />
      {label}
    </label>
  )
}

/** "" or a parseable non-negative number. */
function isBlankNumber(raw: string): boolean {
  if (raw.trim() === '') return true
  const n = Number(raw)
  return Number.isFinite(n) && n >= 0
}

/** "" or a comma-separated list of numbers. */
function isBlankNumberList(raw: string): boolean {
  return parseList(raw).every((s) => Number.isFinite(Number(s)))
}

/** Comma-separated text -> trimmed, non-empty entries. */
export function parseList(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '')
}

/** Comma-separated text -> numbers (status lists). */
export function parseNumberList(raw: string): number[] {
  return parseList(raw).map((s) => Number(s))
}

/** Empty string ⇒ undefined (server default); otherwise the parsed number. */
function parseNumber(raw: string): number | undefined {
  if (raw.trim() === '') return undefined
  const n = Number(raw)
  return Number.isFinite(n) ? n : undefined
}

/**
 * Build the kind-specific config from validated form values. Blank optional
 * fields are omitted so server defaults apply; blank secrets are omitted so an
 * edit keeps the stored one (write-only contract). Exported so create + edit
 * map consistently.
 */
export function toRealmConfig(values: RealmFormValues): RealmConfig {
  if (values.kind === 'oidc') {
    const config: OidcRealmConfig = {
      issuer: values.issuer.trim(),
      client_id: values.client_id.trim(),
      auto_provision: values.auto_provision,
      link_existing_by_username: values.link_existing_by_username,
      allow_http_issuer: values.allow_http_issuer,
    }
    if (values.client_secret !== '') config.client_secret = values.client_secret
    const scopes = parseList(values.scopes)
    if (scopes.length > 0) config.scopes = scopes
    const skew = parseNumber(values.clock_skew_seconds)
    if (skew !== undefined) config.clock_skew_seconds = skew
    if (values.username_claim.trim() !== '') config.username_claim = values.username_claim.trim()
    if (values.email_claim.trim() !== '') config.email_claim = values.email_claim.trim()
    if (values.display_name_claim.trim() !== '') {
      config.display_name_claim = values.display_name_claim.trim()
    }
    const adminGroups = parseList(values.admin_groups)
    if (adminGroups.length > 0) config.admin_groups = adminGroups
    if (values.admin_claim.trim() !== '') config.admin_claim = values.admin_claim.trim()
    const loginDomains = parseList(values.login_domains)
    if (loginDomains.length > 0) config.login_domains = loginDomains
    if (values.button_label.trim() !== '') config.button_label = values.button_label.trim()
    return config
  }
  if (values.kind === 'credential_forwarding') {
    const config: CredentialForwardingConfig = {
      url: values.url.trim(),
      auto_provision: values.auto_provision,
    }
    if (values.method.trim() !== '') config.method = values.method.trim().toUpperCase()
    const success = parseNumberList(values.success_status)
    if (success.length > 0) config.success_status = success
    const reject = parseNumberList(values.reject_status)
    if (reject.length > 0) config.reject_status = reject
    const connect = parseNumber(values.connect_timeout_ms)
    if (connect !== undefined) config.connect_timeout_ms = connect
    const request = parseNumber(values.request_timeout_ms)
    if (request !== undefined) config.request_timeout_ms = request
    const requiredGroups = parseList(values.required_groups)
    if (requiredGroups.length > 0) config.required_groups = requiredGroups
    if (values.groups_path.trim() !== '') config.groups_path = values.groups_path.trim()
    if (values.admin_group.trim() !== '') config.admin_group = values.admin_group.trim()
    const positive = parseNumber(values.positive_ttl_secs)
    if (positive !== undefined) config.positive_ttl_secs = positive
    const negative = parseNumber(values.negative_ttl_secs)
    if (negative !== undefined) config.negative_ttl_secs = negative
    if (values.key_pepper !== '') config.key_pepper = values.key_pepper
    return config
  }
  // local (and reserved kinds): no config.
  return {}
}
