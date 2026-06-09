import { useState } from 'react'
import clsx from 'clsx'

import type { CreateRepo, RepoKind, RepoView } from '~/api/repositories'

/**
 * Shared repository create/edit form (plan §Phase 4). Kind-conditional fields:
 *
 *  - **hosted** → `allow_redeploy`
 *  - **proxy**  → `remote_url`, `package_delay_seconds`, metadata/not-found TTLs,
 *                 and **write-only** upstream creds
 *                 (the password is never populated from a GET — slice-1
 *                 redaction; the form offers a "set new password" affordance and
 *                 only sends it when the admin types one)
 *  - **group**  → members are managed on a separate screen (`GroupMembers`)
 *
 * On **create** `kind` is selectable; on **edit** it is fixed (identity column,
 * not updatable server-side) and shown read-only. The form computes a
 * `CreateRepo`-shaped payload; the Edit screen maps it to the partial
 * `UpdateRepo` (dropping identity fields + an empty password).
 *
 * Validation is inline/controlled (matching the codebase's Login form pattern):
 * a name is required and a proxy requires a `remote_url`.
 */

/** A draft mirrors the form fields; numbers are kept as strings while editing. */
export interface RepoFormValues {
  name: string
  kind: RepoKind
  anonymous_read: boolean
  online: boolean
  allow_redeploy: boolean
  remote_url: string
  package_delay_seconds: string
  upstream_username: string
  /** Newly-typed password; blank ⇒ "leave unchanged" on edit / "none" on create. */
  upstream_password: string
  metadata_ttl_seconds: string
  not_found_ttl_seconds: string
}

export interface RepositoryFormProps {
  /** Edit mode locks the kind + name-immutability hints; create mode is open. */
  mode: 'create' | 'edit'
  /** Existing repo (edit mode) used to seed defaults; absent in create mode. */
  existing?: RepoView
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
    kind: (existing?.kind as RepoKind) ?? 'hosted',
    anonymous_read: existing?.anonymous_read ?? false,
    online: existing?.online ?? true,
    allow_redeploy: existing?.allow_redeploy ?? false,
    remote_url: existing?.remote_url ?? '',
    package_delay_seconds: String(existing?.package_delay_seconds ?? 0),
    upstream_username: existing?.upstream_username ?? '',
    // Never seed the password — it is write-only and redacted on read.
    upstream_password: '',
    metadata_ttl_seconds:
      existing?.metadata_ttl_seconds != null
        ? String(existing.metadata_ttl_seconds)
        : '',
    not_found_ttl_seconds:
      existing?.not_found_ttl_seconds != null
        ? String(existing.not_found_ttl_seconds)
        : '',
  }
}

export function RepositoryForm({
  mode,
  existing,
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

  function validate(): boolean {
    const next: Record<string, string> = {}
    if (values.name.trim() === '') {
      next.name = 'A repository name is required.'
    }
    if (values.kind === 'proxy' && values.remote_url.trim() === '') {
      next.remote_url = 'A proxy repository requires a remote URL.'
    }
    if (values.kind === 'proxy') {
      const delay = Number(values.package_delay_seconds)
      if (!Number.isFinite(delay) || delay < 0) {
        next.package_delay_seconds = 'Delay must be a non-negative number.'
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

  const isProxy = values.kind === 'proxy'
  const isHosted = values.kind === 'hosted'
  const isGroup = values.kind === 'group'

  return (
    <form onSubmit={handleSubmit} className="max-w-2xl space-y-6">
      <Field label="Name" htmlFor="repo-name" error={errors.name}>
        <input
          id="repo-name"
          type="text"
          value={values.name}
          onChange={(e) => set('name', e.target.value)}
          autoFocus={mode === 'create'}
          className={inputClass}
        />
      </Field>

      <Field label="Kind" htmlFor="repo-kind">
        {mode === 'create' ? (
          <select
            id="repo-kind"
            value={values.kind}
            onChange={(e) => set('kind', e.target.value as RepoKind)}
            className={inputClass}
          >
            <option value="hosted">hosted</option>
            <option value="proxy">proxy</option>
            <option value="group">group</option>
          </select>
        ) : (
          <input
            id="repo-kind"
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

      <fieldset className="space-y-2">
        <Checkbox
          id="repo-online"
          checked={values.online}
          onChange={(c) => set('online', c)}
          label="Online (serve requests)"
        />
        <Checkbox
          id="repo-anon"
          checked={values.anonymous_read}
          onChange={(c) => set('anonymous_read', c)}
          label="Allow anonymous read"
        />
      </fieldset>

      {isHosted && (
        <fieldset className="space-y-2 border-t border-slate-100 pt-4">
          <legend className="text-sm font-medium text-slate-700">
            Hosted options
          </legend>
          <Checkbox
            id="repo-redeploy"
            checked={values.allow_redeploy}
            onChange={(c) => set('allow_redeploy', c)}
            label="Allow redeploy (re-push an existing version)"
          />
        </fieldset>
      )}

      {isProxy && (
        <fieldset className="space-y-4 border-t border-slate-100 pt-4">
          <legend className="text-sm font-medium text-slate-700">
            Proxy upstream
          </legend>

          <Field
            label="Remote URL"
            htmlFor="repo-remote-url"
            error={errors.remote_url}
          >
            <input
              id="repo-remote-url"
              type="url"
              value={values.remote_url}
              onChange={(e) => set('remote_url', e.target.value)}
              placeholder="https://api.nuget.org/v3/index.json"
              className={inputClass}
            />
          </Field>

          <Field
            label="Package delay (seconds)"
            htmlFor="repo-delay"
            error={errors.package_delay_seconds}
          >
            <input
              id="repo-delay"
              type="number"
              min={0}
              value={values.package_delay_seconds}
              onChange={(e) => set('package_delay_seconds', e.target.value)}
              className={inputClass}
            />
            <p className="mt-1 text-xs text-slate-500">
              Newly discovered upstream versions stay hidden for this long.
            </p>
          </Field>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label="Metadata TTL (seconds)"
              htmlFor="repo-meta-ttl"
            >
              <input
                id="repo-meta-ttl"
                type="number"
                min={0}
                value={values.metadata_ttl_seconds}
                onChange={(e) => set('metadata_ttl_seconds', e.target.value)}
                placeholder="server default"
                className={inputClass}
              />
            </Field>
            <Field
              label="Not-found TTL (seconds)"
              htmlFor="repo-nf-ttl"
            >
              <input
                id="repo-nf-ttl"
                type="number"
                min={0}
                value={values.not_found_ttl_seconds}
                onChange={(e) => set('not_found_ttl_seconds', e.target.value)}
                placeholder="server default"
                className={inputClass}
              />
            </Field>
          </div>

          <Field label="Upstream username" htmlFor="repo-up-user">
            <input
              id="repo-up-user"
              type="text"
              autoComplete="off"
              value={values.upstream_username}
              onChange={(e) => set('upstream_username', e.target.value)}
              className={inputClass}
            />
          </Field>

          <Field label="Upstream password" htmlFor="repo-up-pass">
            <input
              id="repo-up-pass"
              type="password"
              autoComplete="new-password"
              value={values.upstream_password}
              onChange={(e) => set('upstream_password', e.target.value)}
              placeholder={
                mode === 'edit' && existing?.has_upstream_password
                  ? '•••••••• (set to replace)'
                  : 'Optional'
              }
              className={inputClass}
            />
            <p className="mt-1 text-xs text-slate-500">
              {mode === 'edit' && existing?.has_upstream_password
                ? 'A password is stored. Leave blank to keep it; type a new one to replace it.'
                : 'Write-only. The stored secret is never shown after saving.'}
            </p>
          </Field>
        </fieldset>
      )}

      {isGroup && mode === 'edit' && (
        <p className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600">
          Group members and their priorities are managed on the{' '}
          <span className="font-medium">Members</span> screen.
        </p>
      )}
      {isGroup && mode === 'create' && (
        <p className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600">
          Create the group first, then add members from its Members screen.
        </p>
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
              ? 'Create repository'
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

const inputClass =
  'mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500'

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

/**
 * Build a `CreateRepo` body from validated form values. Only sends kind-relevant
 * fields; an empty TTL becomes `null` (server default) and an empty proxy
 * password is omitted (none set). Exported so create + edit map consistently.
 */
export function toCreateBody(values: RepoFormValues): CreateRepo {
  const body: CreateRepo = {
    name: values.name.trim(),
    kind: values.kind,
    anonymous_read: values.anonymous_read,
    online: values.online,
  }
  if (values.kind === 'hosted') {
    body.allow_redeploy = values.allow_redeploy
  }
  if (values.kind === 'proxy') {
    body.remote_url = values.remote_url.trim()
    body.package_delay_seconds = Number(values.package_delay_seconds) || 0
    body.metadata_ttl_seconds = parseTtl(values.metadata_ttl_seconds)
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

/** Empty string ⇒ null (server default); otherwise the parsed integer. */
function parseTtl(raw: string): number | null {
  if (raw.trim() === '') return null
  const n = Number(raw)
  return Number.isFinite(n) ? n : null
}
