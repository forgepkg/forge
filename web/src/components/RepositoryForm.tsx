import { useState } from 'react'

import type { CreateRepo, RepoKind, RepoView } from '~/api/repositories'
import { Button } from '~/components/catalyst/button'
import {
  Checkbox,
  CheckboxField,
  CheckboxGroup,
} from '~/components/catalyst/checkbox'
import {
  Description,
  ErrorMessage,
  Field,
  FieldGroup,
  Fieldset,
  Label,
  Legend,
} from '~/components/catalyst/fieldset'
import { Input } from '~/components/catalyst/input'
import { Select } from '~/components/catalyst/select'

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
      <Field>
        <Label>Name</Label>
        <Input
          type="text"
          value={values.name}
          onChange={(e) => set('name', e.target.value)}
          autoFocus={mode === 'create'}
          invalid={!!errors.name}
        />
        {errors.name && <ErrorMessage role="alert">{errors.name}</ErrorMessage>}
      </Field>

      <Field>
        <Label>Kind</Label>
        {mode === 'create' ? (
          <Select
            value={values.kind}
            onChange={(e) => set('kind', e.target.value as RepoKind)}
          >
            <option value="hosted">hosted</option>
            <option value="proxy">proxy</option>
            <option value="group">group</option>
          </Select>
        ) : (
          <Input
            type="text"
            value={values.kind}
            readOnly
            aria-readonly="true"
          />
        )}
        {mode === 'edit' && (
          <Description>The kind cannot be changed after creation.</Description>
        )}
      </Field>

      <CheckboxGroup>
        <CheckboxField>
          <Checkbox
            checked={values.online}
            onChange={(c) => set('online', c)}
          />
          <Label>Online (serve requests)</Label>
        </CheckboxField>
        <CheckboxField>
          <Checkbox
            checked={values.anonymous_read}
            onChange={(c) => set('anonymous_read', c)}
          />
          <Label>Allow anonymous read</Label>
        </CheckboxField>
      </CheckboxGroup>

      {isHosted && (
        <Fieldset className="border-t border-zinc-950/5 pt-4 dark:border-white/10">
          <Legend>Hosted options</Legend>
          <CheckboxGroup>
            <CheckboxField>
              <Checkbox
                checked={values.allow_redeploy}
                onChange={(c) => set('allow_redeploy', c)}
              />
              <Label>Allow redeploy (re-push an existing version)</Label>
            </CheckboxField>
          </CheckboxGroup>
        </Fieldset>
      )}

      {isProxy && (
        <Fieldset className="border-t border-zinc-950/5 pt-4 dark:border-white/10">
          <Legend>Proxy upstream</Legend>
          <FieldGroup>
            <Field>
              <Label>Remote URL</Label>
              <Input
                type="url"
                value={values.remote_url}
                onChange={(e) => set('remote_url', e.target.value)}
                placeholder="https://api.nuget.org/v3/index.json"
                invalid={!!errors.remote_url}
              />
              {errors.remote_url && (
                <ErrorMessage role="alert">{errors.remote_url}</ErrorMessage>
              )}
            </Field>

            <Field>
              <Label>Package delay (seconds)</Label>
              <Input
                type="number"
                min={0}
                value={values.package_delay_seconds}
                onChange={(e) => set('package_delay_seconds', e.target.value)}
                invalid={!!errors.package_delay_seconds}
              />
              <Description>
                Newly discovered upstream versions stay hidden for this long.
              </Description>
              {errors.package_delay_seconds && (
                <ErrorMessage role="alert">
                  {errors.package_delay_seconds}
                </ErrorMessage>
              )}
            </Field>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <Label>Metadata TTL (seconds)</Label>
                <Input
                  type="number"
                  min={0}
                  value={values.metadata_ttl_seconds}
                  onChange={(e) => set('metadata_ttl_seconds', e.target.value)}
                  placeholder="server default"
                />
              </Field>
              <Field>
                <Label>Not-found TTL (seconds)</Label>
                <Input
                  type="number"
                  min={0}
                  value={values.not_found_ttl_seconds}
                  onChange={(e) => set('not_found_ttl_seconds', e.target.value)}
                  placeholder="server default"
                />
              </Field>
            </div>

            <Field>
              <Label>Upstream username</Label>
              <Input
                type="text"
                autoComplete="off"
                value={values.upstream_username}
                onChange={(e) => set('upstream_username', e.target.value)}
              />
            </Field>

            <Field>
              <Label>Upstream password</Label>
              <Input
                type="password"
                autoComplete="new-password"
                value={values.upstream_password}
                onChange={(e) => set('upstream_password', e.target.value)}
                placeholder={
                  mode === 'edit' && existing?.has_upstream_password
                    ? '•••••••• (set to replace)'
                    : 'Optional'
                }
              />
              <Description>
                {mode === 'edit' && existing?.has_upstream_password
                  ? 'A password is stored. Leave blank to keep it; type a new one to replace it.'
                  : 'Write-only. The stored secret is never shown after saving.'}
              </Description>
            </Field>
          </FieldGroup>
        </Fieldset>
      )}

      {isGroup && mode === 'edit' && (
        <p className="rounded-lg bg-zinc-950/[2.5%] px-3 py-2 text-sm/6 text-zinc-600 ring-1 ring-zinc-950/5 dark:bg-white/[2.5%] dark:text-zinc-400 dark:ring-white/10">
          Group members and their priorities are managed on the{' '}
          <span className="font-medium">Members</span> screen.
        </p>
      )}
      {isGroup && mode === 'create' && (
        <p className="rounded-lg bg-zinc-950/[2.5%] px-3 py-2 text-sm/6 text-zinc-600 ring-1 ring-zinc-950/5 dark:bg-white/[2.5%] dark:text-zinc-400 dark:ring-white/10">
          Create the group first, then add members from its Members screen.
        </p>
      )}

      {serverError && (
        <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
          {serverError}
        </p>
      )}

      <div className="flex items-center gap-3">
        <Button type="submit" disabled={submitting}>
          {submitting
            ? 'Saving…'
            : mode === 'create'
              ? 'Create repository'
              : 'Save changes'}
        </Button>
        <Button type="button" outline onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
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
