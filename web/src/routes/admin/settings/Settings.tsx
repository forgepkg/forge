import { useState, type FormEvent } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type {
  AnonymousMode,
  AuthSettings,
  AuthSettingsUpdate,
  LoginMode,
} from '~/api/settings'
import { useRealms } from '~/queries/useRealms'
import { useRepositories } from '~/queries/useRepositories'
import { useAuthSettings, useUpdateAuthSettings } from '~/queries/useSettings'
import { Button } from '~/components/catalyst/button'
import { Checkbox, CheckboxField } from '~/components/catalyst/checkbox'
import {
  Description,
  ErrorMessage,
  Field,
  FieldGroup,
  Fieldset,
  Label,
  Legend,
} from '~/components/catalyst/fieldset'
import { Heading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
import { Select } from '~/components/catalyst/select'
import { Code, Text } from '~/components/catalyst/text'
import { Textarea } from '~/components/catalyst/textarea'
import { ErrorState } from '~/components/ErrorState'

export const Route = createFileRoute('/_app/manage/settings')({
  component: SettingsScreen,
})

/**
 * Settings screen (`/admin/settings/auth`): the sign-in and anonymous-access
 * policy, which every instance applies without a restart.
 *
 *  - **Anonymous access**: the mode and its IP allowlist, and the
 *    repositories that allow anonymous reads (the other half of the switch).
 *  - **Sign-in**: the login screen's mode, password Basic on the feeds, the
 *    session lifetimes and the password lockout.
 *
 * Each section saves its own fields (`PUT` changes only what it names), so
 * saving one never undoes a change another administrator made to the other.
 */
function SettingsScreen() {
  const settings = useAuthSettings()

  if (settings.isError) {
    return (
      <ErrorState
        title="Could not load the settings"
        message={settings.error?.message}
        onRetry={() => void settings.refetch()}
      />
    )
  }
  if (settings.isLoading || !settings.data) {
    return <Text>Loading settings…</Text>
  }

  return (
    <section className="space-y-10">
      <div>
        <Heading>Settings</Heading>
        <Text className="mt-1">
          Who may read without signing in, and how people sign in. Changes
          apply to every instance within seconds, without a restart.
        </Text>
      </div>
      <AnonymousAccessForm settings={settings.data} />
      <SignInForm settings={settings.data} />
    </section>
  )
}

/** `seconds` in words (`8 hours`, `7 days`, `90 seconds`), for the hints. */
export function formatDuration(seconds: number): string {
  const units: [number, string][] = [
    [86400, 'day'],
    [3600, 'hour'],
    [60, 'minute'],
  ]
  for (const [size, name] of units) {
    if (seconds >= size && seconds % size === 0) {
      const n = seconds / size
      return `${n} ${name}${n === 1 ? '' : 's'}`
    }
  }
  return `${seconds} second${seconds === 1 ? '' : 's'}`
}

/** A whole number ≥ `min` from a form field, or `null`. */
function parseCount(raw: string, min: number): number | null {
  const trimmed = raw.trim()
  if (!/^\d+$/.test(trimmed)) return null
  const n = Number(trimmed)
  return Number.isSafeInteger(n) && n >= min ? n : null
}

/** The outcome line of a section's save. */
function SaveOutcome({
  saved,
  error,
}: {
  saved: boolean
  error: string | null
}) {
  if (error) {
    return (
      <p
        role="alert"
        className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
      >
        {error}
      </p>
    )
  }
  if (saved) {
    return (
      <p
        role="status"
        className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-sm/6 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
      >
        Saved.
      </p>
    )
  }
  return null
}

const MODE_HINTS: Record<AnonymousMode, string> = {
  off: 'Every request needs credentials.',
  allowlist:
    'Clients whose address is in the allowlist read without credentials; everyone else signs in.',
  all: 'Everyone reads without credentials; signed-in users also read what anonymous callers may.',
}

function AnonymousAccessForm({ settings }: { settings: AuthSettings }) {
  const update = useUpdateAuthSettings()
  const [mode, setMode] = useState<AnonymousMode>(settings.anonymous_mode)
  const [allowlist, setAllowlist] = useState(settings.anonymous_ip_allowlist.join('\n'))
  const [error, setError] = useState<string | null>(null)

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const entries = allowlist
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '')
    if (mode === 'allowlist' && entries.length === 0) {
      setError('List at least one address or network for the allowlist.')
      return
    }
    setError(null)
    update.mutate({ anonymous_mode: mode, anonymous_ip_allowlist: entries })
  }

  const serverError = update.isError ? update.error.body || update.error.message : null
  return (
    <form onSubmit={handleSubmit} className="max-w-2xl space-y-6">
      <Fieldset>
        <Legend>Anonymous access</Legend>
        <Text>
          A repository is read without credentials only when both this mode
          and the repository allow it: the repository&apos;s{' '}
          <strong>Allow anonymous read</strong>, or a grant of the{' '}
          <Code>anonymous</Code> role. Writing always needs a grant.
        </Text>
        <FieldGroup>
          <Field>
            <Label>Mode</Label>
            <Select
              value={mode}
              onChange={(e) => {
                setMode(e.target.value as AnonymousMode)
                setError(null)
              }}
            >
              <option value="off">Off</option>
              <option value="allowlist">IP allowlist</option>
              <option value="all">Everyone</option>
            </Select>
            <Description>{MODE_HINTS[mode]}</Description>
          </Field>
          <Field disabled={mode !== 'allowlist'}>
            <Label>IP allowlist</Label>
            <Textarea
              rows={4}
              value={allowlist}
              onChange={(e) => {
                setAllowlist(e.target.value)
                setError(null)
              }}
              placeholder={'loopback\nprivate\n10.20.0.0/16'}
              invalid={!!error}
            />
            <Description>
              One entry per line: <Code>loopback</Code>, <Code>private</Code>{' '}
              (RFC 1918, link-local and ULA networks), <Code>local</Code> (both),
              a network (<Code>10.20.0.0/16</Code>) or an address. Behind a
              reverse proxy a client&apos;s address is known only when the
              proxy is listed in <Code>auth.trusted_proxy_cidrs</Code>, and a
              request must name the server by its own host (
              <Code>server.public_base_url</Code> or{' '}
              <Code>server.allowed_hosts</Code>); both stay in the
              configuration file.
            </Description>
            {error && <ErrorMessage role="alert">{error}</ErrorMessage>}
          </Field>
        </FieldGroup>
      </Fieldset>

      <AnonymousRepositories />

      <SaveOutcome saved={update.isSuccess} error={serverError} />
      <Button type="submit" disabled={update.isPending}>
        {update.isPending ? 'Saving…' : 'Save anonymous access'}
      </Button>
    </form>
  )
}

/** The repositories that allow anonymous reads, each linking to its page. */
function AnonymousRepositories() {
  const repos = useRepositories()
  if (repos.isError) {
    return <Text>Could not load the repositories.</Text>
  }
  if (!repos.data) {
    return <Text>Loading repositories…</Text>
  }
  const open = repos.data.filter((r) => r.anonymous_read)
  return (
    <div role="region" aria-label="Repositories allowing anonymous reads">
      <Text>
        {open.length === 0
          ? 'No repository allows anonymous reads.'
          : `${open.length === 1 ? 'One repository allows' : `${open.length} repositories allow`} anonymous reads:`}
      </Text>
      {open.length > 0 && (
        <ul className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-sm/6">
          {open.map((r) => (
            <li key={r.name}>
              <Link
                to="/manage/repositories/$repo"
                params={{ repo: r.name }}
                className="font-mono text-sky-600 hover:underline dark:text-sky-400"
              >
                {r.name}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

interface SignInDraft {
  login_mode: LoginMode
  allow_password_basic: boolean
  session_idle_ttl_seconds: string
  session_absolute_ttl_seconds: string
  login_max_failures: string
  login_failure_window_seconds: string
}

type SignInErrors = Partial<Record<keyof SignInDraft, string>>

/** The draft's values, or the errors that keep it from being saved. */
function validateSignIn(
  draft: SignInDraft,
): { body: AuthSettingsUpdate } | { errors: SignInErrors } {
  const errors: SignInErrors = {}
  const idle = parseCount(draft.session_idle_ttl_seconds, 1)
  if (idle === null) errors.session_idle_ttl_seconds = 'Enter a number of seconds, at least 1.'
  const absolute = parseCount(draft.session_absolute_ttl_seconds, 1)
  if (absolute === null)
    errors.session_absolute_ttl_seconds = 'Enter a number of seconds, at least 1.'
  const failures = parseCount(draft.login_max_failures, 0)
  if (failures === null) errors.login_max_failures = 'Enter a number, 0 or more.'
  const window = parseCount(draft.login_failure_window_seconds, 1)
  if (window === null)
    errors.login_failure_window_seconds = 'Enter a number of seconds, at least 1.'
  if (Object.keys(errors).length > 0) return { errors }
  return {
    body: {
      login_mode: draft.login_mode,
      allow_password_basic: draft.allow_password_basic,
      session_idle_ttl_seconds: idle!,
      session_absolute_ttl_seconds: absolute!,
      login_max_failures: failures!,
      login_failure_window_seconds: window!,
    },
  }
}

/** A seconds field's hint: its value in words, when it is one. */
function durationHint(raw: string): string | null {
  const n = parseCount(raw, 1)
  return n === null ? null : `= ${formatDuration(n)}`
}

function SignInForm({ settings }: { settings: AuthSettings }) {
  const update = useUpdateAuthSettings()
  const realms = useRealms()
  const [draft, setDraft] = useState<SignInDraft>({
    login_mode: settings.login_mode,
    allow_password_basic: settings.allow_password_basic,
    session_idle_ttl_seconds: String(settings.session_idle_ttl_seconds),
    session_absolute_ttl_seconds: String(settings.session_absolute_ttl_seconds),
    login_max_failures: String(settings.login_max_failures),
    login_failure_window_seconds: String(settings.login_failure_window_seconds),
  })
  const [errors, setErrors] = useState<SignInErrors>({})

  function set<K extends keyof SignInDraft>(key: K, value: SignInDraft[K]) {
    setDraft((d) => ({ ...d, [key]: value }))
    setErrors((e) => ({ ...e, [key]: undefined }))
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const checked = validateSignIn(draft)
    if ('errors' in checked) {
      setErrors(checked.errors)
      return
    }
    update.mutate(checked.body)
  }

  const forwarding = (realms.data ?? []).filter(
    (r) => r.enabled && r.kind === 'credential_forwarding',
  )
  const serverError = update.isError ? update.error.body || update.error.message : null

  return (
    <form onSubmit={handleSubmit} className="max-w-2xl space-y-6">
      <Fieldset>
        <Legend>Sign-in</Legend>
        <FieldGroup>
          <Field>
            <Label>Login screen</Label>
            <Select
              value={draft.login_mode}
              onChange={(e) => set('login_mode', e.target.value as LoginMode)}
            >
              <option value="identifier_first">Username first</option>
              <option value="combined">Username and password</option>
            </Select>
            <Description>
              {draft.login_mode === 'identifier_first'
                ? 'Asks for the username, then for the password, or sends the user to the identity provider whose login domains match it.'
                : 'Asks for username and password at once, with a button for the OIDC realm.'}{' '}
              The realms it offers are set under{' '}
              <Link
                to="/manage/realms"
                className="text-sky-600 hover:underline dark:text-sky-400"
              >
                Authentication
              </Link>
              .
            </Description>
          </Field>

          <CheckboxField>
            <Checkbox
              checked={draft.allow_password_basic}
              onChange={(checked) => set('allow_password_basic', checked)}
            />
            <Label>Accept passwords over HTTP Basic on the feeds</Label>
            <Description>
              Lets a NuGet client or script send a user&apos;s password instead of
              an API token, which always works. The admin API never accepts a
              password over Basic.
              {forwarding.length > 0 &&
                ` The enabled credential-forwarding realm${forwarding.length === 1 ? '' : 's'} ${forwarding
                  .map((r) => r.name)
                  .join(', ')} accept${forwarding.length === 1 ? 's' : ''} passwords there whatever this says.`}
            </Description>
          </CheckboxField>

          <div className="grid gap-4 sm:grid-cols-2">
            <SecondsField
              label="Session idle timeout (seconds)"
              value={draft.session_idle_ttl_seconds}
              error={errors.session_idle_ttl_seconds}
              onChange={(v) => set('session_idle_ttl_seconds', v)}
              hint="A browser session ends this long after its last use."
            />
            <SecondsField
              label="Session lifetime (seconds)"
              value={draft.session_absolute_ttl_seconds}
              error={errors.session_absolute_ttl_seconds}
              onChange={(v) => set('session_absolute_ttl_seconds', v)}
              hint="A browser session ends this long after sign-in, used or not."
            />
          </div>
          <Text>
            New lifetimes apply to sessions signed in afterwards; an open
            session keeps its lifetime, and its idle timeout changes on its
            next use.
          </Text>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <Label>Failed passwords before lockout</Label>
              <Input
                type="text"
                inputMode="numeric"
                value={draft.login_max_failures}
                onChange={(e) => set('login_max_failures', e.target.value)}
                invalid={!!errors.login_max_failures}
              />
              <Description>
                Per client network and username; <Code>0</Code> turns the
                lockout off.
              </Description>
              {errors.login_max_failures && (
                <ErrorMessage role="alert">{errors.login_max_failures}</ErrorMessage>
              )}
            </Field>
            <SecondsField
              label="Lockout window (seconds)"
              value={draft.login_failure_window_seconds}
              error={errors.login_failure_window_seconds}
              onChange={(v) => set('login_failure_window_seconds', v)}
              hint="Failures count within it, and a lockout lasts as long. At most a day."
            />
          </div>
          <Text>
            Each instance counts failures on its own, so behind a load
            balancer a client can try up to this many times per instance.
          </Text>
        </FieldGroup>
      </Fieldset>

      <SaveOutcome saved={update.isSuccess} error={serverError} />
      <Button type="submit" disabled={update.isPending}>
        {update.isPending ? 'Saving…' : 'Save sign-in'}
      </Button>
    </form>
  )
}

function SecondsField({
  label,
  value,
  error,
  hint,
  onChange,
}: {
  label: string
  value: string
  error?: string
  hint: string
  onChange: (value: string) => void
}) {
  const inWords = durationHint(value)
  return (
    <Field>
      <Label>{label}</Label>
      <Input
        type="text"
        inputMode="numeric"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        invalid={!!error}
      />
      <Description>
        {hint}
        {inWords && ` (${inWords})`}
      </Description>
      {error && <ErrorMessage role="alert">{error}</ErrorMessage>}
    </Field>
  )
}
