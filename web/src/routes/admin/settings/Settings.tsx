import { useState, type FormEvent, type ReactNode } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type {
  AnonymousMode,
  AuthSettings,
  AuthSettingsUpdate,
  LoginMode,
} from '~/api/settings'
import { useRepositories } from '~/queries/useRepositories'
import { useAuthSettings, useUpdateAuthSettings } from '~/queries/useSettings'
import {
  Button,
  Checkbox,
  Code,
  Columns,
  Fieldset,
  Notice,
  Page,
  PageHeader,
  Panel,
  SelectField,
  Skeleton,
  TextField,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'

export const Route = createFileRoute('/_app/manage/settings')({
  component: SettingsScreen,
})

const DESCRIPTION =
  'Who may read without signing in, and how people sign in. Changes apply to every instance within seconds, without a restart.'

/**
 * Settings screen (`/admin/settings/auth`): the sign-in and anonymous-access
 * policy, which every instance applies without a restart.
 *
 *  - **Anonymous access**: the mode; the side column lists the
 *    repositories that allow anonymous reads (the other half of the switch).
 *  - **Sign-in**: the login screen's mode, password Basic on the feeds, the
 *    session lifetimes and the password lockout.
 *
 * Each section is a form panel that saves its own fields (`PUT` changes only
 * what it names), so saving one never undoes a change another administrator
 * made to the other.
 */
function SettingsScreen() {
  const settings = useAuthSettings()

  return (
    <Page>
      <PageHeader title="Settings" description={DESCRIPTION} />
      {settings.isError ? (
        <ErrorState
          title="Could not load the settings"
          message={settings.error?.message}
          onRetry={() => void settings.refetch()}
        />
      ) : settings.isLoading || !settings.data ? (
        <Skeleton lines={6} label="Loading settings…" />
      ) : (
        <Columns aside={<AnonymousRepositories />} asideLabel="Anonymous reads">
          <AnonymousAccessForm settings={settings.data} />
          <SignInForm settings={settings.data} />
        </Columns>
      )}
    </Page>
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

/** A field's error, announced when it appears. */
function fieldError(error: string | null | undefined): ReactNode {
  return error ? <span role="alert">{error}</span> : undefined
}

/** The outcome of a section's save, at the end of its panel. */
function SaveOutcome({
  saved,
  error,
}: {
  saved: boolean
  error: string | null
}) {
  if (error) return <Notice tone="danger">{error}</Notice>
  if (saved) return <Notice tone="ok">Saved.</Notice>
  return null
}

/** A section's submit button, in its panel's footer. */
function SaveButton({ pending, children }: { pending: boolean; children: string }) {
  return (
    <Button type="submit" variant="primary" disabled={pending}>
      {pending ? 'Saving…' : children}
    </Button>
  )
}

const MODE_HINTS: Record<AnonymousMode, string> = {
  off: 'Every request needs credentials.',
  all: 'Everyone reads without credentials; signed-in users also read what anonymous callers may.',
}

/** The anonymous-access mode. */
function AnonymousAccessForm({ settings }: { settings: AuthSettings }) {
  const update = useUpdateAuthSettings()
  const [mode, setMode] = useState<AnonymousMode>(settings.anonymous_mode)

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    update.mutate({ anonymous_mode: mode })
  }

  const serverError = update.isError ? update.error.body || update.error.message : null
  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      title="Anonymous access"
      description={
        <>
          A repository is read without credentials only when both this mode
          and the repository allow it: the repository&apos;s{' '}
          <strong>Allow anonymous read</strong>, or a grant of the{' '}
          <Code>anonymous</Code> role. Writing always needs a grant. To let
          a network in without credentials, have the load balancer name a
          service account through a trusted-header realm (
          <Link to="/manage/realms" className="fg-link">
            Authentication
          </Link>
          ).
        </>
      }
      footer={<SaveButton pending={update.isPending}>Save anonymous access</SaveButton>}
    >
      <div className="fg-form">
        <SelectField
          label="Mode"
          value={mode}
          onChange={(e) => setMode(e.target.value as AnonymousMode)}
          description={MODE_HINTS[mode]}
        >
          <option value="off">Off</option>
          <option value="all">Everyone</option>
        </SelectField>
      </div>
      <SaveOutcome saved={update.isSuccess} error={serverError} />
    </Panel>
  )
}

/**
 * The side column: the repositories that allow anonymous reads, each linking
 * to its settings.
 */
function AnonymousRepositories() {
  const repos = useRepositories()
  const open = repos.data?.filter((r) => r.anonymous_read)
  return (
    <Panel
      title="Repositories allowing anonymous reads"
      description="Read without credentials when the anonymous access mode also allows it."
    >
      {repos.isError ? (
        <Notice tone="danger">Could not load the repositories.</Notice>
      ) : !open ? (
        <Skeleton lines={2} label="Loading repositories…" />
      ) : open.length === 0 ? (
        <p className="fg-text">No repository allows anonymous reads.</p>
      ) : (
        <ul className="m-0 grid list-none gap-1 p-0">
          {open.map((r) => (
            <li key={r.name}>
              <Link
                to="/manage/repositories/$repo"
                params={{ repo: r.name }}
                className="fg-link fg-mono"
              >
                {r.name}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

interface SignInDraft {
  login_mode: LoginMode
  remember_accounts: boolean
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
      remember_accounts: draft.remember_accounts,
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

/**
 * The login screen and its remembered accounts, session lifetimes and the
 * lockout. (Passwords from clients are accepted per realm, under
 * Authentication.)
 */
function SignInForm({ settings }: { settings: AuthSettings }) {
  const update = useUpdateAuthSettings()
  const [draft, setDraft] = useState<SignInDraft>({
    login_mode: settings.login_mode,
    remember_accounts: settings.remember_accounts,
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

  const serverError = update.isError ? update.error.body || update.error.message : null

  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      title="Sign-in"
      footer={<SaveButton pending={update.isPending}>Save sign-in</SaveButton>}
    >
      <div className="fg-form">
        <SelectField
          label="Login screen"
          value={draft.login_mode}
          onChange={(e) => set('login_mode', e.target.value as LoginMode)}
          description={
            <>
              {draft.login_mode === 'identifier_first'
                ? 'Asks for the username, then for the password, or sends the user to the identity provider whose login domains match it.'
                : 'Asks for username and password at once, with a button for the OIDC realm.'}{' '}
              The realms it offers are set under{' '}
              <Link to="/manage/realms" className="fg-link">
                Authentication
              </Link>
              .
            </>
          }
        >
          <option value="identifier_first">Username first</option>
          <option value="combined">Username and password</option>
        </SelectField>

        <Checkbox
          label="Remember accounts on the login screen"
          // The label wraps the description too: name the box by its label alone.
          aria-label="Remember accounts on the login screen"
          checked={draft.remember_accounts}
          onChange={(checked) => set('remember_accounts', checked)}
          description="After a sign-in, the browser keeps the account (its username, name and how it signs in, never a password or a session) and the login screen offers it next time, so signing in again is one click. Turn it off for kiosks and shared computers: their login screens then forget the accounts they kept."
        />

        <p className="fg-text fg-text--small">
          Whether a client (a NuGet feed, <Code>docker login</Code>,{' '}
          <Code>npm login</Code>) may send a user&apos;s password over HTTP Basic is
          set per realm, under{' '}
          <Link to="/manage/realms" className="fg-link">
            Authentication
          </Link>
          . An API token always works there.
        </p>

        <Fieldset
          legend="Sessions"
          description="New lifetimes apply to sessions signed in afterwards; an open session keeps its lifetime, and its idle timeout changes on its next use."
        >
          <div className="fg-fieldrow items-start">
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
        </Fieldset>

        <Fieldset
          legend="Password lockout"
          description="Each instance counts failures on its own, so behind a load balancer a client can try up to this many times per instance."
        >
          <div className="fg-fieldrow items-start">
            <TextField
              label="Failed passwords before lockout"
              mono
              type="text"
              inputMode="numeric"
              value={draft.login_max_failures}
              onChange={(e) => set('login_max_failures', e.target.value)}
              error={fieldError(errors.login_max_failures)}
              description={
                <>
                  Per client network and username; <Code>0</Code> turns the
                  lockout off.
                </>
              }
            />
            <SecondsField
              label="Lockout window (seconds)"
              value={draft.login_failure_window_seconds}
              error={errors.login_failure_window_seconds}
              onChange={(v) => set('login_failure_window_seconds', v)}
              hint="Failures count within it, and a lockout lasts as long. At most a day."
            />
          </div>
        </Fieldset>
      </div>
      <SaveOutcome saved={update.isSuccess} error={serverError} />
    </Panel>
  )
}

/** A number of seconds, with its value in words after the hint. */
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
    <TextField
      label={label}
      mono
      type="text"
      inputMode="numeric"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      error={fieldError(error)}
      description={
        <>
          {hint}
          {inWords && ` (${inWords})`}
        </>
      }
    />
  )
}
