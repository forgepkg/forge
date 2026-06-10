import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, useRouter, useSearch } from '@tanstack/react-router'

import { fetchMe, meKeys } from '~/api/me'
import {
  fetchLoginOptions,
  identify,
  login,
  authKeys,
  type LoginOptions,
  type OidcLoginOption,
} from '~/api/auth'
import { ApiError } from '~/lib/httpClient'
import { clearToken, setSession, setToken } from '~/lib/auth'
import { assignLocation } from '~/lib/navigation'

interface LoginSearch {
  /** Where to return after a successful sign-in (set by the admin guard). */
  redirect?: string
  /** Set when the session expired mid-use (the guard / a 401 redirected here). */
  expired?: boolean
}

export const Route = createFileRoute('/login')({
  component: Login,
  validateSearch: (search: Record<string, unknown>): LoginSearch => ({
    redirect: typeof search.redirect === 'string' ? search.redirect : undefined,
    expired: search.expired === true || search.expired === 'true',
  }),
})

/**
 * Sign-in screen (§12.7 realms). On load it fetches `GET /auth/login-options`
 * and renders one of two layouts:
 *
 *  - **identifier-first** (default): step 1 asks only for the username and
 *    calls `POST /auth/identify`; depending on the realm decision step 2 shows
 *    a password field (`POST /auth/login`) or the browser is sent to the OIDC
 *    authorize URL.
 *  - **combined**: username+password always shown, plus one button per
 *    enabled OIDC realm.
 *
 * A successful password login sets the `forge_session` cookie; we persist the
 * returned CSRF token (session mode) and navigate to the `redirect` target.
 * The slice-1 token-paste form stays available as a secondary option (NuGet
 * registry tokens still work) behind a toggle.
 */
function Login() {
  const { redirect, expired } = useSearch({ from: '/login' })
  const options = useQuery<LoginOptions, ApiError>({
    queryKey: authKeys.loginOptions(),
    queryFn: ({ signal }) => fetchLoginOptions(signal),
    staleTime: 60_000,
    // Fail fast: an unreachable options endpoint immediately falls back to the
    // token form instead of retrying in front of a waiting user.
    retry: false,
  })
  const [useToken, setUseToken] = useState(false)

  // The login-options endpoint failing (old server, network) must never lock
  // the door: fall back to the token form, which needs no options.
  const tokenOnly = useToken || options.isError

  return (
    <div className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6 py-12">
      <div className="mb-8 text-center">
        <h1 className="text-2xl font-semibold text-slate-900">envisia&nbsp;forge</h1>
        <p className="mt-1 text-sm text-slate-500">Sign in to the package registry</p>
      </div>

      <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
        {expired && (
          <p
            role="alert"
            className="mb-4 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800"
          >
            Your session expired. Sign in again to continue.
          </p>
        )}

        {tokenOnly ? (
          <>
            <TokenLoginForm redirect={redirect} />
            {!options.isError && (
              <SecondaryToggle onClick={() => setUseToken(false)}>
                Back to username sign-in
              </SecondaryToggle>
            )}
          </>
        ) : options.isLoading || !options.data ? (
          <p className="text-sm text-slate-500">Loading sign-in options…</p>
        ) : (
          <>
            {options.data.mode === 'combined' ? (
              <CombinedLogin options={options.data} redirect={redirect} />
            ) : (
              <IdentifierFirstLogin redirect={redirect} />
            )}
            <SecondaryToggle onClick={() => setUseToken(true)}>
              Use a registry token instead
            </SecondaryToggle>
          </>
        )}
      </div>
    </div>
  )
}

/** "or"-divider + link toggling between the realm login and the token paste. */
function SecondaryToggle({
  onClick,
  children,
}: {
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <>
      <div className="my-5 flex items-center gap-3 text-xs uppercase tracking-wide text-slate-400">
        <span className="h-px flex-1 bg-slate-200" />
        or
        <span className="h-px flex-1 bg-slate-200" />
      </div>
      <button
        type="button"
        onClick={onClick}
        className="w-full rounded border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100"
      >
        {children}
      </button>
    </>
  )
}

/**
 * Append the post-login destination to an OIDC login URL so the server can
 * send the browser back after the IdP round-trip
 * (`/auth/oidc/login?redirect_to=...`).
 */
function oidcUrl(loginUrl: string, redirect?: string): string {
  if (!redirect) return loginUrl
  const sep = loginUrl.includes('?') ? '&' : '?'
  return `${loginUrl}${sep}redirect_to=${encodeURIComponent(redirect)}`
}

/** Shared hook: perform `POST /auth/login` and enter session mode. */
function usePasswordLogin(redirect?: string) {
  const router = useRouter()
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function signIn(username: string, password: string): Promise<void> {
    setSubmitting(true)
    setError(null)
    try {
      const session = await login({ username, password })
      // The cookie is now set; persist the CSRF token (session mode) and let
      // the shell re-fetch the identity.
      setSession(session.csrf_token)
      queryClient.removeQueries({ queryKey: meKeys.self() })
      void router.navigate({ to: redirect ?? '/' })
    } catch (err) {
      setError(
        err instanceof ApiError && err.isAuthError
          ? 'Invalid username or password'
          : 'Could not sign in. Is the server reachable?',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return { signIn, error, setError, submitting, setSubmitting }
}

/**
 * Identifier-first (UX A): step 1 = username -> `POST /auth/identify`; the
 * realm decision either reveals the password field (step 2, username shown
 * with a back link) or navigates the browser to the IdP.
 */
function IdentifierFirstLogin({ redirect }: { redirect?: string }) {
  const [step, setStep] = useState<'identify' | 'password'>('identify')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const { signIn, error, setError, submitting, setSubmitting } =
    usePasswordLogin(redirect)

  async function onIdentify(e: React.FormEvent) {
    e.preventDefault()
    const trimmed = username.trim()
    if (!trimmed) {
      setError('Enter your username.')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const decision = await identify(trimmed)
      if (decision.mode === 'oidc_redirect' && decision.login_url) {
        assignLocation(oidcUrl(decision.login_url, redirect))
        return // the browser is leaving; keep "submitting" until it does
      }
      setStep('password')
    } catch {
      setError('Could not sign in. Is the server reachable?')
    } finally {
      setSubmitting(false)
    }
  }

  function onPassword(e: React.FormEvent) {
    e.preventDefault()
    if (!password) {
      setError('Enter your password.')
      return
    }
    void signIn(username.trim(), password)
  }

  if (step === 'identify') {
    return (
      <form onSubmit={onIdentify} className="space-y-4">
        <div>
          <label
            htmlFor="login-username"
            className="block text-sm font-medium text-slate-700"
          >
            Username
          </label>
          <input
            id="login-username"
            type="text"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className={inputClass}
          />
        </div>
        {error && (
          <p role="alert" className="text-sm text-red-600">
            {error}
          </p>
        )}
        <button type="submit" disabled={submitting} className={primaryButtonClass}>
          {submitting ? 'Checking…' : 'Continue'}
        </button>
      </form>
    )
  }

  return (
    <form onSubmit={onPassword} className="space-y-4">
      <p className="text-sm text-slate-600">
        Signing in as <span className="font-medium">{username.trim()}</span>{' '}
        <button
          type="button"
          onClick={() => {
            setStep('identify')
            setPassword('')
            setError(null)
          }}
          className="text-sky-700 hover:underline"
        >
          Change
        </button>
      </p>
      <div>
        <label
          htmlFor="login-password"
          className="block text-sm font-medium text-slate-700"
        >
          Password
        </label>
        <input
          id="login-password"
          type="password"
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className={inputClass}
        />
      </div>
      {error && (
        <p role="alert" className="text-sm text-red-600">
          {error}
        </p>
      )}
      <button type="submit" disabled={submitting} className={primaryButtonClass}>
        {submitting ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  )
}

/**
 * Combined (UX B): username+password always shown (when a password realm is
 * enabled) plus one button per OIDC entry. No identify step.
 */
function CombinedLogin({
  options,
  redirect,
}: {
  options: LoginOptions
  redirect?: string
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const { signIn, error, setError, submitting } = usePasswordLogin(redirect)

  function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!username.trim() || !password) {
      setError('Enter your username and password.')
      return
    }
    void signIn(username.trim(), password)
  }

  return (
    <div className="space-y-4">
      {options.password && (
        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="login-username"
              className="block text-sm font-medium text-slate-700"
            >
              Username
            </label>
            <input
              id="login-username"
              type="text"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className={inputClass}
            />
          </div>
          <div>
            <label
              htmlFor="login-password"
              className="block text-sm font-medium text-slate-700"
            >
              Password
            </label>
            <input
              id="login-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={inputClass}
            />
          </div>
          {error && (
            <p role="alert" className="text-sm text-red-600">
              {error}
            </p>
          )}
          <button type="submit" disabled={submitting} className={primaryButtonClass}>
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      )}

      {options.oidc.map((idp) => (
        <OidcButton key={idp.name} idp={idp} redirect={redirect} />
      ))}
    </div>
  )
}

function OidcButton({
  idp,
  redirect,
}: {
  idp: OidcLoginOption
  redirect?: string
}) {
  return (
    <button
      type="button"
      onClick={() => assignLocation(oidcUrl(idp.login_url, redirect))}
      className="w-full rounded border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100"
    >
      Login with {idp.label}
    </button>
  )
}

/**
 * The slice-1 token-paste form (secondary option): the token is verified via
 * `GET /admin/me` and only persisted once the API accepts it, so an invalid
 * token never poisons the stored credential.
 */
function TokenLoginForm({ redirect }: { redirect?: string }) {
  const router = useRouter()
  const queryClient = useQueryClient()
  const [token, setTokenValue] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    const trimmed = token.trim()
    if (!trimmed) {
      setError('Enter a registry token.')
      return
    }
    setSubmitting(true)
    setError(null)
    // Store first so the verification request carries the credential, then roll
    // back if the API rejects it.
    setToken(trimmed)
    try {
      const me = await fetchMe()
      queryClient.setQueryData(meKeys.self(), me)
      void router.navigate({ to: redirect ?? '/' })
    } catch (err) {
      clearToken()
      queryClient.removeQueries({ queryKey: meKeys.self() })
      setError(
        err instanceof ApiError && err.isAuthError
          ? 'That token was not accepted. Check it and try again.'
          : 'Could not verify the token. Is the server reachable?',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div>
        <label
          htmlFor="forge-token"
          className="block text-sm font-medium text-slate-700"
        >
          Registry token
        </label>
        <input
          id="forge-token"
          type="password"
          autoComplete="off"
          autoFocus
          value={token}
          onChange={(e) => setTokenValue(e.target.value)}
          placeholder="Paste your token"
          className={inputClass}
        />
        <p className="mt-1 text-xs text-slate-500">
          Create a token from the Tokens screen, or use one provided out of band.
        </p>
      </div>

      {error && (
        <p role="alert" className="text-sm text-red-600">
          {error}
        </p>
      )}

      <button type="submit" disabled={submitting} className={primaryButtonClass}>
        {submitting ? 'Verifying…' : 'Sign in'}
      </button>
    </form>
  )
}

const inputClass =
  'mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500'

const primaryButtonClass =
  'w-full rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-60'
