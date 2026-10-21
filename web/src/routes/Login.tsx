import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  createFileRoute,
  Link,
  useRouter,
  useSearch,
} from '@tanstack/react-router'

import {
  fetchLoginOptions,
  identify,
  login,
  authKeys,
  type LoginOptions,
  type OidcLoginOption,
} from '~/api/auth'
import { ApiError } from '~/lib/httpClient'
import { setSession } from '~/lib/auth'
import { assignLocation } from '~/lib/navigation'
import { safeReturnTo } from '~/lib/returnTo'
import { AuthLayout } from '~/components/catalyst/auth-layout'
import { Button } from '~/components/catalyst/button'
import { Field, Label } from '~/components/catalyst/fieldset'
import { Heading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
import { Text } from '~/components/catalyst/text'

interface LoginSearch {
  /**
   * Where to return after a successful sign-in (set by the route guards and
   * the expired-session handler). Untrusted: always passed through
   * `safeReturnTo` before use.
   */
  redirect?: string
  /** Set when the session expired mid-use (the guard / a 401 redirected here). */
  expired?: boolean
  /** Set when sign-out could not be confirmed by the server. */
  logout_failed?: boolean
  /** Set when the server's OIDC callback sent the browser back here. */
  error?: LoginError
}

/**
 * Why an OIDC sign-in ended back here (`/login?error=...`): `oidc_failed`
 * when the callback did not validate (or the IdP returned an error),
 * `not_permitted` when the account may not sign in. Any other value is
 * `other`; the raw parameter is never shown.
 */
type LoginError = 'oidc_failed' | 'not_permitted' | 'other'

/** Generic on purpose: IdP details stay in the server log. */
const loginErrorMessages: Record<LoginError, string> = {
  oidc_failed:
    'Sign-in with your identity provider did not complete. Try again; if it keeps failing, ask your administrator.',
  not_permitted:
    'Your account is not permitted to sign in to Forge. Ask your administrator for access.',
  other:
    'Sign-in did not complete. Try again; if it keeps failing, ask your administrator.',
}

function parseLoginError(raw: unknown): LoginError | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined
  return raw === 'oidc_failed' || raw === 'not_permitted' ? raw : 'other'
}

const passwordFallbackOptions: LoginOptions = {
  mode: 'combined',
  password: true,
  oidc: [],
}

export const Route = createFileRoute('/login')({
  component: Login,
  validateSearch: (search: Record<string, unknown>): LoginSearch => ({
    redirect: typeof search.redirect === 'string' ? search.redirect : undefined,
    expired: search.expired === true || search.expired === 'true',
    logout_failed:
      search.logout_failed === true || search.logout_failed === 'true',
    error: parseLoginError(search.error),
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
 * A failed OIDC callback lands here with `?error=<code>`: a short, generic
 * message is shown above the form with a "Try again" link that clears it.
 * Signing in with a registry token is intentionally not offered: the UI always
 * authenticates with username+password or via a realm. Tokens are minted on
 * the Tokens screen for NuGet clients only.
 */
function Login() {
  const { redirect, expired, logout_failed, error } = useSearch({
    from: '/login',
  })
  const options = useQuery<LoginOptions, ApiError>({
    queryKey: authKeys.loginOptions(),
    queryFn: ({ signal }) => fetchLoginOptions(signal),
    staleTime: 60_000,
    // Fail fast; the page falls back to direct password sign-in.
    retry: false,
  })
  const loginOptions =
    options.data ?? (options.isError ? passwordFallbackOptions : undefined)

  return (
    <AuthLayout>
      <div className="w-full max-w-sm space-y-8">
        <div className="space-y-2 text-center">
          <span
            aria-hidden="true"
            className="mx-auto grid size-12 place-items-center rounded-xl bg-gradient-to-br from-sky-500 to-indigo-600 text-lg font-bold text-white shadow-lg shadow-sky-500/20"
          >
            ef
          </span>
          <Heading className="!text-2xl">envisia&nbsp;forge</Heading>
          <Text>Sign in to the package registry</Text>
        </div>

        {error && (
          <div
            role="alert"
            className="space-y-1 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm/6 text-red-700 dark:text-red-400"
          >
            <p>{loginErrorMessages[error]}</p>
            <Link
              to="/login"
              search={{ redirect }}
              className="font-medium underline hover:no-underline"
            >
              Try again
            </Link>
          </div>
        )}

        {expired && (
          <p
            role="alert"
            className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm/6 text-amber-700 dark:text-amber-400"
          >
            Your session expired. Sign in again to continue.
          </p>
        )}

        {logout_failed && (
          <p
            role="alert"
            className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm/6 text-red-700 dark:text-red-400"
          >
            Sign-out could not be confirmed by the server, so your session may
            still be active. Sign in and sign out again, or close the browser.
          </p>
        )}

        {options.isError && (
          <p
            role="status"
            className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm/6 text-amber-700 dark:text-amber-400"
          >
            Sign-in options could not be loaded. Password sign-in is available.
          </p>
        )}

        {!loginOptions ? (
          <Text>Loading sign-in options…</Text>
        ) : loginOptions.mode === 'combined' ? (
          <CombinedLogin options={loginOptions} redirect={redirect} />
        ) : (
          <IdentifierFirstLogin redirect={redirect} />
        )}
      </div>
    </AuthLayout>
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
  return `${loginUrl}${sep}redirect_to=${encodeURIComponent(safeReturnTo(redirect))}`
}

/**
 * The inline message for a failed sign-in step. A 429 is the login lockout
 * (too many recent failures for this username from this address), which is
 * neither a wrong password nor an unreachable server.
 */
function signInErrorMessage(err: unknown): string {
  if (err instanceof ApiError && err.status === 429) {
    const wait = err.retryAfterSeconds
    const when =
      wait === undefined
        ? 'in a few minutes'
        : wait < 60
          ? `in ${wait} second${wait === 1 ? '' : 's'}`
          : `in ${Math.ceil(wait / 60)} minute${Math.ceil(wait / 60) === 1 ? '' : 's'}`
    return `Too many failed sign-in attempts. Sign-in is temporarily locked; try again ${when}.`
  }
  if (err instanceof ApiError && err.isAuthError) {
    return 'Invalid username or password'
  }
  return 'Could not sign in. Is the server reachable?'
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
      // The cookie is now set. Drop every cached query before entering the
      // app — none of it may belong to whoever used this browser before —
      // then persist the CSRF token (session mode); the shell fetches the
      // identity fresh.
      queryClient.clear()
      setSession(session.csrf_token)
      // Stay "submitting" while the app loads; this screen is leaving (the
      // reset below only matters if a guard sends us back here).
      await router.navigate({ href: safeReturnTo(redirect) })
      setSubmitting(false)
    } catch (err) {
      setError(signInErrorMessage(err))
      setSubmitting(false)
    }
  }

  return { signIn, error, setError, submitting, setSubmitting }
}

/** Inline form error, kept as `role="alert"` for tests + screen readers. */
function FormError({ children }: { children: React.ReactNode }) {
  return (
    <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
      {children}
    </p>
  )
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
        // The browser is leaving: keep "submitting" (and Continue disabled)
        // until it does, so a second click cannot start another flow.
        return
      }
      setStep('password')
      setSubmitting(false)
    } catch (err) {
      setError(signInErrorMessage(err))
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
      <form onSubmit={onIdentify} className="space-y-6">
        <Field>
          <Label>Username</Label>
          <Input
            type="text"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </Field>
        {error && <FormError>{error}</FormError>}
        <Button type="submit" disabled={submitting} className="w-full">
          {submitting ? 'Checking…' : 'Continue'}
        </Button>
      </form>
    )
  }

  return (
    <form onSubmit={onPassword} className="space-y-6">
      <Text>
        Signing in as <span className="font-medium">{username.trim()}</span>{' '}
        <button
          type="button"
          onClick={() => {
            setStep('identify')
            setPassword('')
            setError(null)
          }}
          className="text-sky-600 hover:underline dark:text-sky-400"
        >
          Change
        </button>
      </Text>
      <Field>
        <Label>Password</Label>
        <Input
          type="password"
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </Field>
      {error && <FormError>{error}</FormError>}
      <Button type="submit" disabled={submitting} className="w-full">
        {submitting ? 'Signing in…' : 'Sign in'}
      </Button>
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
    <div className="space-y-6">
      {options.password && (
        <form onSubmit={onSubmit} className="space-y-6">
          <Field>
            <Label>Username</Label>
            <Input
              type="text"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </Field>
          <Field>
            <Label>Password</Label>
            <Input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
          {error && <FormError>{error}</FormError>}
          <Button type="submit" disabled={submitting} className="w-full">
            {submitting ? 'Signing in…' : 'Sign in'}
          </Button>
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
    <Button
      outline
      className="w-full"
      onClick={() => assignLocation(oidcUrl(idp.login_url, redirect))}
    >
      Login with {idp.label}
    </Button>
  )
}
