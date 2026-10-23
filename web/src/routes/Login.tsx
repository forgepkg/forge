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
import { Button, Code, Icon, Logo, Notice, Skeleton, TextField } from '~/components/ui'

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
  /**
   * With `username_not_upn`: the realm claim the username came from. Shown
   * only when it looks like a claim name (the URL is anyone's to craft).
   */
  claim?: string
}

/**
 * Why an OIDC sign-in ended back here (`/login?error=...`): `oidc_failed`
 * when the callback did not validate (or the IdP returned an error),
 * `not_permitted` when the account may not sign in, `username_not_upn` when
 * a new account would be named by a claim that does not hold a UPN. Any
 * other value is `other`; the raw parameter is never shown.
 */
type LoginError = 'oidc_failed' | 'not_permitted' | 'username_not_upn' | 'other'

/** Generic on purpose: IdP details stay in the server log. */
const loginErrorMessages: Record<LoginError, string> = {
  oidc_failed:
    'Sign-in with your identity provider did not complete. Try again; if it keeps failing, ask your administrator.',
  not_permitted:
    'Your account is not permitted to sign in to Forge. Ask your administrator for access.',
  username_not_upn:
    'Forge names new accounts by a UPN such as alice@example.com, and your identity provider did not send one. Ask your administrator to map a claim that holds it.',
  other:
    'Sign-in did not complete. Try again; if it keeps failing, ask your administrator.',
}

function parseLoginError(raw: unknown): LoginError | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined
  return raw === 'oidc_failed' ||
    raw === 'not_permitted' ||
    raw === 'username_not_upn'
    ? raw
    : 'other'
}

/** A claim name worth showing: short, and nothing but name characters. */
function parseClaim(raw: unknown): string | undefined {
  return typeof raw === 'string' && /^[A-Za-z0-9_.:/-]{1,64}$/.test(raw)
    ? raw
    : undefined
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
    claim: parseClaim(search.claim),
  }),
})

/**
 * Sign-in screen. On load it fetches `GET /auth/login-options` and renders one
 * of two layouts:
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
  const { redirect, expired, logout_failed, error, claim } = useSearch({
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
    <div className="flex min-h-dvh flex-col items-center gap-7 bg-ground px-4 pt-16 pb-8 text-ink">
      <Logo size={34} />
      <main className="flex w-full max-w-[400px] flex-col gap-6 rounded-lg border border-line bg-surface p-8 shadow-lg max-sm:p-6">
        <div className="flex flex-col gap-1">
          <h1 className="m-0 text-2xl leading-8 font-semibold tracking-[-0.01em]">
            Sign in to Forge
          </h1>
          <p className="fg-text">
            {loginOptions?.mode === 'combined'
              ? 'Use your username and password, or your organization’s sign-in.'
              : 'Enter your username to continue.'}
          </p>
        </div>

        {error && (
          <Notice
            tone="danger"
            action={
              <Link to="/login" search={{ redirect }} className="fg-notice-action">
                Try again
              </Link>
            }
          >
            <p>{loginErrorMessages[error]}</p>
            {error === 'username_not_upn' && claim && (
              <p>
                The username came from the <Code>{claim}</Code> claim.
              </p>
            )}
          </Notice>
        )}

        {expired && (
          <Notice tone="warn">Your session expired. Sign in again to continue.</Notice>
        )}

        {logout_failed && (
          <Notice tone="danger">
            Sign-out could not be confirmed by the server, so your session may
            still be active. Sign in and sign out again, or close the browser.
          </Notice>
        )}

        {options.isError && (
          <Notice tone="warn" role="status">
            Sign-in options could not be loaded. Password sign-in is available.
          </Notice>
        )}

        {!loginOptions ? (
          <Skeleton lines={2} label="Loading sign-in options…" />
        ) : loginOptions.mode === 'combined' ? (
          <CombinedLogin options={loginOptions} redirect={redirect} />
        ) : (
          <IdentifierFirstLogin redirect={redirect} />
        )}

        {loginOptions?.mode !== 'combined' && (
          <p className="fg-text fg-text--small border-t border-line pt-4">
            Forge checks which sign-in your account uses. With your
            organization’s single sign-on you continue at its sign-in page;
            otherwise Forge asks for your password next.
          </p>
        )}
      </main>
      <p className="fg-text fg-text--small">{window.location.host}</p>
    </div>
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
    <p role="alert" className="fg-field-error">
      <Icon name="Alert" size={14} />
      <span>{children}</span>
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
      <form onSubmit={onIdentify} className="flex flex-col gap-4">
        <TextField
          label="Username"
          type="text"
          autoComplete="username"
          autoFocus
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        {error && <FormError>{error}</FormError>}
        <Button type="submit" variant="primary" block disabled={submitting}>
          {submitting ? 'Checking…' : 'Continue'}
        </Button>
      </form>
    )
  }

  return (
    <form onSubmit={onPassword} className="flex flex-col gap-4">
      <p className="fg-text">
        Signing in as <span className="fg-strong">{username.trim()}</span>{' '}
        <button
          type="button"
          onClick={() => {
            setStep('identify')
            setPassword('')
            setError(null)
          }}
          className="fg-link cursor-pointer border-0 bg-transparent p-0"
        >
          Change
        </button>
      </p>
      <TextField
        label="Password"
        type="password"
        autoComplete="current-password"
        autoFocus
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      {error && <FormError>{error}</FormError>}
      <Button type="submit" variant="primary" block disabled={submitting}>
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
    <div className="flex flex-col gap-4">
      {options.password && (
        <form onSubmit={onSubmit} className="flex flex-col gap-4">
          <TextField
            label="Username"
            type="text"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <TextField
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {error && <FormError>{error}</FormError>}
          <Button type="submit" variant="primary" block disabled={submitting}>
            {submitting ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>
      )}

      {options.password && options.oidc.length > 0 && (
        <div className="flex items-center gap-3 text-xs text-ink-faint" aria-hidden="true">
          <span className="h-px flex-1 bg-line" />
          or
          <span className="h-px flex-1 bg-line" />
        </div>
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
      block
      icon="Shield"
      onClick={() => assignLocation(oidcUrl(idp.login_url, redirect))}
    >
      Login with {idp.label}
    </Button>
  )
}
