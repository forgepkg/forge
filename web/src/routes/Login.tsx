import { useEffect, useState } from 'react'
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
import {
  beginOidcSignIn,
  clearPendingSignIn,
  forgetAccount,
  forgetAllAccounts,
  listAccounts,
  rememberAccount,
  type RememberedAccount,
} from '~/lib/accounts'
import { setSession } from '~/lib/auth'
import { assignLocation } from '~/lib/navigation'
import { safeReturnTo } from '~/lib/returnTo'
import { searchFlag } from '~/lib/search'
import { AuthCard } from '~/components/AuthCard'
import {
  Avatar,
  Button,
  Code,
  Icon,
  Notice,
  Skeleton,
  StatusBadge,
  TextField,
} from '~/components/ui'

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
  /** A username to start with: an invited user who just chose a password. */
  username?: string
  /** Set when the user just chose their password from an invitation. */
  invited?: boolean
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

/**
 * The login options while `GET /auth/login-options` cannot be read: the
 * username and password form alone. (Not named after the password: static
 * analysis takes such a name for a credential, and the realm names read from
 * these options reach storage as a pending OIDC sign-in.)
 */
const fallbackLoginOptions: LoginOptions = {
  mode: 'combined',
  password: true,
  oidc: [],
  // Unknown while the options cannot be read: the remembered accounts are
  // neither offered nor forgotten.
  remember_accounts: false,
}

/**
 * The account a remembered-account tile continues with in the mode's form:
 * its identifier, and the password realm `/auth/identify` routed it to.
 */
interface PickedAccount {
  identifier: string
  realm?: string
}

export const Route = createFileRoute('/login')({
  component: Login,
  validateSearch: (search: Record<string, unknown>): LoginSearch => ({
    redirect: typeof search.redirect === 'string' ? search.redirect : undefined,
    expired: searchFlag(search.expired),
    logout_failed: searchFlag(search.logout_failed),
    error: parseLoginError(search.error),
    claim: parseClaim(search.claim),
    username:
      typeof search.username === 'string' && search.username.length <= 256
        ? search.username
        : undefined,
    invited: searchFlag(search.invited),
  }),
})

/**
 * Sign-in screen. On load it fetches `GET /auth/login-options`. When it
 * remembers accounts (`remember_accounts`) and this device signed some in
 * before (`~/lib/accounts`), it first offers them as tiles: one click
 * continues as that account (the password step, or the identity provider
 * with the account as `login_hint`), "Use another account" shows the form.
 * The form is one of two layouts:
 *
 *  - **identifier-first** (default): step 1 asks only for the username and
 *    calls `POST /auth/identify`; depending on the realm decision step 2 shows
 *    a password field (`POST /auth/login`) or the browser is sent to the OIDC
 *    authorize URL.
 *  - **combined**: username+password always shown, plus one button per
 *    enabled OIDC realm.
 *
 * A successful password login sets the `forge_session` cookie; we persist the
 * returned CSRF token (session mode), remember the account, and navigate to
 * the `redirect` target. An OIDC sign-in is remembered once the session it
 * opens reaches the app (`completePendingSignIn`).
 * A failed OIDC callback lands here with `?error=<code>`: a short, generic
 * message is shown above the form with a "Try again" link that clears it.
 * Signing in with a registry token is intentionally not offered: the UI always
 * authenticates with username+password or via a realm. Tokens are minted on
 * the Tokens screen for NuGet clients only.
 */
function Login() {
  const { redirect, expired, logout_failed, error, claim, username, invited } = useSearch({
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
    options.data ?? (options.isError ? fallbackLoginOptions : undefined)
  const remember = loginOptions?.remember_accounts === true
  const [accounts, setAccounts] = useState(listAccounts)
  const [picked, setPicked] = useState<PickedAccount | null>(null)
  const [another, setAnother] = useState(false)
  // An invited user's username starts the form; otherwise the remembered
  // accounts come first, until one is picked or "Use another account".
  const canPick = remember && accounts.length > 0 && !username
  const showPicker = canPick && !another && picked === null

  // Back here, an OIDC sign-in this tab started did not open a session (it
  // failed, or the user came back): it must not be remembered later.
  useEffect(() => clearPendingSignIn(), [])

  // Remembering turned off by an administrator (a kiosk, a shared
  // terminal): keep no account on this device.
  const rememberOff = options.data?.remember_accounts === false
  useEffect(() => {
    if (rememberOff) forgetAllAccounts()
  }, [rememberOff])

  function forget(identifier: string) {
    forgetAccount(identifier)
    setAccounts(listAccounts())
  }

  return (
    <AuthCard
      title="Sign in to Forge"
      subtitle={
        showPicker
          ? 'Pick an account to continue.'
          : loginOptions?.mode === 'combined'
            ? 'Use your username and password, or your organization’s sign-in.'
            : 'Enter your username to continue.'
      }
    >
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

      {invited && <Notice tone="ok">Your password is set. Sign in with it.</Notice>}

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
      ) : showPicker ? (
        <AccountPicker
          accounts={accounts}
          options={loginOptions}
          redirect={redirect}
          onPassword={setPicked}
          onForget={forget}
          onAnother={() => setAnother(true)}
        />
      ) : loginOptions.mode === 'combined' ? (
        <CombinedLogin
          key={picked?.identifier}
          options={loginOptions}
          redirect={redirect}
          remember={remember}
          initialUsername={picked?.identifier ?? username}
          focusPassword={picked !== null}
        />
      ) : (
        <IdentifierFirstLogin
          key={picked?.identifier}
          redirect={redirect}
          remember={remember}
          initialUsername={picked?.identifier ?? username}
          initialRealm={picked?.realm}
        />
      )}

      {canPick && !showPicker && (
        <button
          type="button"
          onClick={() => {
            setPicked(null)
            setAnother(false)
          }}
          className="fg-link cursor-pointer self-start border-0 bg-transparent p-0"
        >
          Back to your accounts
        </button>
      )}

      {loginOptions?.mode !== 'combined' && !showPicker && (
        <p className="fg-text fg-text--small border-t border-line pt-4">
          Forge checks which sign-in your account uses. With your
          organization’s single sign-on you continue at its sign-in page;
          otherwise Forge asks for your password next.
        </p>
      )}
    </AuthCard>
  )
}

/**
 * Append the post-login destination to an OIDC login URL so the server can
 * send the browser back after the IdP round-trip
 * (`/auth/oidc/login?redirect_to=...`), and the account the user means as
 * `login_hint`, which the server passes to the IdP so it does not ask for the
 * account again.
 */
function oidcUrl(loginUrl: string, redirect?: string, loginHint?: string): string {
  const params: string[] = []
  if (redirect) params.push(`redirect_to=${encodeURIComponent(safeReturnTo(redirect))}`)
  if (loginHint) params.push(`login_hint=${encodeURIComponent(loginHint)}`)
  if (params.length === 0) return loginUrl
  const sep = loginUrl.includes('?') ? '&' : '?'
  return `${loginUrl}${sep}${params.join('&')}`
}

/**
 * Leave for the identity provider of `realm`. When the screen remembers
 * accounts, the session the round trip opens is remembered as this realm's
 * (`beginOidcSignIn`).
 */
function startOidcSignIn(
  loginUrl: string,
  realm: string,
  { redirect, loginHint, remember }: { redirect?: string; loginHint?: string; remember: boolean },
): void {
  if (remember) beginOidcSignIn(realm)
  else clearPendingSignIn()
  assignLocation(oidcUrl(loginUrl, redirect, loginHint))
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

/**
 * Shared hook: perform `POST /auth/login` and enter session mode. With
 * `remember`, the account is remembered on this device for the next sign-in
 * (with `realm`, the password realm `/auth/identify` named, when known).
 */
function usePasswordLogin(redirect: string | undefined, remember: boolean) {
  const router = useRouter()
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function signIn(username: string, password: string, realm?: string): Promise<void> {
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
      // This sign-in replaces any OIDC one this tab left unfinished.
      clearPendingSignIn()
      if (remember) {
        rememberAccount({
          identifier: username,
          display_name: session.display_name ?? undefined,
          method: 'password',
          realm,
        })
      }
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
 * with a back link) or navigates the browser to the IdP, with the username
 * as its login hint. With `initialRealm` (a remembered account `identify`
 * already routed to a password realm) it starts at step 2.
 */
function IdentifierFirstLogin({
  redirect,
  remember,
  initialUsername,
  initialRealm,
}: {
  redirect?: string
  remember: boolean
  initialUsername?: string
  initialRealm?: string
}) {
  const [step, setStep] = useState<'identify' | 'password'>(
    initialRealm !== undefined ? 'password' : 'identify',
  )
  const [username, setUsername] = useState(initialUsername ?? '')
  const [realm, setRealm] = useState(initialRealm)
  const [password, setPassword] = useState('')
  const { signIn, error, setError, submitting, setSubmitting } =
    usePasswordLogin(redirect, remember)

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
        startOidcSignIn(decision.login_url, decision.realm, {
          redirect,
          loginHint: trimmed,
          remember,
        })
        // The browser is leaving: keep "submitting" (and Continue disabled)
        // until it does, so a second click cannot start another flow.
        return
      }
      setRealm(decision.realm)
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
    void signIn(username.trim(), password, realm)
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
 * enabled) plus one button per OIDC entry. No identify step. A remembered
 * account picked for it fills the username and puts the cursor in the
 * password (`focusPassword`).
 */
function CombinedLogin({
  options,
  redirect,
  remember,
  initialUsername,
  focusPassword = false,
}: {
  options: LoginOptions
  redirect?: string
  remember: boolean
  initialUsername?: string
  focusPassword?: boolean
}) {
  const [username, setUsername] = useState(initialUsername ?? '')
  const [password, setPassword] = useState('')
  const { signIn, error, setError, submitting } = usePasswordLogin(redirect, remember)

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
            autoFocus={!focusPassword}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <TextField
            label="Password"
            type="password"
            autoComplete="current-password"
            autoFocus={focusPassword}
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
        <OidcButton key={idp.name} idp={idp} redirect={redirect} remember={remember} />
      ))}
    </div>
  )
}

function OidcButton({
  idp,
  redirect,
  remember,
}: {
  idp: OidcLoginOption
  redirect?: string
  remember: boolean
}) {
  return (
    <Button
      block
      icon="Shield"
      onClick={() => startOidcSignIn(idp.login_url, idp.name, { redirect, remember })}
    >
      Login with {idp.label}
    </Button>
  )
}

/**
 * The remembered accounts, newest first, as tiles (like Microsoft's "Pick an
 * account"). A tile continues as its account:
 *
 *  - an OIDC account whose realm the login options still offer goes straight
 *    to that realm's identity provider, the identifier as `login_hint`;
 *  - a password account goes to the password step (`onPassword`): in
 *    combined mode the form with the username filled in, in identifier-first
 *    mode once `/auth/identify` confirms the identifier still signs in with a
 *    password (a domain an OIDC realm took over since goes to its identity
 *    provider instead, as does every account once no password realm is
 *    left);
 *  - an OIDC account whose realm is gone or disabled is routed by
 *    `/auth/identify`, like the identifier typed into the form, so it never
 *    loops back to a realm that is not offered.
 *
 * Each tile's ✕ forgets its account; "Use another account" shows the form.
 */
function AccountPicker({
  accounts,
  options,
  redirect,
  onPassword,
  onForget,
  onAnother,
}: {
  accounts: RememberedAccount[]
  options: LoginOptions
  redirect?: string
  onPassword: (account: PickedAccount) => void
  onForget: (identifier: string) => void
  onAnother: () => void
}) {
  // The identifier being continued with, while its request runs or the
  // browser leaves for the identity provider.
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function pick(account: RememberedAccount) {
    const loginHint = account.identifier
    setError(null)
    setBusy(account.identifier)
    if (account.method === 'oidc') {
      const idp = options.oidc.find((o) => o.name === account.realm)
      if (idp) {
        // The browser is leaving: stay busy until it does.
        startOidcSignIn(idp.login_url, idp.name, { redirect, loginHint, remember: true })
        return
      }
    } else if (options.mode === 'combined' && options.password) {
      onPassword({ identifier: account.identifier })
      return
    }
    try {
      const decision = await identify(account.identifier)
      if (decision.mode === 'oidc_redirect' && decision.login_url) {
        startOidcSignIn(decision.login_url, decision.realm, {
          redirect,
          loginHint,
          remember: true,
        })
        return
      }
      onPassword({ identifier: account.identifier, realm: decision.realm })
    } catch (err) {
      setError(signInErrorMessage(err))
      setBusy(null)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <ul className="fg-accounts" aria-label="Remembered accounts">
        {accounts.map((account) => {
          const name = account.display_name ?? account.identifier
          return (
            <li key={account.identifier} className="fg-account">
              <button
                type="button"
                className="fg-account-pick"
                disabled={busy !== null}
                onClick={() => void pick(account)}
              >
                <Avatar name={name} size={32} decorative />
                <span className="fg-account-who">
                  <span className="fg-account-name">{name}</span>
                  {account.display_name && (
                    <span className="fg-account-id">{account.identifier}</span>
                  )}
                </span>
                {busy === account.identifier ? (
                  <span className="fg-text fg-text--small">Continuing…</span>
                ) : (
                  <StatusBadge icon={account.method === 'oidc' ? 'Shield' : 'Lock'}>
                    {account.method === 'oidc' ? 'SSO' : 'password'}
                  </StatusBadge>
                )}
              </button>
              <Button
                variant="ghost"
                size="sm"
                icon="X"
                iconOnly
                disabled={busy !== null}
                onClick={() => onForget(account.identifier)}
              >
                {`Forget ${account.identifier}`}
              </Button>
            </li>
          )
        })}
      </ul>
      {error && <FormError>{error}</FormError>}
      <Button block icon="Plus" disabled={busy !== null} onClick={onAnother}>
        Use another account
      </Button>
    </div>
  )
}
