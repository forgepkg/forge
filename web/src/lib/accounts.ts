/**
 * Remembered accounts: the accounts signed in on this device, which the login
 * screen offers as a picker (like Microsoft's "Pick an account") so the next
 * sign-in is one click.
 *
 * Kept in localStorage under `forge.accounts`, newest first, at most
 * {@link MAX_ACCOUNTS}. An entry holds what the picker shows and how to
 * continue: the identifier, the identity provider's display name, the sign-in
 * method with its realm, and when it was last used. **Never** a password, a
 * token, the session or anything else that works as a credential: an entry
 * only saves typing the identifier again. The server never lists accounts,
 * so `POST /auth/identify` still answers from public realm configuration
 * alone.
 *
 * Every access is wrapped: with storage blocked (a private window, a policy)
 * the list reads as empty and nothing is kept, so the picker is simply not
 * shown. A stored value that is not a list of entries reads as empty too.
 *
 * An OIDC sign-in ends with a server redirect, so the login screen cannot
 * record its entry: it leaves a pending sign-in in sessionStorage (this tab
 * only, {@link beginOidcSignIn}), and the first `GET /auth/me` after the
 * round trip turns it into an entry ({@link completePendingSignIn}).
 */

const ACCOUNTS_KEY = 'forge.accounts'
const PENDING_KEY = 'forge.accounts.pending'

/** The most accounts kept; signing in with a sixth drops the oldest. */
export const MAX_ACCOUNTS = 5

/** Longest identifier, display name or realm name kept. */
const MAX_FIELD_CHARS = 256

/**
 * A pending OIDC sign-in older than this is dropped: the server's flow ends
 * after 10 minutes, so a later session was not opened by it.
 */
const PENDING_TTL_MS = 10 * 60 * 1000

/** How a remembered account signs in. */
export type AccountMethod = 'password' | 'oidc'

/** One remembered account. */
export interface RememberedAccount {
  /** What the user signs in with: the username (usually an email address). */
  identifier: string
  /** The name the identity provider gave for the user, when it gave one. */
  display_name?: string
  method: AccountMethod
  /** The realm that signed the account in, when the screen learned it. */
  realm?: string
  /** When the account last signed in (epoch milliseconds). */
  last_used: number
}

/** An OIDC sign-in this tab started (sessionStorage). */
interface PendingSignIn {
  realm: string
  started: number
}

/**
 * The key two identifiers of one account share: Forge keeps usernames
 * trimmed, NFC-normalised and lowercased, so `Alice@Corp.com` and
 * `alice@corp.com` are one account.
 */
function accountKey(identifier: string): string {
  return identifier.trim().normalize('NFC').toLowerCase()
}

function boundedString(v: unknown): v is string {
  return typeof v === 'string' && v.trim() !== '' && v.length <= MAX_FIELD_CHARS
}

/** `raw` as an entry, or null when it is not one (tampered, another version). */
function parseAccount(raw: unknown): RememberedAccount | null {
  if (typeof raw !== 'object' || raw === null) return null
  const r = raw as Record<string, unknown>
  if (!boundedString(r.identifier)) return null
  if (r.method !== 'password' && r.method !== 'oidc') return null
  if (typeof r.last_used !== 'number' || !Number.isFinite(r.last_used)) return null
  const account: RememberedAccount = {
    identifier: r.identifier.trim(),
    method: r.method,
    last_used: r.last_used,
  }
  if (boundedString(r.display_name)) account.display_name = r.display_name.trim()
  if (boundedString(r.realm)) account.realm = r.realm
  return account
}

/** The remembered accounts, newest first (empty when storage is unavailable). */
export function listAccounts(): RememberedAccount[] {
  let raw: string | null
  try {
    raw = localStorage.getItem(ACCOUNTS_KEY)
  } catch {
    return []
  }
  if (!raw) return []
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return []
  }
  if (!Array.isArray(parsed)) return []
  const seen = new Set<string>()
  return parsed
    .map(parseAccount)
    .filter((a): a is RememberedAccount => a !== null)
    .sort((a, b) => b.last_used - a.last_used)
    .filter((a) => {
      const key = accountKey(a.identifier)
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
    .slice(0, MAX_ACCOUNTS)
}

function store(accounts: RememberedAccount[]): void {
  try {
    if (accounts.length === 0) localStorage.removeItem(ACCOUNTS_KEY)
    else localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts))
  } catch {
    /* storage unavailable: nothing is remembered */
  }
}

/**
 * Remember a sign-in: the account moves to the front with `now` as its last
 * use, replacing its earlier entry (same identifier, any case). The oldest
 * accounts beyond {@link MAX_ACCOUNTS} are dropped. A value too long to keep
 * is not remembered.
 */
export function rememberAccount(
  account: Omit<RememberedAccount, 'last_used'>,
  now: number = Date.now(),
): void {
  const entry = parseAccount({ ...account, last_used: now })
  if (!entry) return
  const key = accountKey(entry.identifier)
  const others = listAccounts().filter((a) => accountKey(a.identifier) !== key)
  store([entry, ...others].slice(0, MAX_ACCOUNTS))
}

/** Forget one account (its "Forget" on the login screen). */
export function forgetAccount(identifier: string): void {
  const key = accountKey(identifier)
  store(listAccounts().filter((a) => accountKey(a.identifier) !== key))
}

/** Forget every account (also what remembering turned off asks for). */
export function forgetAllAccounts(): void {
  store([])
  clearPendingSignIn()
}

/**
 * Note that this tab is leaving for the identity provider of `realm`, so the
 * session the round trip opens is remembered as an OIDC account of that
 * realm ({@link completePendingSignIn}).
 */
export function beginOidcSignIn(realm: string, now: number = Date.now()): void {
  const pending: PendingSignIn = { realm, started: now }
  try {
    sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending))
  } catch {
    /* storage unavailable: the account is not remembered */
  }
}

/** Drop this tab's pending OIDC sign-in (it failed, or another one replaced it). */
export function clearPendingSignIn(): void {
  try {
    sessionStorage.removeItem(PENDING_KEY)
  } catch {
    /* ignore */
  }
}

function takePendingSignIn(now: number): PendingSignIn | null {
  let raw: string | null
  try {
    raw = sessionStorage.getItem(PENDING_KEY)
  } catch {
    return null
  }
  if (!raw) return null
  clearPendingSignIn()
  try {
    const p = JSON.parse(raw) as Partial<PendingSignIn>
    if (!boundedString(p.realm) || typeof p.started !== 'number') return null
    const age = now - p.started
    return age >= 0 && age <= PENDING_TTL_MS ? { realm: p.realm, started: p.started } : null
  } catch {
    return null
  }
}

/**
 * Called with the session of the first `GET /auth/me` of an app load: when
 * this tab started an OIDC sign-in a moment ago, remember the account it
 * signed in as (by its Forge username, which the identity provider gets back
 * as the login hint next time).
 */
export function completePendingSignIn(
  session: { username: string; display_name?: string | null },
  now: number = Date.now(),
): void {
  const pending = takePendingSignIn(now)
  if (!pending) return
  rememberAccount(
    {
      identifier: session.username,
      display_name: session.display_name ?? undefined,
      method: 'oidc',
      realm: pending.realm,
    },
    now,
  )
}
