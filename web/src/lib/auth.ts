/**
 * Browser authentication — the single module that knows which credential the
 * SPA holds and how to attach it to requests.
 *
 * **Token mode (slice 1):** the user pastes a registry token (created in the
 * Tokens screen or out-of-band). The principal middleware accepts a token as
 * the HTTP Basic *secret* (`Authorization: Basic base64("token:" + secret)`)
 * or as `X-NuGet-ApiKey`. We use Basic for the admin/browse API. The token is
 * stored in `localStorage` (an accepted risk for an internal admin tool).
 *
 * **Session mode (§12.7 realms):** after `POST /auth/login` (or an OIDC
 * redirect) the server sets a `forge_session` cookie that the browser sends
 * automatically (same-origin; `httpClient` uses `credentials: 'same-origin'`).
 * We only persist the **CSRF token** from the login//auth/me response and send
 * it as `X-CSRF-Token` (required by the server on mutating requests; harmless
 * on reads). No Authorization header is emitted in session mode.
 */

const TOKEN_KEY = 'forge.token'
const CSRF_KEY = 'forge.session.csrf'

/** Which credential mechanism is active. */
export type AuthMode = 'token' | 'session'

/** The stored credential: a registry token or a cookie-session CSRF token. */
export type StoredAuth =
  | { mode: 'token'; token: string }
  | { mode: 'session'; csrf: string }

/**
 * In-tab subscribers notified whenever the stored credential changes
 * (`setToken`/`setSession`/`clearToken`). The app shell uses this to re-run
 * the `me` query after a same-tab sign-in/sign-out without a full page reload.
 * Cross-tab changes already arrive via the `storage` event; this covers the
 * same tab.
 */
const subscribers = new Set<() => void>()

function notify(): void {
  for (const fn of subscribers) fn()
}

/**
 * Subscribe to credential changes. Returns an unsubscribe function. Combined
 * with the `storage` event (other tabs), this lets the UI react to any change
 * in the active credential regardless of which tab made it.
 */
export function onAuthChange(listener: () => void): () => void {
  subscribers.add(listener)
  const onStorage = (e: StorageEvent) => {
    if (e.key === null || e.key === TOKEN_KEY || e.key === CSRF_KEY) listener()
  }
  window.addEventListener('storage', onStorage)
  return () => {
    subscribers.delete(listener)
    window.removeEventListener('storage', onStorage)
  }
}

/** Base64-encode a UTF-8 string (token-in-Basic). */
function base64(input: string): string {
  // btoa expects latin1; encode UTF-8 first so non-ASCII secrets survive.
  const bytes = new TextEncoder().encode(input)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}

function read(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

/**
 * The stored credential, or null when unauthenticated. A cookie session wins
 * over a leftover token (setting one clears the other, so both present only
 * happens after a partial storage failure).
 */
export function getAuth(): StoredAuth | null {
  const csrf = read(CSRF_KEY)
  if (csrf) return { mode: 'session', csrf }
  const token = read(TOKEN_KEY)
  if (token) return { mode: 'token', token }
  return null
}

/** The active auth mode, or null when unauthenticated. */
export function getAuthMode(): AuthMode | null {
  return getAuth()?.mode ?? null
}

/** The stored token secret (token mode only), or null. */
export function getToken(): string | null {
  const auth = getAuth()
  return auth?.mode === 'token' ? auth.token : null
}

/** The stored CSRF token (session mode only), or null. */
export function getCsrfToken(): string | null {
  const auth = getAuth()
  return auth?.mode === 'session' ? auth.csrf : null
}

/** Persist a registry token (called from the Login screen's token form). */
export function setToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, token)
    localStorage.removeItem(CSRF_KEY)
  } catch {
    /* storage unavailable (private mode); auth simply won't persist */
  }
  notify()
}

/**
 * Enter session mode: the session itself lives in the `forge_session` cookie;
 * we only persist the CSRF token from `POST /auth/login` / `GET /auth/me`.
 */
export function setSession(csrf: string): void {
  try {
    localStorage.setItem(CSRF_KEY, csrf)
    localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* storage unavailable (private mode); auth simply won't persist */
  }
  notify()
}

/**
 * Clear stored credentials — token and session CSRF alike (called on logout
 * or a 401). In session mode the caller is responsible for `POST /auth/logout`
 * (the cookie is httpOnly; only the server can invalidate it).
 */
export function clearToken(): void {
  try {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(CSRF_KEY)
  } catch {
    /* ignore */
  }
  notify()
}

/** Whether we currently hold a credential the API will accept. */
export function isAuthenticated(): boolean {
  return getAuth() !== null
}

/**
 * Headers to attach to API requests for the active auth mode. Token mode emits
 * an HTTP Basic header with the token as the secret; session mode emits the
 * CSRF header (the session cookie travels automatically) — the server only
 * checks it on mutating requests, sending it on reads is harmless.
 */
export function authHeaders(): Record<string, string> {
  const auth = getAuth()
  if (auth?.mode === 'token') {
    return { Authorization: `Basic ${base64(`token:${auth.token}`)}` }
  }
  if (auth?.mode === 'session') {
    return { 'X-CSRF-Token': auth.csrf }
  }
  return {}
}
