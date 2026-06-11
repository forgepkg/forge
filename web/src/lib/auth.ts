/**
 * Browser authentication — the single module that knows which credential the
 * SPA holds and how to attach it to requests.
 *
 * **Session mode (the only mode):** after `POST /auth/login` (or an OIDC
 * redirect) the server sets a `forge_session` cookie that the browser sends
 * automatically (same-origin; `httpClient` uses `credentials: 'same-origin'`).
 * We only persist the **CSRF token** from the login//auth/me response and send
 * it as `X-CSRF-Token` (required by the server on mutating requests; harmless
 * on reads).
 *
 * Signing in with a registry token is deliberately **not** supported: the UI
 * always authenticates with username+password or via a realm (OIDC). Registry
 * tokens exist only as NuGet feed / API credentials, minted on the Tokens
 * screen.
 */

const CSRF_KEY = 'forge.session.csrf'

/** Legacy slice-1 token storage key — cleared on sight, never read. */
const LEGACY_TOKEN_KEY = 'forge.token'

/**
 * In-tab subscribers notified whenever the stored credential changes
 * (`setSession`/`clearSession`). The app shell uses this to re-run the `me`
 * query after a same-tab sign-in/sign-out without a full page reload.
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
    if (e.key === null || e.key === CSRF_KEY) listener()
  }
  window.addEventListener('storage', onStorage)
  return () => {
    subscribers.delete(listener)
    window.removeEventListener('storage', onStorage)
  }
}

function read(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

/** The stored CSRF token (set on login), or null when unauthenticated. */
export function getCsrfToken(): string | null {
  return read(CSRF_KEY)
}

/**
 * Enter session mode: the session itself lives in the `forge_session` cookie;
 * we only persist the CSRF token from `POST /auth/login` / `GET /auth/me`.
 */
export function setSession(csrf: string): void {
  try {
    localStorage.setItem(CSRF_KEY, csrf)
    localStorage.removeItem(LEGACY_TOKEN_KEY)
  } catch {
    /* storage unavailable (private mode); auth simply won't persist */
  }
  notify()
}

/**
 * Clear the stored CSRF token (called on logout or a 401). The caller is
 * responsible for `POST /auth/logout` (the cookie is httpOnly; only the server
 * can invalidate it).
 */
export function clearSession(): void {
  try {
    localStorage.removeItem(CSRF_KEY)
    localStorage.removeItem(LEGACY_TOKEN_KEY)
  } catch {
    /* ignore */
  }
  notify()
}

/** Whether we currently hold a credential the API will accept. */
export function isAuthenticated(): boolean {
  return getCsrfToken() !== null
}

/**
 * Headers to attach to API requests: the CSRF header (the session cookie
 * travels automatically) — the server only checks it on mutating requests,
 * sending it on reads is harmless.
 */
export function authHeaders(): Record<string, string> {
  const csrf = getCsrfToken()
  if (csrf) return { 'X-CSRF-Token': csrf }
  return {}
}
