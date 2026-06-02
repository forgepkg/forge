/**
 * Browser authentication — the single module that swapping to §12.2 cookie
 * sessions will touch.
 *
 * **Today (slice 1, token):** the user pastes a registry token (created in the
 * Tokens screen or out-of-band). Slice 1's principal middleware accepts a token
 * as the HTTP Basic *secret* (`Authorization: Basic base64("token:" + secret)`)
 * or as `X-NuGet-ApiKey`. We use Basic for the admin/browse API. The token is
 * stored in `localStorage` (an accepted risk for an internal admin tool).
 *
 * **Post-§12.2 (session cookie):** when a session cookie is present the browser
 * sends it automatically (same-origin). The swap is contained here: `authMode`
 * flips to `'cookie'`, `authHeaders()` returns `{}`, and `httpClient` already
 * sends `credentials: 'same-origin'`. No other module changes.
 */

const TOKEN_KEY = 'forge.token'

/** Which credential mechanism is active. Slice 1 is always `'token'`. */
export type AuthMode = 'token' | 'cookie'

/** The active auth mode. Flip to `'cookie'` when §12.2 sessions land. */
export const authMode: AuthMode = 'token'

/**
 * In-tab subscribers notified whenever the stored credential changes
 * (`setToken`/`clearToken`). The app shell uses this to re-run the `me` query
 * after a same-tab sign-in/sign-out without a full page reload. Cross-tab
 * changes already arrive via the `storage` event; this covers the same tab.
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
    if (e.key === null || e.key === TOKEN_KEY) listener()
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

/** The stored token secret, or null if the user has not authenticated. */
export function getToken(): string | null {
  if (authMode !== 'token') return null
  try {
    return localStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

/** Persist a token secret (called from the Login screen). */
export function setToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, token)
  } catch {
    /* storage unavailable (private mode); auth simply won't persist */
  }
  notify()
}

/** Clear stored credentials (called on logout or a 401). */
export function clearToken(): void {
  try {
    localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* ignore */
  }
  notify()
}

/** Whether we currently hold a credential the API will accept. */
export function isAuthenticated(): boolean {
  // Under cookie mode the browser sends the cookie implicitly, so we optimistic
  // -ally report "authenticated" and let `GET /admin/me` be the source of truth.
  if (authMode === 'cookie') return true
  return getToken() !== null
}

/**
 * Headers to attach to API requests for the active auth mode. Token mode emits
 * an HTTP Basic header with the token as the secret; cookie mode emits nothing
 * (the cookie travels automatically).
 */
export function authHeaders(): Record<string, string> {
  if (authMode === 'token') {
    const token = getToken()
    if (token) return { Authorization: `Basic ${base64(`token:${token}`)}` }
  }
  return {}
}
