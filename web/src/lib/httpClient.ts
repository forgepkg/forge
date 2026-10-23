import { apiUrl } from './config'
import { authHeaders, clearSession, getCsrfToken, setSession } from './auth'

/**
 * Centralized HTTP client. **Every** API call goes through here so the auth
 * header / cookie credentials and the base URL are injected in exactly one
 * place — how the SPA authenticates is known only to `auth.ts`, never to the
 * call sites.
 */

/** An API error carrying the HTTP status + the server's (text) body. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
    /** `Retry-After` in seconds, when the server sent one (e.g. on a 429). */
    public readonly retryAfterSeconds?: number,
  ) {
    super(`API ${status}: ${body || '(no body)'}`)
    this.name = 'ApiError'
  }

  /** Auth failures the router/Query layer treats as non-retryable. */
  get isAuthError(): boolean {
    return this.status === 401 || this.status === 403
  }
}

interface RequestOptions {
  method?: string
  /** JSON body; serialized and sent with `Content-Type: application/json`. */
  json?: unknown
  /**
   * A `multipart/form-data` body (file uploads); the browser sets the
   * content type with its boundary.
   */
  form?: FormData
  /** Extra query parameters (undefined values are dropped). */
  query?: Record<string, string | number | boolean | undefined>
  signal?: AbortSignal
  /**
   * Do not report a 401 to the {@link onUnauthorized} handler (the stored
   * session is still cleared). For calls whose 401 the caller handles itself,
   * e.g. `POST /auth/logout` of an already-expired session.
   */
  skipUnauthorizedHandler?: boolean
  /** Internal: this is the single retry after a CSRF re-sync. */
  csrfRetried?: boolean
}

/**
 * What the app does when the server says the session is gone (401). The app
 * shell registers one (`AppLayout`): it drops the cached identity and routes
 * to the login screen. Kept as an injected callback so this module stays free
 * of router / query-client imports.
 */
type UnauthorizedHandler = () => void

let unauthorizedHandler: UnauthorizedHandler | null = null

/**
 * Register the 401 handler (replacing any previous one). Returns an
 * unregister function that only clears the slot if it still holds `handler`,
 * so a remount's registration is never undone by the old cleanup.
 */
export function onUnauthorized(handler: UnauthorizedHandler): () => void {
  unauthorizedHandler = handler
  return () => {
    if (unauthorizedHandler === handler) unauthorizedHandler = null
  }
}

/** The server's body for a CSRF rejection (`missing or invalid csrf token`). */
const CSRF_REJECTION = /csrf/i

/** Methods the server's CSRF check applies to. */
function isMutation(method: string): boolean {
  return !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())
}

/** In-flight `GET /auth/me` re-sync, shared by concurrent CSRF failures. */
let csrfResync: Promise<string | null> | null = null

/**
 * Re-read the session's CSRF token from `GET /auth/me` and store it. Resolves
 * to the fresh token, or `null` when the session is gone or unreachable (a
 * 401 there runs the normal 401 path). Concurrent callers share one request.
 */
function resyncCsrfToken(): Promise<string | null> {
  if (!csrfResync) {
    csrfResync = request<{ csrf_token: string }>('/auth/me')
      .then((session) => {
        if (getCsrfToken() !== session.csrf_token) {
          setSession(session.csrf_token)
        }
        return session.csrf_token
      })
      .catch(() => null)
      .finally(() => {
        csrfResync = null
      })
  }
  return csrfResync
}

/** Parse a `Retry-After` delta-seconds value (HTTP-dates are ignored). */
function retryAfter(res: Response): number | undefined {
  const raw = res.headers.get('retry-after')
  if (!raw || !/^\d+$/.test(raw.trim())) return undefined
  return Number(raw.trim())
}

function withQuery(path: string, query?: RequestOptions['query']): string {
  if (!query) return path
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined) params.set(k, String(v))
  }
  const qs = params.toString()
  return qs ? `${path}?${qs}` : path
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...authHeaders(),
  }
  let body: string | FormData | undefined
  if (opts.json !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.json)
  } else if (opts.form !== undefined) {
    body = opts.form
  }

  const method = opts.method ?? 'GET'
  const res = await fetch(apiUrl(withQuery(path, opts.query)), {
    method,
    headers,
    body,
    // Same-origin so the session cookie is sent automatically; no cross-origin
    // credentials (prod is single-origin, dev uses the Vite proxy).
    credentials: 'same-origin',
    signal: opts.signal,
  })

  if (res.status === 401) {
    // The session is gone (expired, revoked, signed out elsewhere). Let the
    // app drop the cached identity and route to login *first*, then forget
    // the CSRF token. `clearSession` only notifies when a token was stored,
    // so repeated 401s cannot feed a refetch loop.
    if (!opts.skipUnauthorizedHandler) unauthorizedHandler?.()
    clearSession()
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '')
    if (
      res.status === 403 &&
      isMutation(method) &&
      !opts.csrfRetried &&
      CSRF_REJECTION.test(text)
    ) {
      // The stored CSRF token is stale (e.g. another tab signed in again, or
      // an OIDC sign-in replaced the session): re-sync it from the live
      // session and retry once, instead of refusing every mutation until a
      // reload.
      const fresh = await resyncCsrfToken()
      if (fresh !== null && fresh !== headers['X-CSRF-Token']) {
        return request<T>(path, { ...opts, csrfRetried: true })
      }
    }
    throw new ApiError(res.status, text, retryAfter(res))
  }

  if (res.status === 204) return undefined as T
  const contentType = res.headers.get('content-type') ?? ''
  if (contentType.includes('application/json')) {
    return (await res.json()) as T
  }
  return (await res.text()) as unknown as T
}

export const httpClient = {
  get: <T>(path: string, opts?: Omit<RequestOptions, 'method' | 'json'>) =>
    request<T>(path, { ...opts, method: 'GET' }),
  post: <T>(path: string, json?: unknown, opts?: Omit<RequestOptions, 'method'>) =>
    request<T>(path, { ...opts, method: 'POST', json }),
  put: <T>(path: string, json?: unknown, opts?: Omit<RequestOptions, 'method'>) =>
    request<T>(path, { ...opts, method: 'PUT', json }),
  patch: <T>(path: string, json?: unknown, opts?: Omit<RequestOptions, 'method'>) =>
    request<T>(path, { ...opts, method: 'PATCH', json }),
  /** `POST` a `multipart/form-data` body. */
  postForm: <T>(
    path: string,
    form: FormData,
    opts?: Omit<RequestOptions, 'method' | 'json' | 'form'>,
  ) => request<T>(path, { ...opts, method: 'POST', form }),
  delete: <T>(path: string, opts?: Omit<RequestOptions, 'method' | 'json'>) =>
    request<T>(path, { ...opts, method: 'DELETE' }),
}
