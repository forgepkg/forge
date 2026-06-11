import { apiUrl } from './config'
import { authHeaders, clearSession } from './auth'

/**
 * Centralized HTTP client. **Every** API call goes through here so the auth
 * header / cookie credentials and the base URL are injected in exactly one
 * place — switching token-header for §12.2 cookie-session touches only
 * `auth.ts`, never the call sites.
 */

/** An API error carrying the HTTP status + the server's (text) body. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
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
  /** Extra query parameters (undefined values are dropped). */
  query?: Record<string, string | number | boolean | undefined>
  signal?: AbortSignal
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
  let body: string | undefined
  if (opts.json !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.json)
  }

  const res = await fetch(apiUrl(withQuery(path, opts.query)), {
    method: opts.method ?? 'GET',
    headers,
    body,
    // Same-origin so a future §12.2 session cookie is sent automatically; no
    // cross-origin credentials (prod is single-origin, dev uses the Vite proxy).
    credentials: 'same-origin',
    signal: opts.signal,
  })

  if (res.status === 401) {
    // Stale/invalid credentials: clear them so the UI routes back to login.
    clearSession()
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new ApiError(res.status, text)
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
  delete: <T>(path: string, opts?: Omit<RequestOptions, 'method' | 'json'>) =>
    request<T>(path, { ...opts, method: 'DELETE' }),
}
