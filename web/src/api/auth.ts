import { httpClient } from '~/lib/httpClient'

/**
 * Public + session auth API (§12.7 realms).
 *
 * Types mirror the Rust DTOs:
 *
 *  - `GET /auth/login-options` (public) drives how the login screen renders:
 *    identifier-first vs combined, whether a password form exists at all, and
 *    the (at most one) OIDC button.
 *  - `POST /auth/identify` (public) is the identifier-first routing step: it
 *    answers "password or IdP redirect?" for a username without revealing
 *    whether the account exists.
 *  - `POST /auth/login` (public) performs a password login; 200 sets the
 *    `forge_session` cookie and returns the CSRF token; 401 is uniform for any
 *    bad credential.
 *  - `GET /auth/me` / `POST /auth/logout` operate on the cookie session
 *    (logout requires the `X-CSRF-Token` header, supplied by `authHeaders()`).
 */

/** One OIDC sign-in option (`GET /auth/login-options` has at most one). */
export interface OidcLoginOption {
  name: string
  label: string
  /** Navigate the browser here; the server 302s to the IdP. */
  login_url: string
}

/** `GET /auth/login-options` response. */
export interface LoginOptions {
  mode: 'identifier_first' | 'combined'
  /** Whether any password-capable realm is enabled (renders the password form). */
  password: boolean
  oidc: OidcLoginOption[]
}

/** `POST /auth/identify` response — where to send this username. */
export interface IdentifyResponse {
  mode: 'password' | 'oidc_redirect'
  realm: string
  /** Present for `oidc_redirect`; navigate the browser there. */
  login_url?: string
}

/** `POST /auth/login` 200 response (the cookie travels via Set-Cookie). */
export interface LoginResponse {
  user_id: number
  username: string
  is_admin: boolean
  csrf_token: string
}

/** `GET /auth/me` response — the active cookie session, incl. the CSRF token. */
export interface AuthSession {
  user_id: number
  username: string
  is_admin: boolean
  csrf_token: string
}

/** Query-key factory for the public auth resources. */
export const authKeys = {
  loginOptions: () => ['auth', 'login-options'] as const,
}

/** `GET /auth/login-options` — public; how the login screen should render. */
export function fetchLoginOptions(signal?: AbortSignal): Promise<LoginOptions> {
  return httpClient.get<LoginOptions>('/auth/login-options', { signal })
}

/** `POST /auth/identify` — identifier-first routing for a username. */
export function identify(username: string): Promise<IdentifyResponse> {
  return httpClient.post<IdentifyResponse>('/auth/identify', { username })
}

/** `POST /auth/login` — password login; 200 sets the session cookie. */
export function login(body: {
  username: string
  password: string
}): Promise<LoginResponse> {
  return httpClient.post<LoginResponse>('/auth/login', body)
}

/** `GET /auth/me` — the active cookie session (401 when none). */
export function fetchAuthSession(signal?: AbortSignal): Promise<AuthSession> {
  return httpClient.get<AuthSession>('/auth/me', { signal })
}

/** `POST /auth/logout` — invalidate the cookie session (CSRF-guarded). */
export function logout(): Promise<void> {
  return httpClient.post<void>('/auth/logout')
}
