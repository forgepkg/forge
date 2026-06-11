import { httpClient } from '~/lib/httpClient'

/**
 * Admin token management API (per-user).
 *
 * Types mirror the **real** Rust DTOs (reconciled against slice 1, not the
 * forward-looking plan):
 *
 *  - `TokenView` (`crates/server/src/admin/tokens.rs`) is the metadata view —
 *    it carries **no secret and no hash**. Listing never returns the plaintext.
 *  - `CreatedToken` is the `POST` response and the **only** time the plaintext
 *    `token` is ever returned (flattened onto a `TokenView`). It is shown once
 *    via `ShowOnceSecret` and never re-fetched or cached.
 *  - Tokens are scoped to a user in slice 1: `GET`/`POST` are under
 *    `/admin/users/{id}/tokens`; revoke is `DELETE /admin/tokens/{id}`.
 *  - `GET /admin/users/{id}/tokens` returns a **bare array** of `TokenView`.
 *  - `revoke` is a soft-delete (sets `revoked_at`); the server replies 404 when
 *    the token is unknown or already revoked.
 *
 * Admin-gated by the server; reached only after the `_app/admin` route guard.
 */

/** Token metadata view (`TokenView`) — never carries a secret. */
export interface TokenView {
  id: number
  user_id: number
  name: string
  /** RFC3339 timestamp, or `null` for a non-expiring token. */
  expires_at: string | null
  /** RFC3339 timestamp once revoked, else `null`. */
  revoked_at: string | null
  /** RFC3339 timestamp of the most recent use, else `null`. */
  last_used_at: string | null
  created_at: string
}

/** `POST /admin/users/{id}/tokens` request body (`CreateToken`). */
export interface CreateToken {
  name: string
  /** Optional RFC3339 expiry; absent → non-expiring. */
  expires_at?: string | null
}

/**
 * `POST` response (`CreatedToken`): a `TokenView` plus the plaintext `token`.
 * The plaintext is returned **once** and cannot be retrieved again.
 */
export interface CreatedToken extends TokenView {
  token: string
}

/**
 * Query-key factory for the token resource. Tokens are listed per user, so the
 * list key is parameterized by `userId`.
 */
export const tokenKeys = {
  all: () => ['tokens'] as const,
  list: (userId: number) => ['tokens', 'list', userId] as const,
  mine: () => ['tokens', 'mine'] as const,
}

/** `GET /admin/users/{id}/tokens` — a user's tokens (bare array). */
export function fetchTokens(
  userId: number,
  signal?: AbortSignal,
): Promise<TokenView[]> {
  return httpClient.get<TokenView[]>(`/admin/users/${userId}/tokens`, { signal })
}

/**
 * `POST /admin/users/{id}/tokens` — issue a token (201 → `CreatedToken` with the
 * one-time plaintext secret).
 */
export function createToken(
  userId: number,
  body: CreateToken,
): Promise<CreatedToken> {
  return httpClient.post<CreatedToken>(`/admin/users/${userId}/tokens`, body)
}

/** `DELETE /admin/tokens/{id}` — revoke a token (204). */
export function revokeToken(id: number): Promise<void> {
  return httpClient.delete<void>(`/admin/tokens/${id}`)
}

/*
 * Self-service token API (`/admin/me/tokens`): any signed-in user manages
 * **their own** tokens — no admin required. The server additionally requires a
 * password/realm session (a token can never mint further tokens).
 */

/** `GET /admin/me/tokens` — the caller's own tokens (bare array). */
export function fetchMyTokens(signal?: AbortSignal): Promise<TokenView[]> {
  return httpClient.get<TokenView[]>('/admin/me/tokens', { signal })
}

/** `POST /admin/me/tokens` — issue a token for the caller (201 → `CreatedToken`). */
export function createMyToken(body: CreateToken): Promise<CreatedToken> {
  return httpClient.post<CreatedToken>('/admin/me/tokens', body)
}

/** `DELETE /admin/me/tokens/{id}` — revoke one of the caller's tokens (204). */
export function revokeMyToken(id: number): Promise<void> {
  return httpClient.delete<void>(`/admin/me/tokens/${id}`)
}
