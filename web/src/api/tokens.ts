import type { Level } from '~/api/rbac'
import { httpClient } from '~/lib/httpClient'

/**
 * Admin token management API (per-user).
 *
 * Types mirror the **real** Rust DTOs:
 *
 *  - `TokenView` (`crates/server/src/admin/tokens.rs`) is the metadata view —
 *    it carries **no secret and no hash**. Listing never returns the plaintext.
 *  - `CreatedToken` is the `POST` response and the **only** time the plaintext
 *    `token` is ever returned (flattened onto a `TokenView`). It is shown once
 *    via `ShowOnceSecret` and never re-fetched or cached.
 *  - Tokens belong to a user: `GET`/`POST` are under
 *    `/admin/users/{id}/tokens`; revoke is `DELETE /admin/tokens/{id}`, and
 *    an admin changes a token's scope with `PATCH /admin/tokens/{id}/scope`.
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
  /**
   * The token's privilege scope as stored, or `null` when unscoped (the
   * owner's access without `admin`). A stored scope that does not parse is
   * passed through as-is; the server denies such a token everything.
   */
  scope?: TokenScope | null
}

/**
 * Per-token scope (`forge_core::authz::TokenScope`): it only narrows the
 * owner's access. An absent `level` keeps the owner's levels; `admin: true`
 * keeps the owner's `admin` role (the admin API), only without
 * `repositories`; an absent `repositories` means every repository the owner
 * can reach.
 */
export interface TokenScope {
  level?: Level | null
  admin?: boolean | null
  repositories?: number[] | null
}

/** `POST /admin/users/{id}/tokens` request body (`CreateToken`). */
export interface CreateToken {
  name: string
  /** Optional RFC3339 expiry; absent → non-expiring. */
  expires_at?: string | null
  /** Optional scope; absent → the owner's access without `admin`. */
  scope?: TokenScope
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

/**
 * `PATCH /admin/tokens/{id}/scope` — set a token's scope, or clear it with
 * `null` (204; 404 for a revoked token). The next request with the token
 * reads the new scope.
 */
export function setTokenScope(
  id: number,
  scope: TokenScope | null,
): Promise<void> {
  return httpClient.patch<void>(`/admin/tokens/${id}/scope`, { scope })
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
