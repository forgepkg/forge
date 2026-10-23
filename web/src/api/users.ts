import { httpClient } from '~/lib/httpClient'

/**
 * Admin user CRUD API.
 *
 * Types mirror the **real** Rust DTOs (reconciled against slice 1, not the
 * forward-looking plan):
 *
 *  - `UserView` (`crates/server/src/admin/users.rs`) is the password-free
 *    response shape — the argon2id hash is never returned.
 *  - `GET /admin/users` returns a **bare array** of `UserView` (no
 *    `{ total, items }` envelope — slice-1 admin list is unpaginated).
 *  - `CreateUser` is the `POST /admin/users` body. `is_admin` defaults to
 *    `false` and `active` to `true` server-side; we always send them explicitly.
 *    `is_admin` also gives the new user the built-in `admin` role; other
 *    roles are assigned after the create (`assignRole` in `rbac.ts`).
 *  - There is **no update-user endpoint** in slice 1 (the plan's "edit /
 *    activate-deactivate" is not backed by the API yet). The only per-user
 *    write beyond create is `DELETE /admin/users/{id}`, switching a
 *    credential-forwarding account to a local one
 *    (`POST /admin/users/{id}/convert-to-local`), token management (see
 *    `tokens.ts`) and role assignment (see `rbac.ts`).
 *
 * All endpoints are admin-gated by the server; the UI only reaches them after
 * the `_app/admin` route guard confirms `is_admin`.
 */

/** Password-free user view (`UserView`). */
export interface UserView {
  id: number
  username: string
  is_admin: boolean
  active: boolean
  /**
   * How the account signs in: `local` (Forge password), `oidc` (identity
   * provider) or `upstream-basic` (credential-forwarding realm).
   */
  auth_source: string
  /**
   * When the account's credential-forwarding realm last kept a hash of the
   * password its upstream accepted; `null` when it keeps none. Such an
   * account can be switched to a local one (`convertUserToLocal`).
   */
  captured_password_at: string | null
  /**
   * The names of the RBAC roles the user holds, sorted. What the user may do
   * follows from these (with `is_admin`), not from `is_admin` alone.
   */
  roles: string[]
}

const AUTH_SOURCE_LABELS: Record<string, string> = {
  local: 'Password',
  oidc: 'Identity provider',
  'upstream-basic': 'Credential forwarding',
}

/**
 * A user's `auth_source` for display. Look-alike usernames from different
 * sources are different accounts; an unknown value is shown as sent.
 */
export function authSourceLabel(source: string): string {
  return AUTH_SOURCE_LABELS[source] ?? source
}

/** Longest DNS label of a UPN's domain, in characters. */
const MAX_DOMAIN_LABEL_CHARS = 63

/** A label of a UPN's domain: letters (with their marks), digits and `-`. */
const DOMAIN_LABEL = /^[\p{L}\p{M}\p{N}-]+$/u

/**
 * The name the server stores for `raw`: trimmed, NFC, lowercased (and NFC
 * again, as lowercasing can decompose). Mirrors `canonical_username`.
 */
export function canonicalUsername(raw: string): string {
  return raw.trim().normalize('NFC').toLowerCase().normalize('NFC')
}

/**
 * Why `raw` cannot name a new account, or `null` when it is a UPN
 * (`local-part@domain`). Mirrors `is_upn` in `crates/db/src/username.rs`:
 * exactly one `@`; a non-empty local part without whitespace; a domain of at
 * least two labels, each 1 to 63 letters, digits or `-`, neither starting nor
 * ending with `-`, no trailing dot, and a last label that is not all digits.
 * A Unicode domain counts in its canonical form, an `xn--` A-label as
 * written. The server's 400 stays authoritative.
 */
export function upnError(raw: string): string | null {
  const name = canonicalUsername(raw)
  const message = 'The username must be a UPN such as alice@example.com.'
  const parts = name.split('@')
  if (parts.length !== 2) return message
  const [local, domain] = parts
  if (local === '' || /\s/u.test(local)) return message
  const labels = domain.split('.')
  if (labels.length < 2) return message
  for (const label of labels) {
    const length = [...label].length
    if (
      length < 1 ||
      length > MAX_DOMAIN_LABEL_CHARS ||
      label.startsWith('-') ||
      label.endsWith('-') ||
      !DOMAIN_LABEL.test(label)
    ) {
      return message
    }
  }
  if (/^[0-9]+$/.test(labels[labels.length - 1])) return message
  return null
}

/**
 * Whether the stored `username` is a UPN. Accounts created before Forge 1.2
 * may be named otherwise (`alice`, `admin`): they keep signing in, and the
 * users list marks them "legacy name".
 */
export function isUpn(username: string): boolean {
  return upnError(username) === null
}

/** `POST /admin/users` request body (`CreateUser`). */
export interface CreateUser {
  username: string
  password: string
  is_admin: boolean
  active: boolean
}

/**
 * Query-key factory for the user resource. Arrays from one factory so list /
 * detail invalidation share stable, structured keys.
 */
export const userKeys = {
  all: () => ['users'] as const,
  list: () => ['users', 'list'] as const,
  detail: (id: number) => ['users', 'detail', id] as const,
}

/** `GET /admin/users` — bare array of all users. */
export function fetchUsers(signal?: AbortSignal): Promise<UserView[]> {
  return httpClient.get<UserView[]>('/admin/users', { signal })
}

/** `POST /admin/users` — create a user (201 → the created view). */
export function createUser(body: CreateUser): Promise<UserView> {
  return httpClient.post<UserView>('/admin/users', body)
}

/**
 * `POST /admin/users/{id}/convert-to-local` — switch a credential-forwarding
 * account to a local one whose password is its kept hash (409 when it keeps
 * none).
 */
export function convertUserToLocal(id: number): Promise<UserView> {
  return httpClient.post<UserView>(`/admin/users/${id}/convert-to-local`, {})
}

/** `DELETE /admin/users/{id}` — delete a user (204). */
export function deleteUser(id: number): Promise<void> {
  return httpClient.delete<void>(`/admin/users/${id}`)
}
