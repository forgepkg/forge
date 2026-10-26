import { httpClient } from '~/lib/httpClient'
import type { AccessLevel } from '~/api/rbac'

/**
 * Admin user CRUD API.
 *
 * Types mirror the **real** Rust DTOs:
 *
 *  - `UserView` (`crates/server/src/admin/users.rs`) is the password-free
 *    response shape — the argon2id hash is never returned.
 *  - `GET /admin/users` returns a **bare array** of `UserView` (no
 *    `{ total, items }` envelope — the admin list is unpaginated).
 *  - `CreateUser` is the `POST /admin/users` body (#322): no password. A
 *    local account is invited: its user chooses the password from a link,
 *    sent by email, or (no email service, or a failed send) handed to the
 *    admin once in the answer's `invitation.link`. `role` gives the built-in
 *    access level; other roles are assigned on the user page.
 *  - `PATCH /admin/users/{id}` sets the account state alone
 *    (`{"active": false}` deactivates, `true` reactivates); the server
 *    refuses deactivating the last active administrator with 409.
 *    `POST /admin/users/{id}/reauth` signs the user out everywhere. The
 *    other per-user writes are `DELETE /admin/users/{id}`, invitations
 *    (`POST`/`DELETE /admin/users/{id}/invitation`), switching a
 *    credential-forwarding account to a local one (`POST
 *    /admin/users/{id}/convert-to-local`), token management (see
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
   * provider), `upstream-basic` (credential-forwarding realm) or
   * `trusted-header` (the headers of a trusted-header realm's proxy).
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
  /** Where invitations go. */
  email: string | null
  status: UserStatus
  /** The account's invitation while it is invited. */
  invitation?: InvitationView
}

/**
 * `invited`: a live invitation waits for the user to choose a password;
 * `invitation_expired`: invited, but its link no longer works (expired or
 * revoked): make a new one.
 */
export type UserStatus = 'active' | 'inactive' | 'invited' | 'invitation_expired'

/** An invitation, without its token. */
export interface InvitationView {
  email: string
  expires_at: string
  created_at: string
  /** When the email service took it; `null` for a link handed over. */
  sent_at: string | null
}

/** An invitation just made (`POST /admin/users`, `…/invitation`). */
export interface IssuedInvitation {
  email: string
  expires_at: string
  email_sent: boolean
  /** Why no email went out, when one should have. */
  error: string | null
  /** The link when no email carries it: shown once, never again. */
  link: string | null
}

const AUTH_SOURCE_LABELS: Record<string, string> = {
  local: 'Password',
  oidc: 'Identity provider',
  'upstream-basic': 'Credential forwarding',
  'trusted-header': 'Trusted header',
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
 * `POST /admin/users` request body (`CreateUser`): an invited local
 * account, or an account of the credential-forwarding realm named `realm`
 * (it signs in with the upstream's password) or of the trusted-header realm
 * named `realm` (the headers of its proxy name it).
 */
export interface CreateUser {
  username: string
  /** Where the invitation goes; the username when absent. */
  email?: string
  /** The built-in access level; `reader` when absent. */
  role?: AccessLevel
  realm?: string
}

/** `POST /admin/users` answer: the user and, for a local account, its invitation. */
export type CreatedUser = Omit<UserView, 'invitation'> & {
  invitation: IssuedInvitation | null
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
export function createUser(body: CreateUser): Promise<CreatedUser> {
  return httpClient.post<CreatedUser>('/admin/users', body)
}

/**
 * `POST /admin/users/{id}/invitation` — a new invitation, replacing the
 * previous one: sent by email (`send_email`), or as a link to copy.
 */
export function inviteUser(
  id: number,
  body: { send_email: boolean; email?: string },
): Promise<IssuedInvitation> {
  return httpClient.post<IssuedInvitation>(`/admin/users/${id}/invitation`, body)
}

/** `DELETE /admin/users/{id}/invitation` — revoke the invitation (204). */
export function revokeInvitation(id: number): Promise<void> {
  return httpClient.delete<void>(`/admin/users/${id}/invitation`)
}

/**
 * `POST /admin/users/{id}/convert-to-local` — switch a credential-forwarding
 * account to a local one whose password is its kept hash (409 when it keeps
 * none).
 */
export function convertUserToLocal(id: number): Promise<UserView> {
  return httpClient.post<UserView>(`/admin/users/${id}/convert-to-local`, {})
}

/**
 * `PATCH /admin/users/{id}` — deactivate (`false`) or reactivate (`true`) a
 * user; answers the updated view. Deactivating refuses every sign-in, ends
 * the user's sessions and suspends their tokens without revoking them;
 * reactivating changes only the flag.
 */
export function setUserActive(id: number, active: boolean): Promise<UserView> {
  return httpClient.patch<UserView>(`/admin/users/${id}`, { active })
}

/**
 * `POST /admin/users/{id}/reauth` — sign the user out everywhere (204): ends
 * their browser sessions and drops their cached upstream verdicts, and
 * revokes the tokens they minted from a session credential forwarding
 * established.
 */
export function reauthUser(id: number): Promise<void> {
  return httpClient.post<void>(`/admin/users/${id}/reauth`, {})
}

/** `DELETE /admin/users/{id}` — delete a user (204). */
export function deleteUser(id: number): Promise<void> {
  return httpClient.delete<void>(`/admin/users/${id}`)
}
