import { httpClient } from '~/lib/httpClient'

/**
 * Admin repository CRUD + group-membership API.
 *
 * Types mirror the **real** Rust DTOs (reconciled against slice 1, not the
 * forward-looking plan):
 *
 *  - `RepoView` (`crates/server/src/admin/repositories.rs`) is the password-free
 *    response shape. `upstream_password` is **never** returned; the boolean
 *    `has_upstream_password` reports whether one is stored, so the edit form can
 *    show a "set new password" affordance without ever populating the value.
 *  - `GET /admin/repositories` returns a **bare array** of `RepoView` (no
 *    `{ total, items }` envelope — slice-1 admin list is unpaginated).
 *  - `CreateRepo` / `UpdateRepo` are the request bodies. On update an absent
 *    field keeps the stored value; the nullable proxy fields (credentials,
 *    TTLs) are cleared by an explicit `null`. `kind` / `format` are not
 *    updatable.
 *  - `MemberView` / `AddMember` (`crates/server/src/admin/members.rs`) drive the
 *    group editor; `priority` is unique within a group (a duplicate → 409).
 *
 * All endpoints are admin-gated by the server; the UI only reaches them after
 * the `_app/admin` route guard confirms `is_admin`.
 */

/** Repository kind discriminator. */
export type RepoKind = 'hosted' | 'proxy' | 'group'

/** Password-free repository view (`RepoView`). */
export interface RepoView {
  id: number
  name: string
  format: string
  kind: string
  anonymous_read: boolean
  online: boolean
  /** Proxy upstream URL (`null` for hosted / group). */
  remote_url: string | null
  /** Proxy package-delay window in seconds (0 = no delay). */
  package_delay_seconds: number
  /** Proxy upstream basic-auth username, if set. */
  upstream_username: string | null
  /** Whether an upstream password is stored (the value is never returned). */
  has_upstream_password: boolean
  /** Proxy metadata cache TTL in seconds (`null` = server default). */
  metadata_ttl_seconds: number | null
  /** Proxy not-found cache TTL in seconds (`null` = server default). */
  not_found_ttl_seconds: number | null
  /** Hosted: allow re-pushing an existing version. */
  allow_redeploy: boolean
  /**
   * Group: when a package id exists in a hosted member, hide proxy members'
   * versions of it (dependency-confusion guard). Always `false` for
   * non-groups.
   */
  prefer_hosted: boolean
}

/** `POST /admin/repositories` request body (`CreateRepo`). */
export interface CreateRepo {
  name: string
  kind: RepoKind
  format?: string
  anonymous_read?: boolean
  online?: boolean
  // Proxy fields:
  remote_url?: string | null
  package_delay_seconds?: number
  upstream_username?: string | null
  upstream_password?: string | null
  metadata_ttl_seconds?: number | null
  not_found_ttl_seconds?: number | null
  // Hosted field:
  allow_redeploy?: boolean
  // Group field:
  prefer_hosted?: boolean
}

/**
 * `PUT /admin/repositories/{name}` request body (`UpdateRepo`). Every field is
 * optional; an absent field keeps the stored value. For `upstream_username`,
 * `upstream_password`, `metadata_ttl_seconds` and `not_found_ttl_seconds`:
 * absent = keep, `null` = clear (a TTL reverts to the server default), a value
 * = set. Changing `remote_url` to a different origin without a new
 * `upstream_password` makes the server drop the stored credentials. `kind` /
 * `format` are identity columns and are not updatable.
 */
export interface UpdateRepo {
  name?: string
  anonymous_read?: boolean
  online?: boolean
  remote_url?: string | null
  package_delay_seconds?: number
  upstream_username?: string | null
  upstream_password?: string | null
  metadata_ttl_seconds?: number | null
  not_found_ttl_seconds?: number | null
  allow_redeploy?: boolean
  prefer_hosted?: boolean
}

/** A group member view (`MemberView`). */
export interface MemberView {
  name: string
  kind: string
  priority: number
}

/** `POST /admin/repositories/{name}/members` request body (`AddMember`). */
export interface AddMember {
  member: string
  priority: number
}

/**
 * Query-key factory for the repository resource. Arrays from one factory so
 * list / detail / members invalidation share stable, structured keys.
 */
export const repoKeys = {
  all: () => ['repositories'] as const,
  list: () => ['repositories', 'list'] as const,
  detail: (name: string) => ['repositories', 'detail', name] as const,
  members: (name: string) => ['repositories', 'members', name] as const,
}

/** `GET /admin/repositories` — bare array of all repositories. */
export function fetchRepositories(signal?: AbortSignal): Promise<RepoView[]> {
  return httpClient.get<RepoView[]>('/admin/repositories', { signal })
}

/** `GET /admin/repositories/{name}` — one repository's detail. */
export function fetchRepository(
  name: string,
  signal?: AbortSignal,
): Promise<RepoView> {
  return httpClient.get<RepoView>(
    `/admin/repositories/${encodeURIComponent(name)}`,
    { signal },
  )
}

/** `POST /admin/repositories` — create a repository (201 → the created view). */
export function createRepository(body: CreateRepo): Promise<RepoView> {
  return httpClient.post<RepoView>('/admin/repositories', body)
}

/** `PUT /admin/repositories/{name}` — partial update (→ the updated view). */
export function updateRepository(
  name: string,
  body: UpdateRepo,
): Promise<RepoView> {
  return httpClient.put<RepoView>(
    `/admin/repositories/${encodeURIComponent(name)}`,
    body,
  )
}

/** `DELETE /admin/repositories/{name}` — delete a repository (204). */
export function deleteRepository(name: string): Promise<void> {
  return httpClient.delete<void>(
    `/admin/repositories/${encodeURIComponent(name)}`,
  )
}

/** `GET /admin/repositories/{name}/members` — a group's ordered members. */
export function fetchMembers(
  name: string,
  signal?: AbortSignal,
): Promise<MemberView[]> {
  return httpClient.get<MemberView[]>(
    `/admin/repositories/${encodeURIComponent(name)}/members`,
    { signal },
  )
}

/** `POST /admin/repositories/{name}/members` — add a member (201, no body). */
export function addMember(name: string, body: AddMember): Promise<void> {
  return httpClient.post<void>(
    `/admin/repositories/${encodeURIComponent(name)}/members`,
    body,
  )
}

/** `DELETE /admin/repositories/{name}/members/{member}` — remove a member (204). */
export function removeMember(name: string, member: string): Promise<void> {
  return httpClient.delete<void>(
    `/admin/repositories/${encodeURIComponent(name)}/members/${encodeURIComponent(member)}`,
  )
}
