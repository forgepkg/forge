import { httpClient } from '~/lib/httpClient'

/**
 * Admin RBAC API: roles, their grants and members, content selectors, user
 * role assignment and the effective-access explain views.
 *
 * Types mirror the Rust DTOs in `crates/server/src/admin/`:
 *
 *  - `RoleView` (`roles.rs`) counts the role's grants and users. The built-in
 *    roles (`admin`, `writer`, `anonymous`) cannot be deleted; only a
 *    role's description can change.
 *  - `GrantView` (`grants.rs`) is `(repository or every repository, level,
 *    selector?)`: `repository_id: null` means every repository. A role holds
 *    one grant per repository and selector; adding one again sets its level.
 *  - `SelectorView` (`content_selectors.rs`): include and exclude globs on the
 *    lowercased package name. An empty include list matches every package.
 *    `PATCH` keeps an omitted field; deleting a selector deletes the grants
 *    that use it.
 *  - `EffectiveView` (`effective.rs`): the flat union of a principal's grants,
 *    with repository and selector ids the UI resolves to names.
 *
 * Every endpoint is admin-gated by the server; the UI reaches them only after
 * the `/manage` route guard confirms `is_admin`.
 */

/**
 * The ordered access levels a grant (and a token scope) gives, lowest first:
 * each includes the ones below it. Administration is no level: it is the
 * built-in `admin` role.
 */
export const LEVELS = ['read', 'write', 'delete'] as const
export type Level = (typeof LEVELS)[number]

/**
 * The Nexus actions each level covers: `read` covers browse and read, `write`
 * adds add and edit, and `delete` adds delete.
 */
export const LEVEL_COVERS: Record<Level, string> = {
  read: 'browse, read',
  write: 'browse, read, add, edit',
  delete: 'browse, read, add, edit, delete',
}

/** A level with what it covers, as the level pickers offer it. */
export function levelLabel(level: Level): string {
  return `${level} (${LEVEL_COVERS[level]})`
}

/** The built-in role names. */
export const ADMIN_ROLE = 'admin'
export const WRITER_ROLE = 'writer'
export const ANONYMOUS_ROLE = 'anonymous'

/**
 * A user's built-in access level: `admin` (the `admin` role), `writer` (the
 * `writer` role: read and publish packages on every repository, no
 * administration) or `reader` (neither; what they may read follows from
 * their other roles and the anonymous reach). The levels are the built-in
 * roles an admin switches between on the user page.
 */
export type AccessLevel = 'reader' | 'writer' | 'admin'

/** The built-in role behind each access level above `reader`. */
export const ACCESS_ROLES: Record<Exclude<AccessLevel, 'reader'>, string> = {
  admin: ADMIN_ROLE,
  writer: WRITER_ROLE,
}

/**
 * The access level of a user holding `roles` (role names). An administrator
 * by the legacy `is_admin` flag counts as `admin`.
 */
export function accessLevel(roles: readonly string[], isAdmin = false): AccessLevel {
  if (isAdmin || roles.includes(ADMIN_ROLE)) return 'admin'
  if (roles.includes(WRITER_ROLE)) return 'writer'
  return 'reader'
}

/** A role (`RoleView`). */
export interface RoleView {
  id: number
  name: string
  description: string
  builtin: boolean
  /** The role's grants: deleting the role removes them. */
  grant_count: number
  /** The users holding the role: deleting the role unassigns them. */
  user_count: number
}

/** `POST /admin/roles` body. */
export interface CreateRole {
  name: string
  description?: string
}

/** A user holding a role (`GET /admin/roles/{id}/users` item). */
export interface RoleMember {
  id: number
  username: string
  auth_source: string
  active: boolean
}

/** A grant (`GrantView`); `repository_id: null` = every repository. */
export interface GrantView {
  id: number
  role_id: number
  repository_id: number | null
  level: Level
  selector_id: number | null
}

/**
 * `PUT /admin/roles/{id}/grants` body. Omit `repository_id` for every
 * repository. Sets the level of the role's grant on that repository and
 * selector when it has one.
 */
export interface AddGrant {
  repository_id?: number
  level: Level
  selector_id?: number
}

/** A content selector (`SelectorView`). */
export interface SelectorView {
  id: number
  name: string
  description: string
  includes: string[]
  excludes: string[]
}

/** `POST /admin/content-selectors` body. */
export interface CreateSelector {
  name: string
  description?: string
  includes: string[]
  excludes: string[]
}

/** `PATCH /admin/content-selectors/{id}` body; the name cannot change. */
export interface UpdateSelector {
  description?: string
  includes?: string[]
  excludes?: string[]
}

/** `POST /admin/content-selectors/match` body. */
export interface MatchSelector {
  includes: string[]
  excludes: string[]
  name: string
}

/** One grant of an effective set (`effective.rs` `GrantView`). */
export interface EffectiveGrant {
  level: Level
  repository_id: number | null
  selector_id: number | null
  includes: string[] | null
  excludes: string[] | null
}

/** A principal's effective access (`EffectiveView`). */
export interface EffectiveView {
  /** Allow-all: the `admin` role, or the legacy `is_admin` flag. */
  is_admin: boolean
  grants: EffectiveGrant[]
}

export const roleKeys = {
  all: () => ['roles'] as const,
  list: () => ['roles', 'list'] as const,
  detail: (id: number) => ['roles', 'detail', id] as const,
  grants: (id: number) => ['roles', 'grants', id] as const,
  members: (id: number) => ['roles', 'members', id] as const,
}

export const selectorKeys = {
  all: () => ['content-selectors'] as const,
  list: () => ['content-selectors', 'list'] as const,
  grants: (id: number) => ['content-selectors', 'grants', id] as const,
}

export const userRoleKeys = {
  all: () => ['user-roles'] as const,
  roles: (userId: number) => ['user-roles', 'roles', userId] as const,
  effective: (userId: number) => ['user-roles', 'effective', userId] as const,
}

/** `GET /admin/roles` — every role, by name. */
export function fetchRoles(signal?: AbortSignal): Promise<RoleView[]> {
  return httpClient.get<RoleView[]>('/admin/roles', { signal })
}

/** `GET /admin/roles/{id}`. */
export function fetchRole(id: number, signal?: AbortSignal): Promise<RoleView> {
  return httpClient.get<RoleView>(`/admin/roles/${id}`, { signal })
}

/** `POST /admin/roles` (201 → the role; 409 for a taken name). */
export function createRole(body: CreateRole): Promise<RoleView> {
  return httpClient.post<RoleView>('/admin/roles', body)
}

/** `PATCH /admin/roles/{id}` — change the description. */
export function updateRole(id: number, description: string): Promise<RoleView> {
  return httpClient.patch<RoleView>(`/admin/roles/${id}`, { description })
}

/** `DELETE /admin/roles/{id}` (403 for a built-in role). */
export function deleteRole(id: number): Promise<void> {
  return httpClient.delete<void>(`/admin/roles/${id}`)
}

/** `GET /admin/roles/{id}/users` — the role's members. */
export function fetchRoleMembers(
  id: number,
  signal?: AbortSignal,
): Promise<RoleMember[]> {
  return httpClient.get<RoleMember[]>(`/admin/roles/${id}/users`, { signal })
}

/** `GET /admin/roles/{id}/grants`. */
export function fetchGrants(
  roleId: number,
  signal?: AbortSignal,
): Promise<GrantView[]> {
  return httpClient.get<GrantView[]>(`/admin/roles/${roleId}/grants`, {
    signal,
  })
}

/** `PUT /admin/roles/{id}/grants` — add a grant (idempotent, 201). */
export function addGrant(roleId: number, body: AddGrant): Promise<void> {
  return httpClient.put<void>(`/admin/roles/${roleId}/grants`, body)
}

/** `DELETE /admin/roles/{id}/grants/{grant_id}`. */
export function removeGrant(roleId: number, grantId: number): Promise<void> {
  return httpClient.delete<void>(`/admin/roles/${roleId}/grants/${grantId}`)
}

/** `GET /admin/users/{id}/roles` — the roles a user holds. */
export function fetchUserRoles(
  userId: number,
  signal?: AbortSignal,
): Promise<RoleView[]> {
  return httpClient.get<RoleView[]>(`/admin/users/${userId}/roles`, { signal })
}

/** `PUT /admin/users/{id}/roles` — assign a role (idempotent, 204). */
export function assignRole(userId: number, roleId: number): Promise<void> {
  return httpClient.put<void>(`/admin/users/${userId}/roles`, {
    role_id: roleId,
  })
}

/**
 * `DELETE /admin/users/{id}/roles/{role_id}` — 409 when it would take `admin`
 * from the last active administrator.
 */
export function unassignRole(userId: number, roleId: number): Promise<void> {
  return httpClient.delete<void>(`/admin/users/${userId}/roles/${roleId}`)
}

/** `GET /admin/users/{id}/effective`. */
export function fetchUserEffective(
  userId: number,
  signal?: AbortSignal,
): Promise<EffectiveView> {
  return httpClient.get<EffectiveView>(`/admin/users/${userId}/effective`, {
    signal,
  })
}

/** `GET /admin/content-selectors`. */
export function fetchSelectors(signal?: AbortSignal): Promise<SelectorView[]> {
  return httpClient.get<SelectorView[]>('/admin/content-selectors', { signal })
}

/** `POST /admin/content-selectors` (400 for an invalid glob, 409 for a taken name). */
export function createSelector(body: CreateSelector): Promise<SelectorView> {
  return httpClient.post<SelectorView>('/admin/content-selectors', body)
}

/** `PATCH /admin/content-selectors/{id}`. */
export function updateSelector(
  id: number,
  body: UpdateSelector,
): Promise<SelectorView> {
  return httpClient.patch<SelectorView>(`/admin/content-selectors/${id}`, body)
}

/** `DELETE /admin/content-selectors/{id}` — deletes its grants too. */
export function deleteSelector(id: number): Promise<void> {
  return httpClient.delete<void>(`/admin/content-selectors/${id}`)
}

/** `GET /admin/content-selectors/{id}/grants` — what deleting it removes. */
export function fetchSelectorGrants(
  id: number,
  signal?: AbortSignal,
): Promise<GrantView[]> {
  return httpClient.get<GrantView[]>(`/admin/content-selectors/${id}/grants`, {
    signal,
  })
}

/**
 * `POST /admin/content-selectors/match` — whether `name` matches the
 * patterns, by the server's own globs (400 for an invalid glob).
 */
export function matchSelector(
  body: MatchSelector,
  signal?: AbortSignal,
): Promise<{ matches: boolean }> {
  return httpClient.post<{ matches: boolean }>(
    '/admin/content-selectors/match',
    body,
    { signal },
  )
}
