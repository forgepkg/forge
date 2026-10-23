import { httpClient } from '~/lib/httpClient'

/**
 * Admin repository CRUD + group-membership API.
 *
 * Types mirror the **real** Rust DTOs:
 *
 *  - `RepoView` (`crates/server/src/admin/repositories.rs`) is the password-free
 *    response shape. `upstream_password` is **never** returned; the boolean
 *    `has_upstream_password` reports whether one is stored, so the edit form can
 *    show a "set new password" affordance without ever populating the value.
 *  - `GET /admin/repositories` returns a **bare array** of `RepoView` (no
 *    `{ total, items }` envelope — the admin list is unpaginated).
 *  - `CreateRepo` / `UpdateRepo` are the request bodies. On update an absent
 *    field keeps the stored value; the nullable proxy fields (credentials,
 *    TTLs) are cleared by an explicit `null`. `kind` / `format` are not
 *    updatable.
 *  - Docker repositories (`format: "docker"`, served at `/v2/`) carry their
 *    own options — `host`, `immutable_tags`, `latest_mutable`,
 *    `writable_member` — which the server refuses on a NuGet repository (and
 *    `package_delay_seconds` / `allow_redeploy` on a docker one). Both bodies
 *    reject unknown fields.
 *  - `MemberView` / `AddMember` / `UpdateMember`
 *    (`crates/server/src/admin/members.rs`) drive the group editor; `priority`
 *    is unique within a group (a duplicate → 409). A member may itself be a
 *    group; an add that would create a cycle or nest too deep → 409.
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
  /**
   * Group: package id prefixes (lowercase, e.g. `acme.`) never served from a
   * proxy member, even before a hosted member has the id. Empty otherwise.
   * A docker group's prefixes may name namespaces (`acme/`).
   */
  reserved_prefixes: string[]
  /**
   * Docker: a DNS name (e.g. `docker.example.com`) the repository also
   * answers on at the root (`<host>/<image>`). `null` when unset / NuGet.
   */
  host: string | null
  /** Hosted docker: a pushed tag may not be moved to another manifest. */
  immutable_tags: boolean
  /** Hosted docker with `immutable_tags`: `latest` may still be moved. */
  latest_mutable: boolean
  /** Docker group: the hosted member a push to the group goes to. */
  writable_member: string | null
  /**
   * Hosted: the largest push it accepts in bytes (docker: the largest blob);
   * `null` for its format's default (`FormatView.default_max_upload_bytes`).
   */
  max_upload_bytes: number | null
}

/** `POST /admin/repositories` request body (`CreateRepo`). */
export interface CreateRepo {
  name: string
  kind: RepoKind
  /** A format id of `GET /admin/formats`; defaults to `nuget` server-side. */
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
  // Group fields:
  prefer_hosted?: boolean
  reserved_prefixes?: string[]
  // Docker fields (refused for NuGet repositories):
  /** Any docker kind: a DNS name the repository answers on by itself. */
  host?: string
  /** Hosted docker only. */
  immutable_tags?: boolean
  /** Hosted docker only (meaningful with `immutable_tags`). */
  latest_mutable?: boolean
  /** Docker group only: name of a hosted docker repository pushes go to. */
  writable_member?: string
  /** Hosted only: the largest push it accepts, in bytes. Absent: the default. */
  max_upload_bytes?: number
}

/**
 * `PUT /admin/repositories/{name}` request body (`UpdateRepo`). Every field is
 * optional; an absent field keeps the stored value. For `upstream_username`,
 * `upstream_password`, `metadata_ttl_seconds` and `not_found_ttl_seconds`:
 * absent = keep, `null` = clear (a TTL reverts to the server default), a value
 * = set. Changing `remote_url` to a different origin without a new
 * `upstream_password` makes the server drop the stored credentials. `kind` /
 * `format` are identity columns and are not updatable. The docker options
 * follow the same rules (`host` / `writable_member`: `null` clears) and are a
 * 400 on a NuGet repository.
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
  /** Replaces the whole list; `[]` clears it. */
  reserved_prefixes?: string[]
  /** Docker only; `null` clears it. */
  host?: string | null
  /** Hosted docker only. */
  immutable_tags?: boolean
  /** Hosted docker only. */
  latest_mutable?: boolean
  /** Docker group only; `null` clears it (pushes to the group are refused). */
  writable_member?: string | null
  /** Hosted only; `null` clears it (the format's default applies). */
  max_upload_bytes?: number | null
}

/**
 * An installed package format (`FormatView` of `GET /admin/formats`): the
 * built-in format plugins (NuGet, Helm) and every loaded WebAssembly plugin.
 */
export interface FormatView {
  /** The format id (`RepoView.format`). */
  id: string
  /** Display name. */
  name: string
  /** Built into the server rather than a WebAssembly plugin. */
  builtin: boolean
  /** The repository kinds it supports (proxy only with a host-side upstream, e.g. NuGet). */
  kinds: RepoKind[]
  /** Where its repositories are served: `{mount}/{repository}`. */
  mount: string
  /** Plugin version. */
  version?: string
  /** Plugin description. */
  description?: string
  /** SHA-256 of a WebAssembly plugin's component. */
  sha256?: string
  /** The upload limit of its hosted repositories without one of their own. */
  default_max_upload_bytes?: number
  /** The largest upload limit a repository may be given; `null`: unbounded. */
  max_upload_bytes_limit?: number | null
}

/**
 * `POST /admin/repositories/{name}/proxy-cache/invalidate` request body
 * (`InvalidateBody`): without `package`, the whole proxy's cache.
 */
export interface InvalidateProxyCache {
  /** A package id (a docker proxy: an image name, e.g. `library/nginx`). */
  package?: string
}

/** What a proxy cache invalidation removed (`Invalidated`). */
export interface ProxyCacheInvalidated {
  /** Remembered upstream "not found" answers removed (NuGet, Helm). */
  not_found_cleared: number
  /** Cached tags due for re-validation against the upstream (docker). */
  tags_expired: number
}

/** A group member view (`MemberView`). */
export interface MemberView {
  name: string
  kind: string
  priority: number
  /**
   * Owns the group's package ids: once any member is an owner, only owners
   * hide proxy versions (`prefer_hosted`) and serve reserved prefixes. Set
   * with `PATCH .../members/{member}` (the members screen's owner toggle); a
   * proxy cannot be an owner (400), and an owner must be unflagged before
   * it can be removed (409).
   */
  owner: boolean
}

/** `POST /admin/repositories/{name}/members` request body (`AddMember`). */
export interface AddMember {
  member: string
  priority: number
}

/** `PATCH /admin/repositories/{name}/members/{member}` body (`UpdateMember`). */
export interface UpdateMember {
  owner: boolean
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

/** Query key of the installed formats. */
export const formatKeys = {
  list: () => ['formats'] as const,
}

/** `GET /admin/formats` — the formats repositories can be created with. */
export function fetchFormats(signal?: AbortSignal): Promise<FormatView[]> {
  return httpClient.get<FormatView[]>('/admin/formats', { signal })
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

/**
 * `POST /admin/repositories/{name}/proxy-cache/invalidate` — make a proxy ask
 * its upstream again: forgets its "not found" answers (of one package, or of
 * all), its cached listings and documents, and re-validates docker tags.
 * Downloaded packages stay cached.
 */
export function invalidateProxyCache(
  name: string,
  body: InvalidateProxyCache,
): Promise<ProxyCacheInvalidated> {
  return httpClient.post<ProxyCacheInvalidated>(
    `/admin/repositories/${encodeURIComponent(name)}/proxy-cache/invalidate`,
    body,
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

/** `PATCH /admin/repositories/{name}/members/{member}` — set `owner` (204). */
export function updateMember(
  name: string,
  member: string,
  body: UpdateMember,
): Promise<void> {
  return httpClient.patch<void>(
    `/admin/repositories/${encodeURIComponent(name)}/members/${encodeURIComponent(member)}`,
    body,
  )
}
