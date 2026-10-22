import { queryOptions } from '@tanstack/react-query'

import { ApiError, httpClient } from '~/lib/httpClient'

/**
 * Read-side browse / package-detail API.
 *
 * Types mirror the **real** Rust DTOs in `crates/server/src/browse.rs`:
 *
 *  - There are **no** `total_downloads` / per-version `downloads` fields:
 *    downloads are tracked server-side, but the browse API does not expose
 *    them. The UI therefore does not render download stats.
 *  - `delay_status` is `"available" | "delayed_until" | null` (snake_case enum).
 *  - `retention_status` is reserved and always `null`.
 *
 * Every `/browse/*` endpoint requires a signed-in user (401 otherwise); the
 * `_app` layout's login gate ensures these are only called with a session.
 * An offline hosted or group repository answers its package detail and its
 * per-repository search with 503 (see {@link isRepositoryOffline}).
 */

/** One readable repository (`GET /browse/repos` item) — a folder-view root. */
export interface BrowseRepo {
  /** Repository name. */
  name: string
  /** Repository kind: `hosted` | `proxy` | `group`. */
  kind: string
  /**
   * `false` while the repository is offline: a proxy still browses what it
   * cached, a hosted or group repository answers 503.
   */
  online: boolean
  /**
   * Repository format: `nuget`, `docker`, or a plugin format's id. A docker
   * repository holds images, browsed through `/browse/images` (see
   * `~/api/images`), not packages.
   */
  format: string
  /**
   * The address clients use for the repository (`<server><mount>/<name>`,
   * e.g. `https://forge.example.com/v3/internal`), for the connect snippets.
   * Absent for a docker repository (its registry comes with its images) and
   * for a format this server does not have installed.
   */
  url?: string
}

/**
 * The 503 an offline hosted or group repository answers browse requests with
 * during a maintenance window (`repository is offline`, with `Retry-After`).
 * Other 503s, such as a busy database, are not this.
 */
export function isRepositoryOffline(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    error.status === 503 &&
    /offline/i.test(error.body)
  )
}

/** One cross-repository search hit (`GET /browse/packages` item). */
export interface BrowseItem {
  /** Repository the package lives in. */
  repo: string
  /** Repository kind: `hosted` | `proxy` | `group`. */
  repo_kind: string
  /** Lowercased package id (the search / normalize key). */
  id: string
  /** Package id with its original casing. */
  original_id: string
  /** Highest-precedence visible version. */
  latest_version: string
  /** Whether the latest version is listed. */
  listed: boolean
}

/** `GET /browse/packages` response (paginated). */
export interface BrowseResult {
  /** Total hits across all visible repositories (pre-paging). */
  total: number
  /** The requested page. */
  items: BrowseItem[]
}

/** Proxy package-delay status of a version on the detail view. */
export type DelayStatus = 'available' | 'delayed_until'

/** One version on the package-detail view (`DetailVersion`). */
export interface DetailVersion {
  /** Normalized version. */
  version: string
  /** Version as originally published. */
  version_original: string
  /** Whether the version is listed. */
  listed: boolean
  /** `.nupkg` byte size, if a stored asset is known (null when not cached). */
  size: number | null
  /**
   * When the version reached Forge (`component.created_at`), if known: the
   * push time on a hosted repository, the first download on a proxy.
   */
  published_at: string | null
  /** Proxy package-delay status (`null` for hosted / group versions). */
  delay_status: DelayStatus | null
  /** When a delayed proxy version becomes available (`first_seen + delay`). */
  delayed_until?: string | null
  /** Retention status — reserved; always `null`. */
  retention_status: string | null
}

/** One dependency within a dependency group. */
export interface DetailDependency {
  id: string
  range: string | null
}

/** A dependency group (per target framework) for one version. */
export interface DetailDependencyGroup {
  target_framework: string | null
  dependencies: DetailDependency[]
}

/** `GET /browse/packages/{repo}/{id}` response. */
export interface PackageDetail {
  repo: string
  repo_kind: string
  id: string
  original_id: string
  versions: DetailVersion[]
  /** Dependency groups keyed by normalized version string. */
  dependency_groups_by_version: Record<string, DetailDependencyGroup[]>
}

/** Search parameters for the browse list (mirrors `BrowseQuery`). */
export interface SearchParams {
  /** Free-text query (matches package id substrings). Empty matches all. */
  q?: string
  /** Optional exact repository-name filter. */
  repo?: string
  /** Include prerelease versions in the latest-version computation. */
  prerelease?: boolean
  /** Pagination offset. */
  skip?: number
  /** Page size (backend clamps to [1, 100]; 0 / unset => 20). */
  take?: number
}

/**
 * Query-key factory for the package resource. Arrays from a single factory so
 * invalidation and `keepPreviousData` pagination share stable, structured keys.
 */
export const pkgKeys = {
  all: () => ['packages'] as const,
  repos: () => ['packages', 'repos'] as const,
  search: (params: SearchParams) =>
    ['packages', 'search', normalizeSearchKey(params)] as const,
  detail: (repo: string, id: string) =>
    ['packages', 'detail', repo, id] as const,
}

/** Stable, serializable key fragment for a search (defaults applied). */
function normalizeSearchKey(params: SearchParams) {
  return {
    q: params.q ?? '',
    repo: params.repo ?? null,
    prerelease: params.prerelease ?? false,
    skip: params.skip ?? 0,
    take: params.take ?? 0,
  }
}

/** Fetch the repositories the signed-in user may browse (sorted by name). */
export function fetchBrowseRepos(signal?: AbortSignal): Promise<BrowseRepo[]> {
  return httpClient.get<BrowseRepo[]>('/browse/repos', { signal })
}

/**
 * Shared TanStack Query options for the browsable repositories. Reused by the
 * `useBrowseRepos` hook and the repository screen's loader (which needs a
 * repository's format before it renders), so both read one cache entry.
 */
export const browseReposQueryOptions = queryOptions<BrowseRepo[], ApiError>({
  queryKey: pkgKeys.repos(),
  queryFn: ({ signal }) => fetchBrowseRepos(signal),
})

/** Fetch a page of cross-repository search hits. */
export function fetchPackages(
  params: SearchParams,
  signal?: AbortSignal,
): Promise<BrowseResult> {
  return httpClient.get<BrowseResult>('/browse/packages', {
    query: {
      q: params.q || undefined,
      repo: params.repo || undefined,
      prerelease: params.prerelease || undefined,
      skip: params.skip || undefined,
      take: params.take || undefined,
    },
    signal,
  })
}

/** Fetch package detail (versions + dependency groups) for one package. */
export function fetchPackageDetail(
  repo: string,
  id: string,
  signal?: AbortSignal,
): Promise<PackageDetail> {
  return httpClient.get<PackageDetail>(
    `/browse/packages/${encodeURIComponent(repo)}/${encodeURIComponent(id)}`,
    { signal },
  )
}
