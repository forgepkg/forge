import { httpClient } from '~/lib/httpClient'

/**
 * Imports into a hosted repository from another server, read through the
 * format's own protocol: a NuGet feed or a registry, or a raw repository
 * (`crates/server/src/admin/imports.rs`).
 *
 *  - `POST /admin/repositories/{name}/imports` checks the source first (the
 *    preflight: a feed's service index resolves and its search answers, a
 *    registry answers its API and serves a catalog, or a raw repository
 *    serves a listing, another Forge's or Nexus' asset listing; an import
 *    that names its packages, images or paths needs none of it) and answers
 *    400/502 with the reason, or 409 while the repository has an import
 *    running.
 *  - An import scans the source (`phase: scan`), then copies the items it
 *    found (`phase: copy`). A dry run decides every item without writing a
 *    package.
 *  - The password is write-only (`has_password`) and is deleted when the
 *    import completes; a cancelled or failed import keeps it to be resumed.
 */

/** Formats an import copies (`crates/server/src/import/mod.rs`). */
export const IMPORT_FORMATS = ['nuget', 'docker', 'raw']

/** `queued` → `running` → `completed` | `failed` | `cancelled`. */
export type ImportState =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'

/** What became of an item. */
export type ItemState =
  | 'pending'
  | 'imported'
  | 'replaced'
  | 'identical'
  | 'conflict'
  | 'failed'
  | 'planned'

/** A version (raw: a file) Forge holds with other bytes. */
export type OnConflict = 'skip' | 'overwrite' | 'fail'

/**
 * What the scan walks: a feed's `search`, a registry's `catalog`, Nexus'
 * asset listing (`assets`) or another Forge's JSON listing (`directories`)
 * of a raw repository, or the `names` the import gives.
 */
export type ImportListing =
  | 'search'
  | 'catalog'
  | 'assets'
  | 'directories'
  | 'names'

export interface ImportProgress {
  /** Items the scan found so far. */
  found: number
  pending: number
  imported: number
  replaced: number
  identical: number
  conflict: number
  failed: number
  /** Dry run: items that would be copied, and their size where the source says. */
  planned: number
  planned_size: number
  /** Bytes downloaded from the source. */
  bytes_copied: number
}

export interface ImportView {
  id: number
  repository: string
  /** The source: a feed's service index, or a registry. */
  url: string
  /** The package ids or images it copies; `null`: every one the source lists. */
  names: string[] | null
  username: string | null
  has_password: boolean
  on_conflict: OnConflict
  concurrency: number
  dry_run: boolean
  state: ImportState
  phase: 'scan' | 'copy'
  cancel_requested: boolean
  /** The `Server` header the source answered the preflight with. */
  source_server: string | null
  /** How many packages the feed's search reported in the preflight. */
  source_total: number | null
  listing: ImportListing
  last_error: string | null
  created_by: number | null
  created_at: string
  started_at: string | null
  finished_at: string | null
  updated_at: string
  progress: ImportProgress
}

export interface ImportItem {
  id: number
  /**
   * `component` (a version, a tag), a Docker `manifest` held by digest (a
   * referrer), or a raw `file` (`name` its path, `version` empty).
   */
  kind: 'component' | 'manifest' | 'file'
  name: string
  version: string
  state: ItemState
  detail: string | null
  size: number | null
  bytes_copied: number
  published_at: string | null
  downloaded_at: string | null
  uploader: string | null
  attempts: number
  updated_at: string
}

/** `POST /admin/repositories/{name}/imports` (unknown fields are refused). */
export interface CreateImport {
  /** A feed's service index (`…/index.json`), a registry, or a raw repository. */
  url: string
  /**
   * The package ids or images to copy, instead of every one the source lists
   * (raw: the paths of the files, below `url`).
   */
  names?: string[]
  username?: string
  password?: string
  on_conflict?: OnConflict
  concurrency?: number
  dry_run?: boolean
}

/** `POST …/imports/{id}/resume`. */
export interface ResumeImport {
  password?: string
  retry_failed?: boolean
  items?: number[]
}

export const importKeys = {
  all: (repo: string) => ['imports', repo] as const,
  items: (repo: string, id: number, state: string) =>
    ['imports', repo, id, 'items', state] as const,
}

function base(repo: string): string {
  return `/admin/repositories/${encodeURIComponent(repo)}/imports`
}

/** Whether an import waits for, or is held by, a worker. */
export function isActive(i: ImportView): boolean {
  return i.state === 'queued' || i.state === 'running'
}

export function fetchImports(
  repo: string,
  signal?: AbortSignal,
): Promise<ImportView[]> {
  return httpClient.get<ImportView[]>(base(repo), { signal })
}

export function createImport(
  repo: string,
  body: CreateImport,
): Promise<ImportView> {
  return httpClient.post<ImportView>(base(repo), body)
}

export function fetchImportItems(
  repo: string,
  id: number,
  state: ItemState | undefined,
  signal?: AbortSignal,
): Promise<ImportItem[]> {
  return httpClient.get<ImportItem[]>(`${base(repo)}/${id}/items`, {
    signal,
    query: { state, limit: 200 },
  })
}

export function cancelImport(repo: string, id: number): Promise<ImportView> {
  return httpClient.post<ImportView>(`${base(repo)}/${id}/cancel`)
}

export function resumeImport(
  repo: string,
  id: number,
  body: ResumeImport,
): Promise<ImportView> {
  return httpClient.post<ImportView>(`${base(repo)}/${id}/resume`, body)
}

export function deleteImport(repo: string, id: number): Promise<void> {
  return httpClient.delete<void>(`${base(repo)}/${id}`)
}
