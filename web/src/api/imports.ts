import { httpClient } from '~/lib/httpClient'

/**
 * Imports from Nexus into a hosted repository
 * (`crates/server/src/admin/imports.rs`).
 *
 *  - `POST /admin/repositories/{name}/imports` checks the source first (the
 *    preflight: Nexus answers, the Nexus repository is hosted and of the same
 *    format, a Docker repository's registry API answers) and answers 400/502
 *    with the reason, or 409 while the repository has an import running.
 *  - An import scans Nexus (`phase: scan`), then copies the items it found
 *    (`phase: copy`). A dry run decides every item without writing a package.
 *  - The password is write-only (`has_password`) and is deleted when the
 *    import completes; a cancelled or failed import keeps it to be resumed.
 */

/** Formats an import copies (`crates/server/src/nexus_import/mod.rs`). */
export const IMPORT_FORMATS = ['nuget', 'docker']

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

/** A version Forge holds with other bytes. */
export type OnConflict = 'skip' | 'overwrite' | 'fail'

export interface ImportProgress {
  /** Items the scan found so far. */
  found: number
  pending: number
  imported: number
  replaced: number
  identical: number
  conflict: number
  failed: number
  /** Dry run: items that would be copied, and their size in Nexus. */
  planned: number
  planned_size: number
  /** Bytes downloaded from Nexus. */
  bytes_copied: number
  /** Every asset the scan saw in the Nexus repository, and their size. */
  assets: number
  size: number
}

export interface ImportView {
  id: number
  repository: string
  url: string
  source_repository: string
  registry_url: string | null
  username: string | null
  has_password: boolean
  on_conflict: OnConflict
  concurrency: number
  dry_run: boolean
  state: ImportState
  phase: 'scan' | 'copy'
  cancel_requested: boolean
  nexus_version: string | null
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
  /** `component`, or a Docker `manifest` Nexus holds by digest (a referrer). */
  kind: 'component' | 'manifest'
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
  url: string
  repository: string
  username?: string
  password?: string
  /** Docker only: the Nexus repository's registry API (its connector). */
  registry_url?: string
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
