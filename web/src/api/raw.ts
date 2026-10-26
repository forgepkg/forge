import { httpClient } from '~/lib/httpClient'

/**
 * Raw (generic file) repositories: files under arbitrary paths, served at
 * `/repository/<repo>/<path>` (`crates/formats/raw`).
 *
 *  - A directory's listing is `GET /repository/<repo>/<dir>/` as JSON, a page at a
 *    time (`after` names the entry a page starts after, `next` the next
 *    page's). The session reads it like any client; package selectors and
 *    group membership apply.
 *  - The web UI changes files through `/browse/raw/<repo>/files` with its
 *    session (the repository URL itself takes an API token): a multipart upload into a
 *    directory, a delete of a file. A directory is deleted through the admin
 *    API (`DELETE /admin/repositories/<repo>/files?path=<dir>/`).
 *
 * Directories are `""` (the root) or paths ending in `/`.
 */

/** One entry of a listing (`listing::Entry`). */
export interface RawEntry {
  /** The name in its directory; a directory's ends in `/`. */
  name: string
  /** The full path; a directory's ends in `/`. */
  path: string
  type: 'file' | 'directory'
  size?: number
  content_type?: string
  /** Lowercase hex SHA-256 (the `ETag`). */
  sha256?: string
  /** When the content was last deployed (`Last-Modified`). */
  last_modified?: string
  last_downloaded?: string | null
}

/** A page of a directory listing (`listing::Page`). */
export interface RawListing {
  repository: string
  /** The directory: `""` or ending in `/`. */
  path: string
  entries: RawEntry[]
  /** The `after` of the next page; `null` on the last. */
  next: string | null
}

/** What became of one uploaded file (`upload::Stored`). */
export interface RawStored {
  path: string
  size: number
  sha256: string
  status: 'created' | 'replaced' | 'unchanged'
}

/** A path percent-encoded for a URL, segment by segment. */
export function encodeRawPath(path: string): string {
  return path.split('/').map(encodeURIComponent).join('/')
}

/** The address of `path` in repository `repo` (relative to the server). */
export function rawFileUrl(repo: string, path: string): string {
  return `/repository/${encodeURIComponent(repo)}/${encodeRawPath(path)}`
}

export const rawKeys = {
  all: ['raw'] as const,
  repo: (repo: string) => [...rawKeys.all, repo] as const,
  listing: (repo: string, path: string, after: string | undefined) =>
    [...rawKeys.repo(repo), path, after ?? ''] as const,
}

/** `GET /repository/<repo>/<path>` as JSON. */
export function fetchRawListing(
  repo: string,
  path: string,
  after: string | undefined,
  signal?: AbortSignal,
): Promise<RawListing> {
  return httpClient.get<RawListing>(rawFileUrl(repo, path), {
    query: { format: 'json', after, limit: 100 },
    signal,
  })
}

/** `POST /browse/raw/<repo>/files?directory=<directory>`: upload `files`. */
export function uploadRawFiles(
  repo: string,
  directory: string,
  files: File[],
): Promise<{ files: RawStored[] }> {
  const form = new FormData()
  for (const file of files) form.append('file', file, file.name)
  return httpClient.postForm<{ files: RawStored[] }>(
    `/browse/raw/${encodeURIComponent(repo)}/files`,
    form,
    { query: { directory } },
  )
}

/** `DELETE /browse/raw/<repo>/files?path=<path>`: delete a file. */
export function deleteRawFile(repo: string, path: string): Promise<void> {
  return httpClient.delete<void>(`/browse/raw/${encodeURIComponent(repo)}/files`, {
    query: { path },
  })
}

/**
 * `DELETE /admin/repositories/<repo>/files?path=<dir>/` (admins): delete a
 * directory and every file below it.
 */
export function deleteRawDirectory(
  repo: string,
  path: string,
): Promise<{ deleted: number }> {
  return httpClient.delete<{ deleted: number }>(
    `/admin/repositories/${encodeURIComponent(repo)}/files`,
    { query: { path } },
  )
}
