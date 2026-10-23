import { Fragment, useRef, useState } from 'react'

import { encodeRawPath, rawFileUrl, type RawEntry } from '~/api/raw'
import { useRawDelete, useRawListing, useRawUpload } from '~/queries/useRawListing'
import { isRepositoryOffline } from '~/api/packages'
import type { ApiError } from '~/lib/httpClient'
import { formatBytes, formatDateTime } from '~/lib/oci'
import { Button } from '~/components/catalyst/button'
import { Subheading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { CommandSnippet, CopyButton } from '~/components/CopyButton'
import { ErrorState, RepositoryOfflineState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { ChevronIcon, FolderIcon } from '~/routes/Browse'

/**
 * The tree browser of a raw repository: the files and directories of one
 * directory (a page at a time), with
 *
 *  - a breadcrumb back up the path, and the directory's entries (a directory
 *    opens, a file shows its details: size, type, SHA-256, its URL, and the
 *    `curl` commands to download, check and upload it);
 *  - for a hosted repository, an upload of files into the directory and the
 *    delete of a file (the server decides whether the user may);
 *  - for administrators, the delete of a directory with everything below it
 *    (hosted, or a proxy's cached copies).
 *
 * The directory and page live in the URL (`path`, `after`); `onNavigate`
 * changes them. `url` is the repository's address (`/browse/repos`).
 */
export function RawBrowser({
  repo,
  kind,
  url,
  path,
  after,
  isAdmin,
  onNavigate,
}: {
  repo: string
  kind: string
  url?: string
  /** The directory: `""` or ending in `/`. */
  path: string
  after?: string
  isAdmin: boolean
  onNavigate: (path: string, after?: string) => void
}) {
  const listing = useRawListing(repo, path, after)
  const [selected, setSelected] = useState<RawEntry | null>(null)
  const hosted = kind === 'hosted'
  const base = url ?? `${window.location.origin}/raw/${repo}`

  function open(next: string, nextAfter?: string) {
    setSelected(null)
    onNavigate(next, nextAfter)
  }

  return (
    <div className="space-y-6">
      <PathCrumbs repo={repo} path={path} onOpen={(p) => open(p)} />

      {hosted && <UploadForm repo={repo} directory={path} />}

      <Listing
        repo={repo}
        path={path}
        after={after}
        listing={listing}
        selected={selected}
        onSelect={setSelected}
        onOpen={open}
      />

      {selected && (
        <FileDetails
          repo={repo}
          base={base}
          entry={selected}
          canDelete={hosted}
          onDeleted={() => setSelected(null)}
        />
      )}

      {isAdmin && kind !== 'group' && path !== '' && (
        <DirectoryDelete
          repo={repo}
          path={path}
          proxy={kind === 'proxy'}
          onDeleted={() => open(parentOf(path))}
        />
      )}

      <RawConnect base={base} path={path} canUpload={hosted} />
    </div>
  )
}

/** The directory above `path` (`""` or ending in `/`). */
export function parentOf(path: string): string {
  const trimmed = path.replace(/\/$/, '')
  const slash = trimmed.lastIndexOf('/')
  return slash < 0 ? '' : trimmed.slice(0, slash + 1)
}

/** The repository root, then one crumb per directory of `path`. */
function PathCrumbs({
  repo,
  path,
  onOpen,
}: {
  repo: string
  path: string
  onOpen: (path: string) => void
}) {
  const segments = path.split('/').filter((s) => s !== '')
  const crumbs = [
    { label: repo, path: '' },
    ...segments.map((label, i) => ({
      label,
      path: `${segments.slice(0, i + 1).join('/')}/`,
    })),
  ]
  return (
    <nav
      aria-label="Path"
      className="flex flex-wrap items-center gap-1 font-mono text-sm/6 text-zinc-500 dark:text-zinc-400"
    >
      {crumbs.map((crumb, i) => (
        <Fragment key={crumb.path}>
          {i > 0 && <span aria-hidden="true">/</span>}
          {i === crumbs.length - 1 ? (
            <span className="font-medium text-zinc-950 dark:text-white">{crumb.label}</span>
          ) : (
            <button
              type="button"
              onClick={() => onOpen(crumb.path)}
              className="hover:text-zinc-950 hover:underline dark:hover:text-white"
            >
              {crumb.label}
            </button>
          )}
        </Fragment>
      ))}
    </nav>
  )
}

function Listing({
  repo,
  path,
  after,
  listing,
  selected,
  onSelect,
  onOpen,
}: {
  repo: string
  path: string
  after?: string
  listing: ReturnType<typeof useRawListing>
  selected: RawEntry | null
  onSelect: (entry: RawEntry) => void
  onOpen: (path: string, after?: string) => void
}) {
  if (listing.isError && isRepositoryOffline(listing.error)) {
    return <RepositoryOfflineState onRetry={() => void listing.refetch()} />
  }
  if (listing.isError && listing.error?.status === 404) {
    return (
      <EmptyState title={path === '' ? 'No files' : 'No such directory'}>
        {path === ''
          ? 'This repository does not contain any files yet.'
          : 'Nothing is stored under this directory (any more).'}
      </EmptyState>
    )
  }
  if (listing.isError) {
    return (
      <ErrorState
        title="Could not load the directory"
        message={listing.error?.message}
        onRetry={() => void listing.refetch()}
      />
    )
  }
  if (listing.isLoading || !listing.data) {
    return <Text>Loading files…</Text>
  }
  const entries = listing.data.entries
  if (entries.length === 0 && !after) {
    return (
      <EmptyState title="No files">
        This repository does not contain any files yet.
      </EmptyState>
    )
  }
  return (
    <div className="space-y-3">
      <ul
        aria-label={`Contents of ${repo}/${path}`}
        className="divide-y divide-zinc-950/5 overflow-hidden rounded-xl ring-1 ring-zinc-950/5 dark:divide-white/5 dark:ring-white/10"
      >
        {path !== '' && (
          <li>
            <button
              type="button"
              onClick={() => onOpen(parentOf(path))}
              className="flex w-full items-center gap-3 px-4 py-2.5 text-left font-mono text-sm text-zinc-500 transition hover:bg-zinc-950/[2.5%] dark:text-zinc-400 dark:hover:bg-white/[2.5%]"
            >
              ../
            </button>
          </li>
        )}
        {entries.map((entry) =>
          entry.type === 'directory' ? (
            <li key={entry.path}>
              <button
                type="button"
                onClick={() => onOpen(entry.path)}
                className="group flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-zinc-950/[2.5%] dark:hover:bg-white/[2.5%]"
              >
                <FolderIcon />
                <span className="font-medium text-zinc-950 group-hover:text-sky-700 dark:text-white dark:group-hover:text-sky-400">
                  {entry.name}
                </span>
                <ChevronIcon />
              </button>
            </li>
          ) : (
            <li key={entry.path}>
              <button
                type="button"
                aria-pressed={selected?.path === entry.path}
                onClick={() => onSelect(entry)}
                className="group flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-zinc-950/[2.5%] aria-pressed:bg-sky-500/5 dark:hover:bg-white/[2.5%]"
              >
                <FileIcon />
                <span className="truncate font-medium text-zinc-950 group-hover:text-sky-700 dark:text-white dark:group-hover:text-sky-400">
                  {entry.name}
                </span>
                <span className="ml-auto flex shrink-0 items-center gap-4 text-sm text-zinc-500 dark:text-zinc-400">
                  <span>{formatBytes(entry.size)}</span>
                  <span className="hidden sm:inline" title={entry.last_modified}>
                    {formatDateTime(entry.last_modified)}
                  </span>
                </span>
              </button>
            </li>
          ),
        )}
      </ul>
      {(after || listing.data.next) && (
        <div className="flex items-center gap-3">
          {after && (
            <Button outline onClick={() => onOpen(path)}>
              First page
            </Button>
          )}
          {listing.data.next && (
            <Button outline onClick={() => onOpen(path, listing.data.next ?? undefined)}>
              Next page
            </Button>
          )}
        </div>
      )}
    </div>
  )
}

/** A file's details, its URL and commands, and its delete. */
function FileDetails({
  repo,
  base,
  entry,
  canDelete,
  onDeleted,
}: {
  repo: string
  base: string
  entry: RawEntry
  canDelete: boolean
  onDeleted: () => void
}) {
  const remove = useRawDelete(repo)
  const [confirming, setConfirming] = useState(false)
  const fileUrl = `${base}/${encodeRawPath(entry.path)}`
  return (
    <section
      aria-labelledby="raw-file"
      className="space-y-4 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <div className="flex flex-wrap items-center gap-3">
        <Subheading id="raw-file" className="font-mono">
          {entry.path}
        </Subheading>
        <a
          href={rawFileUrl(repo, entry.path)}
          download={entry.name}
          className="text-sm/6 text-sky-600 hover:underline dark:text-sky-400"
        >
          Download
        </a>
      </div>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm/6">
        <dt className="text-zinc-500 dark:text-zinc-400">Size</dt>
        <dd>{formatBytes(entry.size)}</dd>
        <dt className="text-zinc-500 dark:text-zinc-400">Type</dt>
        <dd className="font-mono">{entry.content_type}</dd>
        <dt className="text-zinc-500 dark:text-zinc-400">Last modified</dt>
        <dd>{formatDateTime(entry.last_modified)}</dd>
        <dt className="text-zinc-500 dark:text-zinc-400">SHA-256</dt>
        <dd className="flex min-w-0 items-center gap-1">
          <span className="truncate font-mono">{entry.sha256}</span>
          {entry.sha256 && <CopyButton value={entry.sha256} label="Copy SHA-256" />}
        </dd>
      </dl>
      <CommandSnippet label="URL" command={fileUrl} copyLabel="Copy URL" />
      <CommandSnippet
        label="Download it with curl"
        command={`curl -u <username>:<token> -O ${fileUrl}`}
        copyLabel="Copy download command"
      />
      {canDelete &&
        (confirming ? (
          <div className="flex flex-wrap items-center gap-3">
            <Text>Delete {entry.name}? This cannot be undone.</Text>
            <Button
              color="red"
              disabled={remove.isPending}
              onClick={() =>
                remove.mutate(entry.path, {
                  onSuccess: () => {
                    setConfirming(false)
                    onDeleted()
                  },
                })
              }
            >
              {remove.isPending ? 'Deleting…' : 'Delete file'}
            </Button>
            <Button plain onClick={() => setConfirming(false)}>
              Cancel
            </Button>
          </div>
        ) : (
          <Button outline onClick={() => setConfirming(true)}>
            Delete…
          </Button>
        ))}
      {remove.isError && (
        <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
          {deleteError(remove.error as ApiError)}
        </p>
      )}
    </section>
  )
}

function deleteError(error: ApiError): string {
  if (error.status === 403 || error.status === 401) {
    return 'You may not delete files in this repository.'
  }
  if (error.status === 405) return error.body || 'The repository is read-only.'
  return error.body || error.message
}

/** Upload files into `directory` of a hosted repository. */
function UploadForm({ repo, directory }: { repo: string; directory: string }) {
  const upload = useRawUpload(repo)
  const input = useRef<HTMLInputElement>(null)
  const [files, setFiles] = useState<File[]>([])
  const [done, setDone] = useState<string | null>(null)

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (files.length === 0) return
    setDone(null)
    upload.mutate(
      { directory, files },
      {
        onSuccess: (result) => {
          setDone(
            `Uploaded ${result.files.length} ${result.files.length === 1 ? 'file' : 'files'}.`,
          )
          setFiles([])
          if (input.current) input.current.value = ''
        },
      },
    )
  }

  return (
    <form
      onSubmit={submit}
      aria-label="Upload files"
      className="flex flex-wrap items-center gap-3 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <label className="text-sm/6 font-medium text-zinc-950 dark:text-white">
        Upload to <span className="font-mono">/{directory}</span>
        <input
          ref={input}
          type="file"
          multiple
          className="ml-3 text-sm/6 text-zinc-600 dark:text-zinc-400"
          onChange={(e) => setFiles(Array.from(e.target.files ?? []))}
        />
      </label>
      <Button type="submit" disabled={files.length === 0 || upload.isPending}>
        {upload.isPending ? 'Uploading…' : 'Upload'}
      </Button>
      {done && (
        <p role="status" className="w-full text-sm/6 text-emerald-700 dark:text-emerald-400">
          {done}
        </p>
      )}
      {upload.isError && (
        <p role="alert" className="w-full text-sm/6 text-red-600 dark:text-red-400">
          {uploadError(upload.error as ApiError)}
        </p>
      )}
    </form>
  )
}

function uploadError(error: ApiError): string {
  if (error.status === 401 || error.status === 403) {
    return error.body && error.status === 403 && error.body !== 'forbidden'
      ? error.body
      : 'You may not upload files to this repository.'
  }
  if (error.status === 409) {
    return `${error.body} — the repository does not allow redeploying it.`
  }
  if (error.status === 413) return error.body || 'A file is larger than the repository allows.'
  return error.body || error.message
}

/** Administrators: delete a directory and everything below it. */
function DirectoryDelete({
  repo,
  path,
  proxy,
  onDeleted,
}: {
  repo: string
  path: string
  proxy: boolean
  onDeleted: () => void
}) {
  const remove = useRawDelete(repo)
  const [confirming, setConfirming] = useState(false)
  return (
    <div className="flex flex-wrap items-center gap-3">
      {confirming ? (
        <>
          <Text>
            Delete <span className="font-mono">{path}</span> and every file below it
            {proxy ? ' from the cache' : ''}? This cannot be undone.
          </Text>
          <Button
            color="red"
            disabled={remove.isPending}
            onClick={() =>
              remove.mutate(path, {
                onSuccess: () => {
                  setConfirming(false)
                  onDeleted()
                },
              })
            }
          >
            {remove.isPending ? 'Deleting…' : 'Delete directory'}
          </Button>
          <Button plain onClick={() => setConfirming(false)}>
            Cancel
          </Button>
        </>
      ) : (
        <Button outline onClick={() => setConfirming(true)}>
          Delete this directory…
        </Button>
      )}
      {remove.isError && (
        <p role="alert" className="w-full text-sm/6 text-red-600 dark:text-red-400">
          {(remove.error as ApiError).body || (remove.error as Error).message}
        </p>
      )}
    </div>
  )
}

/** The `curl` commands for this directory. */
function RawConnect({
  base,
  path,
  canUpload,
}: {
  base: string
  path: string
  canUpload: boolean
}) {
  const dir = `${base}/${encodeRawPath(path)}`
  return (
    <section
      aria-labelledby="raw-connect"
      className="space-y-4 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <div>
        <Subheading id="raw-connect">Connect</Subheading>
        <Text className="mt-1">
          Use your username and an API token as the password (create one on
          the Tokens page). Every file has its checksums next to it:{' '}
          <span className="font-mono">.sha256</span>,{' '}
          <span className="font-mono">.sha512</span>,{' '}
          <span className="font-mono">.sha1</span> and{' '}
          <span className="font-mono">.md5</span>.
        </Text>
      </div>
      <CommandSnippet
        label="Download a file"
        command={`curl -u <username>:<token> -O ${dir}<file>`}
        copyLabel="Copy download command"
      />
      <CommandSnippet
        label="Check it against its checksum"
        command={`curl -u <username>:<token> ${dir}<file>.sha256 | sha256sum -c`}
        copyLabel="Copy checksum command"
      />
      {canUpload && (
        <CommandSnippet
          label="Upload a file"
          command={`curl -u <username>:<token> --upload-file <file> ${dir}<file>`}
          copyLabel="Copy upload command"
        />
      )}
      <CommandSnippet
        label="List the directory as JSON"
        command={`curl -u <username>:<token> -H 'Accept: application/json' ${dir}`}
        copyLabel="Copy list command"
      />
    </section>
  )
}

/** A document glyph for file rows. */
function FileIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 20 20"
      fill="currentColor"
      className="h-5 w-5 shrink-0 text-zinc-400 dark:text-zinc-500"
    >
      <path d="M3 3.5A1.5 1.5 0 0 1 4.5 2h6.879a1.5 1.5 0 0 1 1.06.44l4.122 4.12A1.5 1.5 0 0 1 17 7.622V16.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 3 16.5v-13Z" />
    </svg>
  )
}
