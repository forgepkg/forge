import { Fragment, useId, useRef, useState } from 'react'

import { encodeRawPath, rawFileUrl, type RawEntry } from '~/api/raw'
import { useRawDelete, useRawListing, useRawUpload } from '~/queries/useRawListing'
import { isRepositoryOffline } from '~/api/packages'
import type { ApiError } from '~/lib/httpClient'
import { formatBytes, formatDateTime } from '~/lib/oci'
import { ErrorState, RepositoryOfflineState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import {
  Button,
  Code,
  Columns,
  CommandSnippet,
  CopyButton,
  CopyField,
  Dialog,
  FactList,
  Icon,
  Notice,
  Panel,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Toolbar,
} from '~/components/ui'

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
    <Columns
      aside={
        <>
          {selected && (
            <FileDetails
              repo={repo}
              base={base}
              entry={selected}
              canDelete={hosted}
              onDeleted={() => setSelected(null)}
            />
          )}
          <RawConnect base={base} path={path} canUpload={hosted} />
        </>
      }
      asideLabel="File and commands"
    >
      <Panel
        title="Files"
        flush
        actions={
          isAdmin &&
          kind !== 'group' &&
          path !== '' && (
            <DirectoryDelete
              repo={repo}
              path={path}
              proxy={kind === 'proxy'}
              onDeleted={() => open(parentOf(path))}
            />
          )
        }
      >
        <Toolbar>
          <PathCrumbs repo={repo} path={path} onOpen={(p) => open(p)} />
        </Toolbar>
        <Listing
          repo={repo}
          path={path}
          after={after}
          listing={listing}
          selected={selected}
          onSelect={setSelected}
          onOpen={open}
        />
      </Panel>

      {hosted && <UploadForm repo={repo} directory={path} />}
    </Columns>
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
    <nav aria-label="Path" className="fg-crumbs font-mono">
      <ol>
        {crumbs.map((crumb, i) => (
          <Fragment key={crumb.path}>
            <li>
              {i > 0 && (
                <span className="fg-crumbs-sep" aria-hidden="true">
                  /
                </span>
              )}
              {i === crumbs.length - 1 ? (
                <span className="fg-crumbs-current" aria-current="location">
                  {crumb.label}
                </span>
              ) : (
                <button
                  type="button"
                  onClick={() => onOpen(crumb.path)}
                  className="fg-link cursor-pointer border-0 bg-transparent p-0 font-mono"
                >
                  {crumb.label}
                </button>
              )}
            </li>
          </Fragment>
        ))}
      </ol>
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
      <EmptyState
        title={path === '' ? 'No files' : 'No such directory'}
        icon="Folder"
        bordered={false}
      >
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
    return <Skeleton variant="table" label="Loading files…" />
  }
  const entries = listing.data.entries
  if (entries.length === 0 && !after) {
    return (
      <EmptyState title="No files" icon="Folder" bordered={false}>
        This repository does not contain any files yet.
      </EmptyState>
    )
  }
  return (
    <>
      <Table caption={`Contents of ${repo}/${path}`}>
        <TableHead>
          <TableHeader>Name</TableHeader>
          <TableHeader align="right" width="110px">
            Size
          </TableHeader>
          <TableHeader width="170px">Last modified</TableHeader>
        </TableHead>
        <TableBody>
          {path !== '' && (
            <TableRow>
              <TableCell lead colSpan={3}>
                <button type="button" onClick={() => onOpen(parentOf(path))} className={ROW_BUTTON}>
                  <Icon name="ArrowUp" size={16} />
                  <span className="font-mono">../</span>
                </button>
              </TableCell>
            </TableRow>
          )}
          {entries.map((entry) =>
            entry.type === 'directory' ? (
              <TableRow key={entry.path}>
                <TableCell lead colSpan={3}>
                  <button type="button" onClick={() => onOpen(entry.path)} className={ROW_BUTTON}>
                    <Icon name="Folder" size={16} />
                    <span>{entry.name}</span>
                  </button>
                </TableCell>
              </TableRow>
            ) : (
              <TableRow key={entry.path} selected={selected?.path === entry.path}>
                <TableCell lead>
                  <button
                    type="button"
                    aria-pressed={selected?.path === entry.path}
                    onClick={() => onSelect(entry)}
                    className={ROW_BUTTON}
                  >
                    <Icon name="File" size={16} />
                    <span className="truncate">{entry.name}</span>
                  </button>
                </TableCell>
                <TableCell align="right" nowrap>
                  {formatBytes(entry.size)}
                </TableCell>
                <TableCell nowrap>
                  <span title={entry.last_modified}>{formatDateTime(entry.last_modified)}</span>
                </TableCell>
              </TableRow>
            ),
          )}
        </TableBody>
      </Table>
      {(after || listing.data.next) && (
        <nav className="fg-pager" aria-label="Pagination">
          <span className="fg-pager-btns">
            {after && (
              <Button size="sm" icon="ChevronLeft" onClick={() => onOpen(path)}>
                First page
              </Button>
            )}
            {listing.data.next && (
              <Button
                size="sm"
                iconEnd="ChevronRight"
                onClick={() => onOpen(path, listing.data.next ?? undefined)}
              >
                Next page
              </Button>
            )}
          </span>
        </nav>
      )}
    </>
  )
}

/** An entry's name as a button that fills its cell, styled as the row's link. */
const ROW_BUTTON =
  'fg-link-strong w-full cursor-pointer border-0 bg-transparent p-0 text-left font-[inherit]'

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
    <Panel
      title={<span className="font-mono">{entry.path}</span>}
      actions={
        <Button
          href={rawFileUrl(repo, entry.path)}
          download={entry.name}
          size="sm"
          icon="Download"
        >
          Download
        </Button>
      }
    >
      <FactList
        items={[
          { term: 'Size', value: formatBytes(entry.size) },
          { term: 'Type', value: entry.content_type, mono: true },
          { term: 'Last modified', value: formatDateTime(entry.last_modified) },
          {
            term: 'SHA-256',
            mono: true,
            value: (
              <span className="flex min-w-0 items-center gap-1">
                <span className="min-w-0 break-all">{entry.sha256}</span>
                {entry.sha256 && <CopyButton value={entry.sha256} label="Copy SHA-256" />}
              </span>
            ),
          },
        ]}
      />
      <CopyField label="URL" value={fileUrl} copyLabel="Copy URL" />
      <CommandSnippet
        label="Download it with curl"
        command={`curl -u <username>:<token> -O ${fileUrl}`}
        copyLabel="Copy download command"
      />
      {canDelete && (
        <div>
          <Button variant="danger" size="sm" icon="Trash" onClick={() => setConfirming(true)}>
            Delete…
          </Button>
        </div>
      )}
      {remove.isError && (
        <Notice tone="danger">{deleteError(remove.error as ApiError)}</Notice>
      )}
      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        icon="Trash"
        tone="danger"
        title={`Delete ${entry.name}?`}
        description="Clients that download it from this URL start failing. This cannot be undone."
        confirmLabel={remove.isPending ? 'Deleting…' : 'Delete file'}
        confirmVariant="danger-solid"
        confirmDisabled={remove.isPending}
        onConfirm={() =>
          remove.mutate(entry.path, {
            onSuccess: () => {
              setConfirming(false)
              onDeleted()
            },
          })
        }
      />
    </Panel>
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

  const inputId = useId()
  return (
    <Panel
      as="form"
      onSubmit={submit}
      title="Upload files"
      description={
        <>
          Into <Code>/{directory}</Code>. A file with the name of one already
          there replaces it, if the repository allows redeploying.
        </>
      }
      footer={
        <Button
          type="submit"
          variant="primary"
          icon="Upload"
          disabled={files.length === 0 || upload.isPending}
        >
          {upload.isPending ? 'Uploading…' : 'Upload'}
        </Button>
      }
    >
      <div className="fg-field">
        <label htmlFor={inputId} className="fg-label">
          Files
        </label>
        <input
          id={inputId}
          ref={input}
          type="file"
          multiple
          className="text-ink-muted"
          onChange={(e) => setFiles(Array.from(e.target.files ?? []))}
        />
      </div>
      {done && <Notice tone="ok">{done}</Notice>}
      {upload.isError && (
        <Notice tone="danger">{uploadError(upload.error as ApiError)}</Notice>
      )}
    </Panel>
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
    <>
      <Button variant="danger" size="sm" icon="Trash" onClick={() => setConfirming(true)}>
        Delete this directory…
      </Button>
      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        icon="Trash"
        tone="danger"
        title={`Delete ${path}?`}
        description={
          proxy
            ? 'Every file below it goes from the cache; Forge fetches them from the upstream again when asked. This cannot be undone.'
            : 'Every file below it goes with it, and clients that download them start failing. This cannot be undone.'
        }
        confirmLabel={remove.isPending ? 'Deleting…' : 'Delete directory'}
        confirmVariant="danger-solid"
        confirmDisabled={remove.isPending}
        onConfirm={() =>
          remove.mutate(path, {
            onSuccess: () => {
              setConfirming(false)
              onDeleted()
            },
          })
        }
      >
        {remove.isError && (
          <Notice tone="danger">
            {(remove.error as ApiError).body || (remove.error as Error).message}
          </Notice>
        )}
      </Dialog>
    </>
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
    <Panel
      title="Connect"
      description={
        <>
          Use your username and an API token as the password; create one
          under Your tokens. Every file has its checksums next to it:{' '}
          <Code>.sha256</Code>, <Code>.sha512</Code>, <Code>.sha1</Code> and{' '}
          <Code>.md5</Code>.
        </>
      }
    >
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
    </Panel>
  )
}
