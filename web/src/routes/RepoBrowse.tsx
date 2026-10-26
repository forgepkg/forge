import { useEffect, useState, type ReactNode } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import {
  browseReposQueryOptions,
  isRepositoryOffline,
  type BrowseItem,
} from '~/api/packages'
import type { ImageItem, ImagesResult } from '~/api/images'
import { useBrowseRepos } from '~/queries/useBrowseRepos'
import { usePackageSearch } from '~/queries/usePackageSearch'
import { useImageSearch } from '~/queries/useImageSearch'
import { formatDateTime } from '~/lib/oci'
import { searchFlag, searchInt } from '~/lib/search'
import { SearchBox } from '~/components/SearchBox'
import { ErrorState, RepositoryOfflineState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { DockerConnect } from '~/components/DockerConnect'
import { PackageConnect } from '~/components/PackageConnect'
import { RawBrowser } from '~/components/RawBrowser'
import {
  Button,
  Checkbox,
  Columns,
  Icon,
  Page,
  PageHeader,
  Paginator,
  Panel,
  Skeleton,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Toolbar,
  Version,
  formatIcon,
} from '~/components/ui'
import { useMe } from '~/queries/useMe'

/**
 * Validated per-repo search params (shareable / deep-linkable URL state). All
 * keys are optional so links *to* the repo screen need not restate them; the
 * route component reads them with concrete defaults applied below.
 * (`prerelease` only applies to NuGet repositories; `path` and `after` — the
 * directory and the page — to raw ones.)
 */
interface RepoBrowseSearch {
  q?: string
  prerelease?: boolean
  skip?: number
  path?: string
  after?: string
}

const PAGE_SIZE = 20

export const Route = createFileRoute('/_app/repos/$repo')({
  validateSearch: (search: Record<string, unknown>): RepoBrowseSearch => {
    // Every key, undefined when absent or invalid: the router lays this over
    // the URL's own values, so a key left out would keep the URL's text, such
    // as the `prerelease=false&skip=0` the search box writes.
    const out: RepoBrowseSearch = {
      q: undefined,
      prerelease: undefined,
      skip: undefined,
      path: undefined,
      after: undefined,
    }
    if (typeof search.q === 'string' && search.q.length > 0) out.q = search.q
    if (searchFlag(search.prerelease)) out.prerelease = true
    const skip = searchInt(search.skip)
    if (skip !== undefined && skip > 0) out.skip = skip
    // A directory: no leading `/`, ending in `/`.
    if (typeof search.path === 'string' && search.path.length > 0) {
      const path = search.path.replace(/^\/+/, '')
      if (path !== '') out.path = path.endsWith('/') ? path : `${path}/`
    }
    if (typeof search.after === 'string' && search.after.length > 0) {
      out.after = search.after
    }
    return out
  },
  // The repository's format decides what this screen lists (NuGet packages or
  // docker images): have the (usually cached) repository list before the
  // first render instead of flashing the wrong screen, refreshed once when it
  // predates this repository or a repository change invalidated it (which
  // `ensureQueryData` alone would not refetch). Best effort — a failure is
  // shown, with a retry, by the component's own query.
  loader: async ({ context: { queryClient }, params }) => {
    try {
      const repos = await queryClient.ensureQueryData(browseReposQueryOptions)
      const invalidated =
        queryClient.getQueryState(browseReposQueryOptions.queryKey)?.isInvalidated === true
      if (invalidated || !repos.some((r) => r.name === params.repo)) {
        await queryClient.fetchQuery({ ...browseReposQueryOptions, staleTime: 0 })
      }
    } catch {
      // Rendered by the component (`useBrowseRepos`), with a retry.
    }
  },
  component: RepoBrowse,
})

/**
 * One repository's contents: the second level of the folder view, with the
 * per-repo search box — packages (plus the client snippets of the format:
 * `dotnet nuget`, or the URL) for a package repository,
 * images (plus the `docker login` / `pull` snippets) for a docker one. The query is debounced
 * into the URL search params (so it is shareable and survives reload) and fed
 * to `usePackageSearch` / `useImageSearch` scoped to this repository, which
 * keep the previous page visible while the next loads.
 */
function RepoBrowse() {
  const { repo } = Route.useParams()
  const raw = Route.useSearch()
  const q = raw.q ?? ''
  const prerelease = raw.prerelease ?? false
  const skip = raw.skip ?? 0
  const navigate = useNavigate({ from: Route.fullPath })
  const repos = useBrowseRepos()
  // Unknown here (not readable, or gone): treated as NuGet, whose search
  // answers with the server's verdict.
  const info = repos.data?.find((r) => r.name === repo)
  const isDocker = info?.format === 'docker'
  const isRaw = info?.format === 'raw'
  const me = useMe()

  // Local input mirrors the URL `q` but updates on every keystroke; a debounce
  // pushes it into the URL (and thus the query key) so we don't fetch per char.
  const [input, setInput] = useState(q)
  // The URL `q` the input was last synchronized with (or that we pushed).
  const [syncedQ, setSyncedQ] = useState(q)

  // The URL changed underneath the input — Back/Forward, a link, a reload of
  // another query: show that query. (Adjusting state while rendering, the
  // React-recommended way to reset state on a prop change.) Our own debounced
  // push records its value first, so it never clobbers newer keystrokes.
  // Without this the stale input re-pushed itself and Back got stuck.
  if (q !== syncedQ) {
    setSyncedQ(q)
    setInput(q)
  }

  // Debounce the text input into the URL search param. This synchronizes a
  // controlled input with router URL state (an external system), resets paging
  // to the first page on a new query, and cleans up its timer — a legitimate
  // effect rather than render-derived state. It *replaces* the history entry:
  // typing is one step, not one per pause, so Back leaves the search.
  useEffect(() => {
    if (input === q) return
    const t = setTimeout(() => {
      setSyncedQ(input)
      void navigate({
        search: { q: input, prerelease, skip: 0 },
        replace: true,
      })
    }, 300)
    return () => clearTimeout(t)
  }, [input, q, prerelease, navigate])

  function setSkip(nextSkip: number) {
    void navigate({ search: { q, prerelease, skip: nextSkip } })
  }

  function togglePrerelease(next: boolean) {
    void navigate({ search: { q, prerelease: next, skip: 0 } })
  }

  const isAdmin = me.data?.is_admin === true
  const description = isDocker
    ? 'Search and browse the images in this repository.'
    : isRaw
      ? 'Browse the files in this repository.'
      : 'Search and browse the packages in this repository.'

  return (
    <Page>
      <PageHeader
        title={repo}
        icon={info ? formatIcon(info.format) : undefined}
        crumbs={[{ label: 'Repositories', to: '/' }, { label: repo }]}
        description={description}
        kind={info?.kind}
        format={info?.format}
        actions={
          isAdmin && (
            <Button
              href={`/manage/repositories/${encodeURIComponent(repo)}`}
              icon="Sliders"
            >
              Settings
            </Button>
          )
        }
      >
        {info?.online === false && (
          <StatusBadge
            title={
              info.kind === 'proxy'
                ? 'Offline: shows only the packages Forge has cached'
                : 'Offline for maintenance'
            }
          >
            offline
          </StatusBadge>
        )}
      </PageHeader>

      {repos.isError ? (
        <ErrorState
          title="Could not load repository"
          message={repos.error?.message}
          onRetry={() => void repos.refetch()}
        />
      ) : repos.isLoading ? (
        <Skeleton variant="table" label="Loading repository…" />
      ) : isRaw && info ? (
        <RawBrowser
          repo={repo}
          kind={info.kind}
          url={info.url}
          path={raw.path ?? ''}
          after={raw.after}
          isAdmin={isAdmin}
          onNavigate={(path, after) =>
            void navigate({
              search: {
                ...(path !== '' ? { path } : {}),
                ...(after ? { after } : {}),
              },
            })
          }
        />
      ) : isDocker ? (
        <ImageBrowse
          repo={repo}
          repoKind={info?.kind}
          canPush={info?.kind === 'hosted'}
          q={q}
          skip={skip}
          onSkipChange={setSkip}
          toolbar={
            <SearchBox
              value={input}
              onChange={setInput}
              label="Search images"
              placeholder="Search images…"
              className="min-w-0 flex-[1_1_280px]"
            />
          }
        />
      ) : (
        <Columns
          aside={
            info?.url && (
              <PackageConnect
                format={info.format}
                repo={repo}
                url={info.url}
                canPush={info.kind === 'hosted'}
              />
            )
          }
          asideLabel="Connect"
        >
          <PackageBrowse
            repo={repo}
            q={q}
            prerelease={prerelease}
            skip={skip}
            onSkipChange={setSkip}
            toolbar={
              <>
                <SearchBox
                  value={input}
                  onChange={setInput}
                  className="min-w-0 flex-[1_1_280px]"
                />
                <Checkbox
                  label="Include prerelease versions"
                  checked={prerelease}
                  onChange={(checked) => togglePrerelease(checked)}
                />
              </>
            }
          />
        </Columns>
      )}
    </Page>
  )
}

/** A NuGet repository's packages (`usePackageSearch` scoped to the repo). */
function PackageBrowse({
  repo,
  q,
  prerelease,
  skip,
  onSkipChange,
  toolbar,
}: {
  repo: string
  q: string
  prerelease: boolean
  skip: number
  onSkipChange: (next: number) => void
  toolbar: ReactNode
}) {
  const search = usePackageSearch({ q, repo, prerelease, skip, take: PAGE_SIZE })
  return (
    <Panel
      title="Packages"
      count={search.data ? search.data.total : undefined}
      flush
    >
      <Toolbar>{toolbar}</Toolbar>
      <RepoBrowseResults
      isLoading={search.isLoading}
      isError={search.isError}
      offline={isRepositoryOffline(search.error)}
      errorMessage={search.error?.message}
      onRetry={() => void search.refetch()}
      total={search.data?.total ?? 0}
      items={search.data?.items ?? []}
      hasQuery={q.length > 0}
      skip={skip}
      onSkipChange={onSkipChange}
      />
    </Panel>
  )
}

function RepoBrowseResults({
  isLoading,
  isError,
  offline,
  errorMessage,
  onRetry,
  total,
  items,
  hasQuery,
  skip,
  onSkipChange,
}: {
  isLoading: boolean
  isError: boolean
  /** The search failed because the repository is offline (503). */
  offline: boolean
  errorMessage?: string
  onRetry: () => void
  total: number
  items: BrowseItem[]
  hasQuery: boolean
  skip: number
  onSkipChange: (next: number) => void
}) {
  if (isError && offline) {
    return <RepositoryOfflineState onRetry={onRetry} />
  }

  if (isError) {
    return (
      <ErrorState
        title="Could not load packages"
        message={errorMessage}
        onRetry={onRetry}
      />
    )
  }

  // First load (no previous page kept): the shape of the table.
  if (isLoading) {
    return <Skeleton variant="table" label="Loading packages…" />
  }

  // `skip` past the last result (an old bookmark, or packages deleted since):
  // the repository is not empty, only this page is.
  if (items.length === 0 && total > 0 && skip > 0) {
    return <PastLastPage noun="packages" total={total} />
  }

  if (items.length === 0) {
    return (
      <EmptyState title="No packages found" bordered={false}>
        {hasQuery
          ? 'Try a different search term or include prerelease versions.'
          : 'This repository does not contain any packages yet.'}
      </EmptyState>
    )
  }

  return (
    <>
      <Table caption="Packages">
        <TableHead>
          <TableHeader>Package</TableHeader>
          <TableHeader width="200px">Latest version</TableHeader>
        </TableHead>
        <TableBody>
          {items.map((item) => (
            <TableRow key={`${item.repo}/${item.id}`}>
              <TableCell lead>
                <Link
                  to="/packages/$repo/$id"
                  params={{ repo: item.repo, id: item.id }}
                  className="fg-link-strong"
                >
                  <Icon name="Package" size={16} />
                  <span>{item.original_id}</span>
                </Link>
              </TableCell>
              <TableCell>
                <Version value={item.latest_version} listed={item.listed} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Paginator skip={skip} take={PAGE_SIZE} total={total} onSkipChange={onSkipChange} />
    </>
  )
}

/**
 * A docker repository's images (`useImageSearch`) and, once the first page
 * names the registry, the connect snippets (login / pull; push for hosted).
 */
function ImageBrowse({
  repo,
  repoKind,
  canPush,
  q,
  skip,
  onSkipChange,
  toolbar,
}: {
  repo: string
  /** `hosted` | `proxy` | `group`; unknown while the repository list loads. */
  repoKind: string | undefined
  canPush: boolean
  q: string
  skip: number
  onSkipChange: (next: number) => void
  toolbar: ReactNode
}) {
  const search = useImageSearch({ repo, q, skip, take: PAGE_SIZE })
  return (
    <Columns
      aside={
        search.data && (
          <DockerConnect
            registry={search.data.registry}
            pullPrefix={search.data.pull_prefix}
            canPush={canPush}
          />
        )
      }
      asideLabel="Connect"
    >
      <Panel
        title="Images"
        count={search.data ? search.data.total : undefined}
        flush
      >
        <Toolbar>{toolbar}</Toolbar>
        <ImageBrowseResults
        isLoading={search.isLoading}
        isError={search.isError}
        offline={isRepositoryOffline(search.error)}
        errorMessage={search.error?.message}
        onRetry={() => void search.refetch()}
        result={search.data}
        repo={repo}
        repoKind={repoKind}
        hasQuery={q.length > 0}
        skip={skip}
          onSkipChange={onSkipChange}
        />
      </Panel>
    </Columns>
  )
}

function ImageBrowseResults({
  isLoading,
  isError,
  offline,
  errorMessage,
  onRetry,
  result,
  repo,
  repoKind,
  hasQuery,
  skip,
  onSkipChange,
}: {
  isLoading: boolean
  isError: boolean
  /** The listing failed because the repository is offline (503). */
  offline: boolean
  errorMessage?: string
  onRetry: () => void
  result: ImagesResult | undefined
  repo: string
  repoKind: string | undefined
  hasQuery: boolean
  skip: number
  onSkipChange: (next: number) => void
}) {
  if (isError && offline) {
    return <RepositoryOfflineState onRetry={onRetry} />
  }

  if (isError) {
    return (
      <ErrorState
        title="Could not load images"
        message={errorMessage}
        onRetry={onRetry}
      />
    )
  }

  if (isLoading) {
    return <Skeleton variant="table" label="Loading images…" />
  }

  const total = result?.total ?? 0
  const items = result?.items ?? []

  if (items.length === 0 && total > 0 && skip > 0) {
    return <PastLastPage noun="images" total={total} />
  }

  if (items.length === 0) {
    return (
      <EmptyState title="No images found" icon="Layers" bordered={false}>
        {hasQuery
          ? 'Try a different search term.'
          : 'This repository does not contain any images yet.'}
      </EmptyState>
    )
  }

  return (
    <>
      <Table caption="Images">
        <TableHead>
          <TableHeader>Image</TableHeader>
          <TableHeader align="right" width="90px">
            Tags
          </TableHeader>
          <TableHeader align="right" width="110px">
            Manifests
          </TableHeader>
          {/* A proxy's images carry their cache time, not a push (#248). */}
          {repoKind === 'proxy' ? (
            <TableHeader
              width="170px"
              hint="When Forge last cached a manifest of the image from the upstream"
            >
              Last cached
            </TableHeader>
          ) : (
            <TableHeader width="170px">Last pushed</TableHeader>
          )}
        </TableHead>
        <TableBody>
          {items.map((item) => (
            <ImageRow key={item.image} repo={repo} item={item} />
          ))}
        </TableBody>
      </Table>
      <Paginator skip={skip} take={PAGE_SIZE} total={total} onSkipChange={onSkipChange} />
    </>
  )
}

function ImageRow({ repo, item }: { repo: string; item: ImageItem }) {
  return (
    <TableRow>
      <TableCell lead>
        <Link
          to="/images/$repo/$"
          params={{ repo, _splat: item.image }}
          className="fg-link-strong"
        >
          <Icon name="Layers" size={16} />
          <span>{item.image}</span>
        </Link>
      </TableCell>
      <TableCell align="right">{item.tag_count}</TableCell>
      <TableCell align="right">{item.manifest_count}</TableCell>
      <TableCell nowrap>
        <span title={item.last_pushed_at}>{formatDateTime(item.last_pushed_at)}</span>
      </TableCell>
    </TableRow>
  )
}

/** The empty state of a `skip` past the last page, with a way back. */
function PastLastPage({ noun, total }: { noun: string; total: number }) {
  return (
    <EmptyState title={`No ${noun} on this page`} bordered={false}>
      There are {total} {total === 1 ? 'result' : 'results'}, all on earlier
      pages.{' '}
      <Link
        from={Route.fullPath}
        to="."
        search={(prev) => ({ ...prev, skip: undefined })}
        className="fg-link"
      >
        Back to page 1
      </Link>
    </EmptyState>
  )
}
