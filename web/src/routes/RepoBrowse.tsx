import { useEffect, useState } from 'react'
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
import { Heading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { Checkbox, CheckboxField } from '~/components/catalyst/checkbox'
import { Label } from '~/components/catalyst/fieldset'
import { SearchBox } from '~/components/SearchBox'
import { Paginator } from '~/components/Paginator'
import { ErrorState, RepositoryOfflineState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { Breadcrumbs } from '~/components/Breadcrumbs'
import { RepoKindBadge } from '~/components/RepoKindBadge'
import { RepoFormatBadge } from '~/components/RepoFormatBadge'
import { DockerConnect } from '~/components/DockerConnect'
import { ChevronIcon, FolderIcon } from './Browse'

/**
 * Validated per-repo search params (shareable / deep-linkable URL state). All
 * keys are optional so links *to* the repo screen need not restate them; the
 * route component reads them with concrete defaults applied below.
 * (`prerelease` only applies to NuGet repositories.)
 */
interface RepoBrowseSearch {
  q?: string
  prerelease?: boolean
  skip?: number
}

const PAGE_SIZE = 20

export const Route = createFileRoute('/_app/repos/$repo')({
  validateSearch: (search: Record<string, unknown>): RepoBrowseSearch => {
    const out: RepoBrowseSearch = {}
    if (typeof search.q === 'string' && search.q.length > 0) out.q = search.q
    if (search.prerelease === true || search.prerelease === 'true') {
      out.prerelease = true
    }
    if (typeof search.skip === 'number' && search.skip > 0) {
      out.skip = Math.floor(search.skip)
    }
    return out
  },
  // The repository's format decides what this screen lists (NuGet packages or
  // docker images): have the (usually cached) repository list before the
  // first render instead of flashing the wrong screen, refreshed once when it
  // predates this repository. Best effort — a failure is shown, with a retry,
  // by the component's own query.
  loader: async ({ context: { queryClient }, params }) => {
    try {
      const repos = await queryClient.ensureQueryData(browseReposQueryOptions)
      if (!repos.some((r) => r.name === params.repo)) {
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
 * per-repo search box — packages for a NuGet repository, images (plus the
 * `docker login` / `pull` snippets) for a docker one. The query is debounced
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

  return (
    <section className="space-y-6">
      <div className="space-y-2">
        <Breadcrumbs
          items={[{ label: 'Repositories', to: '/' }, { label: repo }]}
        />
        <div className="flex flex-wrap items-center gap-3">
          <Heading>{repo}</Heading>
          {info && (
            <span className="flex items-center gap-2">
              <RepoKindBadge kind={info.kind} />
              <RepoFormatBadge format={info.format} />
            </span>
          )}
        </div>
        <Text>
          {isDocker
            ? 'Search and browse the images in this repository.'
            : 'Search and browse the packages in this repository.'}
        </Text>
      </div>

      {repos.isError ? (
        <ErrorState
          title="Could not load repository"
          message={repos.error?.message}
          onRetry={() => void repos.refetch()}
        />
      ) : repos.isLoading ? (
        <Text>Loading repository…</Text>
      ) : isDocker ? (
        <>
          <SearchBox
            value={input}
            onChange={setInput}
            label="Search images"
            placeholder="Search images…"
          />
          <ImageBrowse
            repo={repo}
            canPush={info?.kind === 'hosted'}
            q={q}
            skip={skip}
            onSkipChange={setSkip}
          />
        </>
      ) : (
        <>
          <div className="space-y-3">
            <SearchBox value={input} onChange={setInput} />
            <CheckboxField>
              <Checkbox
                checked={prerelease}
                onChange={(checked) => togglePrerelease(checked)}
              />
              <Label>Include prerelease versions</Label>
            </CheckboxField>
          </div>

          <PackageBrowse
            repo={repo}
            q={q}
            prerelease={prerelease}
            skip={skip}
            onSkipChange={setSkip}
          />
        </>
      )}
    </section>
  )
}

/** A NuGet repository's packages (`usePackageSearch` scoped to the repo). */
function PackageBrowse({
  repo,
  q,
  prerelease,
  skip,
  onSkipChange,
}: {
  repo: string
  q: string
  prerelease: boolean
  skip: number
  onSkipChange: (next: number) => void
}) {
  const search = usePackageSearch({ q, repo, prerelease, skip, take: PAGE_SIZE })
  return (
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

  // First load (no previous page kept): a simple skeleton-ish hint.
  if (isLoading) {
    return <Text>Loading packages…</Text>
  }

  // `skip` past the last result (an old bookmark, or packages deleted since):
  // the repository is not empty, only this page is.
  if (items.length === 0 && total > 0 && skip > 0) {
    return <PastLastPage noun="packages" total={total} />
  }

  if (items.length === 0) {
    return (
      <EmptyState title="No packages found">
        {hasQuery
          ? 'Try a different search term or include prerelease versions.'
          : 'This repository does not contain any packages yet.'}
      </EmptyState>
    )
  }

  return (
    <div className="space-y-4">
      <ul className="divide-y divide-zinc-950/5 overflow-hidden rounded-xl ring-1 ring-zinc-950/5 dark:divide-white/5 dark:ring-white/10">
        {items.map((item) => (
          <li key={item.id}>
            <Link
              to="/packages/$repo/$id"
              params={{ repo: item.repo, id: item.id }}
              className="group flex items-center gap-3 px-4 py-3.5 transition hover:bg-zinc-950/[2.5%] dark:hover:bg-white/[2.5%]"
            >
              <FolderIcon />
              <span className="font-medium text-zinc-950 group-hover:text-sky-700 dark:text-white dark:group-hover:text-sky-400">
                {item.original_id}
              </span>
              <span className="ml-auto font-mono text-sm text-zinc-500 dark:text-zinc-400">
                {item.latest_version}
              </span>
              <ChevronIcon />
            </Link>
          </li>
        ))}
      </ul>

      <Paginator
        skip={skip}
        take={PAGE_SIZE}
        total={total}
        onSkipChange={onSkipChange}
      />
    </div>
  )
}

/**
 * A docker repository's images (`useImageSearch`) and, once the first page
 * names the registry, the connect snippets (login / pull; push for hosted).
 */
function ImageBrowse({
  repo,
  canPush,
  q,
  skip,
  onSkipChange,
}: {
  repo: string
  canPush: boolean
  q: string
  skip: number
  onSkipChange: (next: number) => void
}) {
  const search = useImageSearch({ repo, q, skip, take: PAGE_SIZE })
  return (
    <>
      <ImageBrowseResults
        isLoading={search.isLoading}
        isError={search.isError}
        offline={isRepositoryOffline(search.error)}
        errorMessage={search.error?.message}
        onRetry={() => void search.refetch()}
        result={search.data}
        repo={repo}
        hasQuery={q.length > 0}
        skip={skip}
        onSkipChange={onSkipChange}
      />
      {search.data && (
        <DockerConnect
          registry={search.data.registry}
          pullPrefix={search.data.pull_prefix}
          canPush={canPush}
        />
      )}
    </>
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
    return <Text>Loading images…</Text>
  }

  const total = result?.total ?? 0
  const items = result?.items ?? []

  if (items.length === 0 && total > 0 && skip > 0) {
    return <PastLastPage noun="images" total={total} />
  }

  if (items.length === 0) {
    return (
      <EmptyState title="No images found">
        {hasQuery
          ? 'Try a different search term.'
          : 'This repository does not contain any images yet.'}
      </EmptyState>
    )
  }

  return (
    <div className="space-y-4">
      <ul className="divide-y divide-zinc-950/5 overflow-hidden rounded-xl ring-1 ring-zinc-950/5 dark:divide-white/5 dark:ring-white/10">
        {items.map((item) => (
          <ImageRow key={item.image} repo={repo} item={item} />
        ))}
      </ul>

      <Paginator
        skip={skip}
        take={PAGE_SIZE}
        total={total}
        onSkipChange={onSkipChange}
      />
    </div>
  )
}

function ImageRow({ repo, item }: { repo: string; item: ImageItem }) {
  return (
    <li>
      <Link
        to="/images/$repo/$"
        params={{ repo, _splat: item.image }}
        className="group flex items-center gap-3 px-4 py-3.5 transition hover:bg-zinc-950/[2.5%] dark:hover:bg-white/[2.5%]"
      >
        <ImageIcon />
        <span className="font-medium text-zinc-950 group-hover:text-sky-700 dark:text-white dark:group-hover:text-sky-400">
          {item.image}
        </span>
        <span className="ml-auto flex items-center gap-3 text-sm text-zinc-500 dark:text-zinc-400">
          <span>
            {plural(item.tag_count, 'tag')} ·{' '}
            {plural(item.manifest_count, 'manifest')}
          </span>
          <span className="hidden sm:inline" title={item.last_pushed_at}>
            pushed {formatDateTime(item.last_pushed_at)}
          </span>
        </span>
        <ChevronIcon />
      </Link>
    </li>
  )
}

/** "1 tag" / "3 tags". */
function plural(n: number, noun: string): string {
  return `${n} ${n === 1 ? noun : `${noun}s`}`
}

/** The empty state of a `skip` past the last page, with a way back. */
function PastLastPage({ noun, total }: { noun: string; total: number }) {
  return (
    <EmptyState title={`No ${noun} on this page`}>
      There are {total} {total === 1 ? 'result' : 'results'}, all on earlier
      pages.{' '}
      <Link
        from={Route.fullPath}
        to="."
        search={(prev) => ({ ...prev, skip: undefined })}
        className="text-sky-600 hover:underline dark:text-sky-400"
      >
        Back to page 1
      </Link>
    </EmptyState>
  )
}

/** A small container-image glyph (a cube) for image rows. */
function ImageIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 20 20"
      fill="currentColor"
      className="h-5 w-5 shrink-0 text-cyan-600 dark:text-cyan-400"
    >
      <path d="M10.362 1.093a.75.75 0 0 0-.724 0L2.523 5.018 10 9.143l7.477-4.125-7.115-3.925ZM18 6.443l-7.25 4v8.25l6.862-3.786A.75.75 0 0 0 18 14.25V6.443ZM9.25 18.693v-8.25l-7.25-4v7.807a.75.75 0 0 0 .388.657l6.862 3.786Z" />
    </svg>
  )
}
