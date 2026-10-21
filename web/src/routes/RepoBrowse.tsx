import { useEffect, useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { BrowseItem } from '~/api/packages'
import { usePackageSearch } from '~/queries/usePackageSearch'
import { Heading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { Checkbox, CheckboxField } from '~/components/catalyst/checkbox'
import { Label } from '~/components/catalyst/fieldset'
import { SearchBox } from '~/components/SearchBox'
import { Paginator } from '~/components/Paginator'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { Breadcrumbs } from '~/components/Breadcrumbs'
import { ChevronIcon, FolderIcon } from './Browse'

/**
 * Validated per-repo search params (shareable / deep-linkable URL state). All
 * keys are optional so links *to* the repo screen need not restate them; the
 * route component reads them with concrete defaults applied below.
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
  component: RepoBrowse,
})

/**
 * One repository's packages: the second level of the folder view, with the
 * per-repo search box. The query is debounced into the URL search params (so
 * it is shareable and survives reload) and fed to `usePackageSearch` scoped to
 * this repository, which keeps the previous page visible while the next loads.
 */
function RepoBrowse() {
  const { repo } = Route.useParams()
  const raw = Route.useSearch()
  const q = raw.q ?? ''
  const prerelease = raw.prerelease ?? false
  const skip = raw.skip ?? 0
  const navigate = useNavigate({ from: Route.fullPath })

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

  const search = usePackageSearch({ q, repo, prerelease, skip, take: PAGE_SIZE })

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
        <Heading>{repo}</Heading>
        <Text>Search and browse the packages in this repository.</Text>
      </div>

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

      <RepoBrowseResults
        isLoading={search.isLoading}
        isError={search.isError}
        errorMessage={search.error?.message}
        onRetry={() => void search.refetch()}
        total={search.data?.total ?? 0}
        items={search.data?.items ?? []}
        hasQuery={q.length > 0}
        skip={skip}
        onSkipChange={setSkip}
      />
    </section>
  )
}

function RepoBrowseResults({
  isLoading,
  isError,
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
  errorMessage?: string
  onRetry: () => void
  total: number
  items: BrowseItem[]
  hasQuery: boolean
  skip: number
  onSkipChange: (next: number) => void
}) {
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
    return (
      <EmptyState title="No packages on this page">
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
