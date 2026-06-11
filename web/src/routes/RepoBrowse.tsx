import { useEffect, useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { BrowseItem } from '~/api/packages'
import { usePackageSearch } from '~/queries/usePackageSearch'
import { SearchBox } from '~/components/SearchBox'
import { Paginator } from '~/components/Paginator'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { FolderIcon } from './Browse'

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

  // Debounce the text input into the URL search param. This synchronizes a
  // controlled input with router URL state (an external system), resets paging
  // to the first page on a new query, and cleans up its timer — a legitimate
  // effect rather than render-derived state.
  useEffect(() => {
    if (input === q) return
    const t = setTimeout(() => {
      void navigate({ search: { q: input, prerelease, skip: 0 } })
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
      <div>
        <nav className="text-sm text-slate-500">
          <Link to="/" className="text-sky-700 hover:underline">
            Repositories
          </Link>
          <span className="mx-1">/</span>
          <span className="font-medium text-slate-700">{repo}</span>
        </nav>
        <h1 className="mt-2 text-2xl font-semibold">{repo}</h1>
        <p className="mt-1 text-slate-600">
          Search and browse the packages in this repository.
        </p>
      </div>

      <div className="space-y-3">
        <SearchBox value={input} onChange={setInput} />
        <label className="flex items-center gap-2 text-sm text-slate-600">
          <input
            type="checkbox"
            checked={prerelease}
            onChange={(e) => togglePrerelease(e.target.checked)}
            className="rounded border-slate-300"
          />
          Include prerelease versions
        </label>
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
    return <p className="text-slate-500">Loading packages…</p>
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
      <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white">
        {items.map((item) => (
          <li key={item.id}>
            <Link
              to="/packages/$repo/$id"
              params={{ repo: item.repo, id: item.id }}
              className="flex items-center gap-3 px-4 py-3 hover:bg-slate-50"
            >
              <FolderIcon />
              <span className="font-medium text-sky-700">
                {item.original_id}
              </span>
              <span className="ml-auto font-mono text-sm text-slate-600">
                {item.latest_version}
              </span>
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
