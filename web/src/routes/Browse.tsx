import { useEffect, useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { BrowseItem } from '~/api/packages'
import { usePackageSearch } from '~/queries/usePackageSearch'
import { RepoKindBadge } from '~/components/RepoKindBadge'
import { SearchBox } from '~/components/SearchBox'
import { Paginator } from '~/components/Paginator'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'

/**
 * Validated browse search params (shareable / deep-linkable URL state). All
 * keys are optional so links *to* Browse (`to="/"`) need not restate them; the
 * route component reads them with concrete defaults applied below.
 */
interface BrowseSearch {
  q?: string
  prerelease?: boolean
  skip?: number
}

const PAGE_SIZE = 20

export const Route = createFileRoute('/_app/')({
  validateSearch: (search: Record<string, unknown>): BrowseSearch => {
    const out: BrowseSearch = {}
    if (typeof search.q === 'string' && search.q.length > 0) out.q = search.q
    if (search.prerelease === true || search.prerelease === 'true') {
      out.prerelease = true
    }
    if (typeof search.skip === 'number' && search.skip > 0) {
      out.skip = Math.floor(search.skip)
    }
    return out
  },
  component: Browse,
})

/**
 * Cross-repository package browse + search (plan §4, §Phase 3). The query is
 * debounced into the URL search params (so it is shareable and survives reload)
 * and fed to `usePackageSearch`, which keeps the previous page visible while the
 * next loads. Reachable by any reader; no admin gate.
 */
function Browse() {
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

  const search = usePackageSearch({ q, prerelease, skip, take: PAGE_SIZE })

  function setSkip(nextSkip: number) {
    void navigate({ search: { q, prerelease, skip: nextSkip } })
  }

  function togglePrerelease(next: boolean) {
    void navigate({ search: { q, prerelease: next, skip: 0 } })
  }

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Browse</h1>
        <p className="mt-1 text-slate-600">
          Search and browse packages across all repositories you can read.
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

      <BrowseResults
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

function BrowseResults({
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
          : 'No readable repositories contain any packages yet.'}
      </EmptyState>
    )
  }

  return (
    <div className="space-y-4">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-left text-slate-500">
            <th className="py-2 pr-4 font-medium">Package</th>
            <th className="py-2 pr-4 font-medium">Repository</th>
            <th className="py-2 pr-4 font-medium">Latest version</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr
              key={`${item.repo}/${item.id}`}
              className="border-b border-slate-100 last:border-0"
            >
              <td className="py-2 pr-4">
                <Link
                  to="/packages/$repo/$id"
                  params={{ repo: item.repo, id: item.id }}
                  className="font-medium text-sky-700 hover:underline"
                >
                  {item.original_id}
                </Link>
              </td>
              <td className="py-2 pr-4">
                <span className="flex items-center gap-2">
                  <span className="text-slate-700">{item.repo}</span>
                  <RepoKindBadge kind={item.repo_kind} />
                </span>
              </td>
              <td className="py-2 pr-4 font-mono text-slate-600">
                {item.latest_version}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <Paginator
        skip={skip}
        take={PAGE_SIZE}
        total={total}
        onSkipChange={onSkipChange}
      />
    </div>
  )
}
