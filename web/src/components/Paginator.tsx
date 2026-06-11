import { Button } from '~/components/catalyst/button'

/**
 * Server-side paginator over a `{ total }` result. Pages are computed from
 * `skip` / `take`; navigation calls back with the new `skip`. Disabled at the
 * ends so the parent never requests an out-of-range page.
 */
export function Paginator({
  skip,
  take,
  total,
  onSkipChange,
}: {
  skip: number
  take: number
  total: number
  onSkipChange: (nextSkip: number) => void
}) {
  const pageCount = Math.max(1, Math.ceil(total / take))
  const currentPage = Math.floor(skip / take) + 1
  const atStart = skip <= 0
  const atEnd = skip + take >= total

  return (
    <nav
      className="flex items-center justify-between gap-4 text-sm/6 text-zinc-500 dark:text-zinc-400"
      aria-label="Pagination"
    >
      <span>
        {total === 0
          ? 'No results'
          : `Page ${currentPage} of ${pageCount} · ${total} total`}
      </span>
      <div className="flex items-center gap-2">
        <Button
          outline
          disabled={atStart}
          onClick={() => onSkipChange(Math.max(0, skip - take))}
        >
          Previous
        </Button>
        <Button outline disabled={atEnd} onClick={() => onSkipChange(skip + take)}>
          Next
        </Button>
      </div>
    </nav>
  )
}
