import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type { SelectorView } from '~/api/rbac'
import { useSelectors } from '~/queries/useRbac'
import { Badge } from '~/components/catalyst/badge'
import { Heading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/catalyst/table'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { SelectorDeleteConfirm } from '~/components/SelectorDeleteConfirm'

export const Route = createFileRoute('/_app/manage/content-selectors')({
  component: SelectorsList,
})

/**
 * Admin content-selector screen. A selector is a named set of include and
 * exclude globs on the package name; a grant that names one covers only the
 * packages it matches. Lists every selector with its patterns, links to the
 * create and edit forms, and deletes after a confirmation naming the grants
 * that go with it.
 */
function SelectorsList() {
  const selectors = useSelectors()
  const [pendingDelete, setPendingDelete] = useState<SelectorView | null>(null)

  return (
    <section className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <Heading>Content selectors</Heading>
          <Text className="mt-1">
            Narrow a grant to the packages whose names match. Excludes win over
            includes; an empty include list matches every package.
          </Text>
        </div>
        <Link
          to="/manage/content-selectors/new"
          className="shrink-0 rounded-lg bg-zinc-900 px-3 py-1.5 text-sm/6 font-semibold text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-950 dark:hover:bg-zinc-200"
        >
          New selector
        </Link>
      </div>

      {pendingDelete && (
        <SelectorDeleteConfirm
          key={pendingDelete.id}
          selector={pendingDelete}
          onCancel={() => setPendingDelete(null)}
          onDeleted={() => setPendingDelete(null)}
        />
      )}

      {selectors.isError ? (
        <ErrorState
          title="Could not load content selectors"
          message={selectors.error?.message}
          onRetry={() => void selectors.refetch()}
        />
      ) : selectors.isLoading ? (
        <Text>Loading content selectors…</Text>
      ) : (selectors.data?.length ?? 0) === 0 ? (
        <EmptyState title="No content selectors yet">
          Create one to grant access to some packages of a repository only.
        </EmptyState>
      ) : (
        <Table striped>
          <TableHead>
            <TableRow>
              <TableHeader>Name</TableHeader>
              <TableHeader>Includes</TableHeader>
              <TableHeader>Excludes</TableHeader>
              <TableHeader>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {selectors.data!.map((s) => (
              <TableRow key={s.id}>
                <TableCell>
                  <Link
                    to="/manage/content-selectors/$selectorId"
                    params={{ selectorId: String(s.id) }}
                    className="font-medium text-sky-600 hover:underline dark:text-sky-400"
                  >
                    {s.name}
                  </Link>
                  {s.description && (
                    <div className="text-zinc-500 dark:text-zinc-400">
                      {s.description}
                    </div>
                  )}
                </TableCell>
                <TableCell>
                  {s.includes.length === 0 ? (
                    <Badge color="amber">every package</Badge>
                  ) : (
                    <Patterns patterns={s.includes} />
                  )}
                </TableCell>
                <TableCell>
                  {s.excludes.length === 0 ? (
                    <span className="text-zinc-400 dark:text-zinc-500">—</span>
                  ) : (
                    <Patterns patterns={s.excludes} />
                  )}
                </TableCell>
                <TableCell>
                  <button
                    type="button"
                    onClick={() => setPendingDelete(s)}
                    className="font-medium text-red-600 hover:underline dark:text-red-400"
                    aria-label={`Delete ${s.name}`}
                  >
                    Delete
                  </button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </section>
  )
}

function Patterns({ patterns }: { patterns: string[] }) {
  return (
    <span className="flex flex-wrap gap-1 font-mono">
      {patterns.map((p) => (
        <code
          key={p}
          className="rounded bg-zinc-950/5 px-1 text-xs/5 dark:bg-white/10"
        >
          {p}
        </code>
      ))}
    </span>
  )
}
