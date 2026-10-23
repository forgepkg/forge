import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type { SelectorView } from '~/api/rbac'
import { useSelectors } from '~/queries/useRbac'
import {
  Button,
  CellActions,
  CellStack,
  Chip,
  Page,
  PageHeader,
  Panel,
  Skeleton,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/ui'
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
 * create and edit forms (New selector in the header), and deletes after a
 * confirmation dialog naming the grants that go with it.
 */
function SelectorsList() {
  const selectors = useSelectors()
  const [pendingDelete, setPendingDelete] = useState<SelectorView | null>(null)

  return (
    <Page>
      <PageHeader
        title="Content selectors"
        description="Narrow a grant to the packages whose names match. Excludes win over includes; an empty include list matches every package."
        actions={
          <Button variant="primary" icon="Plus" href="/manage/content-selectors/new">
            New selector
          </Button>
        }
      />

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
        <Skeleton variant="table" rows={3} columns={3} label="Loading content selectors…" />
      ) : (selectors.data?.length ?? 0) === 0 ? (
        <EmptyState title="No content selectors yet" icon="Filter">
          Create one to grant access to some packages of a repository only.
        </EmptyState>
      ) : (
        <Panel title="All selectors" count={selectors.data!.length} flush>
          <Table caption="Content selectors">
            <TableHead>
              <TableHeader>Name</TableHeader>
              <TableHeader>Includes</TableHeader>
              <TableHeader>Excludes</TableHeader>
              <TableHeader align="right" width="96px">
                <span className="fg-sr">Actions</span>
              </TableHeader>
            </TableHead>
            <TableBody>
              {selectors.data!.map((s) => (
                <TableRow key={s.id}>
                  <TableCell lead>
                    <CellStack sub={s.description || undefined}>
                      <Link
                        to="/manage/content-selectors/$selectorId"
                        params={{ selectorId: String(s.id) }}
                        className="fg-link-strong"
                      >
                        {s.name}
                      </Link>
                    </CellStack>
                  </TableCell>
                  <TableCell>
                    {s.includes.length === 0 ? (
                      <StatusBadge
                        tone="warn"
                        title="An empty include list matches every package"
                      >
                        every package
                      </StatusBadge>
                    ) : (
                      <Patterns patterns={s.includes} />
                    )}
                  </TableCell>
                  <TableCell>
                    {s.excludes.length === 0 ? (
                      <span className="text-ink-faint">—</span>
                    ) : (
                      <Patterns patterns={s.excludes} />
                    )}
                  </TableCell>
                  <TableCell align="right">
                    <CellActions>
                      <Button
                        size="sm"
                        variant="ghost"
                        icon="Trash"
                        aria-label={`Delete ${s.name}`}
                        onClick={() => setPendingDelete(s)}
                      >
                        Delete
                      </Button>
                    </CellActions>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}
    </Page>
  )
}

/** Glob patterns as mono chips. */
function Patterns({ patterns }: { patterns: string[] }) {
  return (
    <span className="fg-cell-badges">
      {patterns.map((p) => (
        <Chip key={p}>{p}</Chip>
      ))}
    </span>
  )
}
