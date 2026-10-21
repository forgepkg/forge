import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { RepoView } from '~/api/repositories'
import {
  useDeleteRepository,
  useRepositories,
} from '~/queries/useRepositories'
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
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
import { RepoKindBadge } from '~/components/RepoKindBadge'
import { RepoFormatBadge } from '~/components/RepoFormatBadge'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'

export const Route = createFileRoute('/_app/manage/repositories')({
  component: RepositoriesList,
})

/**
 * Admin repositories list (plan §Phase 4). Lists every repository with its
 * format (NuGet / Docker), kind, online / anonymous-read flags, and links to
 * edit / (for groups) members / delete. Delete surfaces the server's conflict
 * message inline (a hosted repo with packages refuses deletion).
 */
function RepositoriesList() {
  const repos = useRepositories()
  const del = useDeleteRepository()
  const [pendingDelete, setPendingDelete] = useState<string | null>(null)

  function confirmDelete(name: string) {
    del.mutate(name, {
      onSettled: () => setPendingDelete(null),
    })
  }

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <Heading>Repositories</Heading>
          <Text className="mt-1">
            Create and manage hosted, proxy, and group repositories — NuGet
            feeds and Docker registries.
          </Text>
        </div>
        <Button href="/manage/repositories/new">New repository</Button>
      </div>

      {del.isError && (
        <p
          role="alert"
          className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
        >
          {del.error.body || del.error.message}
        </p>
      )}

      {repos.isError ? (
        <ErrorState
          title="Could not load repositories"
          message={repos.error?.message}
          onRetry={() => void repos.refetch()}
        />
      ) : repos.isLoading ? (
        <Text>Loading repositories…</Text>
      ) : (repos.data?.length ?? 0) === 0 ? (
        <EmptyState title="No repositories yet">
          Create your first repository to start serving packages.
        </EmptyState>
      ) : (
        <Table striped>
          <TableHead>
            <TableRow>
              <TableHeader>Name</TableHeader>
              <TableHeader>Format</TableHeader>
              <TableHeader>Kind</TableHeader>
              <TableHeader>Status</TableHeader>
              <TableHeader>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {repos.data!.map((repo) => (
              <RepoRow
                key={repo.id}
                repo={repo}
                isDeleting={del.isPending && pendingDelete === repo.name}
                pendingDelete={pendingDelete === repo.name}
                onRequestDelete={() => setPendingDelete(repo.name)}
                onCancelDelete={() => setPendingDelete(null)}
                onConfirmDelete={() => confirmDelete(repo.name)}
              />
            ))}
          </TableBody>
        </Table>
      )}
    </section>
  )
}

function RepoRow({
  repo,
  isDeleting,
  pendingDelete,
  onRequestDelete,
  onCancelDelete,
  onConfirmDelete,
}: {
  repo: RepoView
  isDeleting: boolean
  pendingDelete: boolean
  onRequestDelete: () => void
  onCancelDelete: () => void
  onConfirmDelete: () => void
}) {
  const navigate = useNavigate()
  return (
    <TableRow>
      <TableCell>
        <button
          type="button"
          onClick={() =>
            void navigate({
              to: '/manage/repositories/$repo',
              params: { repo: repo.name },
            })
          }
          className="font-medium text-sky-600 hover:underline dark:text-sky-400"
        >
          {repo.name}
        </button>
      </TableCell>
      <TableCell>
        <RepoFormatBadge format={repo.format} />
      </TableCell>
      <TableCell>
        <RepoKindBadge kind={repo.kind} />
      </TableCell>
      <TableCell>
        {repo.online ? (
          <Badge color="emerald">online</Badge>
        ) : (
          <Badge color="zinc">offline</Badge>
        )}
        {repo.anonymous_read && (
          <span className="ml-2 text-xs text-zinc-500 dark:text-zinc-400">
            anonymous read
          </span>
        )}
      </TableCell>
      <TableCell>
        <span className="flex items-center gap-3">
          <Link
            to="/manage/repositories/$repo"
            params={{ repo: repo.name }}
            className="text-sky-600 hover:underline dark:text-sky-400"
          >
            Edit
          </Link>
          {repo.kind === 'group' && (
            <Link
              to="/manage/repositories/$repo/members"
              params={{ repo: repo.name }}
              className="text-sky-600 hover:underline dark:text-sky-400"
            >
              Members
            </Link>
          )}
          {pendingDelete ? (
            <span className="flex items-center gap-2">
              <button
                type="button"
                onClick={onConfirmDelete}
                disabled={isDeleting}
                className="font-medium text-red-600 hover:underline disabled:opacity-60 dark:text-red-400"
              >
                {isDeleting ? 'Deleting…' : 'Confirm'}
              </button>
              <button
                type="button"
                onClick={onCancelDelete}
                className="text-zinc-500 hover:underline dark:text-zinc-400"
              >
                Cancel
              </button>
            </span>
          ) : (
            <button
              type="button"
              onClick={onRequestDelete}
              className="font-medium text-red-600 hover:underline dark:text-red-400"
            >
              Delete
            </button>
          )}
        </span>
      </TableCell>
    </TableRow>
  )
}
