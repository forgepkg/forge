import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { RepoView } from '~/api/repositories'
import {
  useDeleteRepository,
  useRepositories,
} from '~/queries/useRepositories'
import { RepoKindBadge } from '~/components/RepoKindBadge'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'

export const Route = createFileRoute('/_app/admin/repositories')({
  component: RepositoriesList,
})

/**
 * Admin repositories list (plan §Phase 4). Lists every repository with its kind,
 * online / anonymous-read flags, and links to edit / (for groups) members /
 * delete. Delete surfaces the server's conflict message inline (a hosted repo
 * with packages refuses deletion).
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Repositories</h1>
          <p className="mt-1 text-slate-600">
            Create and manage hosted, proxy, and group repositories.
          </p>
        </div>
        <Link
          to="/admin/repositories/new"
          className="rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700"
        >
          New repository
        </Link>
      </div>

      {del.isError && (
        <p
          role="alert"
          className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700"
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
        <p className="text-slate-500">Loading repositories…</p>
      ) : (repos.data?.length ?? 0) === 0 ? (
        <EmptyState title="No repositories yet">
          Create your first repository to start serving packages.
        </EmptyState>
      ) : (
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-slate-200 text-left text-slate-500">
              <th className="py-2 pr-4 font-medium">Name</th>
              <th className="py-2 pr-4 font-medium">Kind</th>
              <th className="py-2 pr-4 font-medium">Status</th>
              <th className="py-2 pr-4 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
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
          </tbody>
        </table>
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
    <tr className="border-b border-slate-100 last:border-0">
      <td className="py-2 pr-4">
        <button
          type="button"
          onClick={() =>
            void navigate({
              to: '/admin/repositories/$repo',
              params: { repo: repo.name },
            })
          }
          className="font-medium text-sky-700 hover:underline"
        >
          {repo.name}
        </button>
      </td>
      <td className="py-2 pr-4">
        <RepoKindBadge kind={repo.kind} />
      </td>
      <td className="py-2 pr-4 text-slate-600">
        <span className={repo.online ? 'text-emerald-700' : 'text-slate-400'}>
          {repo.online ? 'online' : 'offline'}
        </span>
        {repo.anonymous_read && (
          <span className="ml-2 text-xs text-slate-400">anonymous read</span>
        )}
      </td>
      <td className="py-2 pr-4">
        <span className="flex items-center gap-3">
          <Link
            to="/admin/repositories/$repo"
            params={{ repo: repo.name }}
            className="text-sky-700 hover:underline"
          >
            Edit
          </Link>
          {repo.kind === 'group' && (
            <Link
              to="/admin/repositories/$repo/members"
              params={{ repo: repo.name }}
              className="text-sky-700 hover:underline"
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
                className="text-red-700 hover:underline disabled:opacity-60"
              >
                {isDeleting ? 'Deleting…' : 'Confirm'}
              </button>
              <button
                type="button"
                onClick={onCancelDelete}
                className="text-slate-500 hover:underline"
              >
                Cancel
              </button>
            </span>
          ) : (
            <button
              type="button"
              onClick={onRequestDelete}
              className="text-red-700 hover:underline"
            >
              Delete
            </button>
          )}
        </span>
      </td>
    </tr>
  )
}
