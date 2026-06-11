import { createFileRoute, Link } from '@tanstack/react-router'

import { useBrowseRepos } from '~/queries/useBrowseRepos'
import { RepoKindBadge } from '~/components/RepoKindBadge'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'

export const Route = createFileRoute('/_app/')({
  component: Browse,
})

/**
 * Browse root: the repositories the signed-in user may read, rendered as the
 * top level of the folder view (repository → packages → versions). Search is
 * per repository and lives on the repository screen, not here.
 */
function Browse() {
  const repos = useBrowseRepos()

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Browse</h1>
        <p className="mt-1 text-slate-600">
          Open a repository to browse and search its packages.
        </p>
      </div>

      {repos.isError ? (
        <ErrorState
          title="Could not load repositories"
          message={repos.error?.message}
          onRetry={() => void repos.refetch()}
        />
      ) : repos.isLoading ? (
        <p className="text-slate-500">Loading repositories…</p>
      ) : (repos.data?.length ?? 0) === 0 ? (
        <EmptyState title="No repositories">
          You have no readable repositories yet. Ask an administrator to grant
          you access.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white">
          {repos.data!.map((repo) => (
            <li key={repo.name}>
              <Link
                to="/repos/$repo"
                params={{ repo: repo.name }}
                className="flex items-center gap-3 px-4 py-3 hover:bg-slate-50"
              >
                <FolderIcon />
                <span className="font-medium text-sky-700">{repo.name}</span>
                <RepoKindBadge kind={repo.kind} />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

/** A small folder glyph reinforcing the file-browser metaphor. */
export function FolderIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 20 20"
      fill="currentColor"
      className="h-5 w-5 shrink-0 text-amber-500"
    >
      <path d="M2 5.5A1.5 1.5 0 0 1 3.5 4h4.086a1.5 1.5 0 0 1 1.06.44l1.415 1.414a.5.5 0 0 0 .353.146H16.5A1.5 1.5 0 0 1 18 7.5v7A1.5 1.5 0 0 1 16.5 16h-13A1.5 1.5 0 0 1 2 14.5v-9Z" />
    </svg>
  )
}
