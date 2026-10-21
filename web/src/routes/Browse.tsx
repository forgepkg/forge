import { createFileRoute, Link } from '@tanstack/react-router'

import { useBrowseRepos } from '~/queries/useBrowseRepos'
import { Badge } from '~/components/catalyst/badge'
import { Heading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { RepoKindBadge } from '~/components/RepoKindBadge'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'

export const Route = createFileRoute('/_app/')({
  component: Browse,
})

/**
 * Browse root: the repositories the signed-in user may read, rendered as the
 * top level of the folder view (repository → packages → versions). Search is
 * per repository and lives on the repository screen, not here. An offline
 * repository carries an "offline" badge.
 */
function Browse() {
  const repos = useBrowseRepos()

  return (
    <section className="space-y-6">
      <div>
        <Heading>Browse</Heading>
        <Text className="mt-1">
          Open a repository to browse and search its packages.
        </Text>
      </div>

      {repos.isError ? (
        <ErrorState
          title="Could not load repositories"
          message={repos.error?.message}
          onRetry={() => void repos.refetch()}
        />
      ) : repos.isLoading ? (
        <Text>Loading repositories…</Text>
      ) : (repos.data?.length ?? 0) === 0 ? (
        <EmptyState title="No repositories">
          You have no readable repositories yet. Ask an administrator to grant
          you access.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-zinc-950/5 overflow-hidden rounded-xl ring-1 ring-zinc-950/5 dark:divide-white/5 dark:ring-white/10">
          {repos.data!.map((repo) => (
            <li key={repo.name}>
              <Link
                to="/repos/$repo"
                params={{ repo: repo.name }}
                className="group flex items-center gap-3 px-4 py-3.5 transition hover:bg-zinc-950/[2.5%] dark:hover:bg-white/[2.5%]"
              >
                <FolderIcon />
                <span className="font-medium text-zinc-950 group-hover:text-sky-700 dark:text-white dark:group-hover:text-sky-400">
                  {repo.name}
                </span>
                <RepoKindBadge kind={repo.kind} />
                {repo.online === false && (
                  <Badge
                    color="zinc"
                    title={
                      repo.kind === 'proxy'
                        ? 'Offline: shows only the packages Forge has cached'
                        : 'Offline for maintenance'
                    }
                  >
                    offline
                  </Badge>
                )}
                <ChevronIcon />
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
      className="h-5 w-5 shrink-0 text-amber-500 dark:text-amber-400"
    >
      <path d="M2 5.5A1.5 1.5 0 0 1 3.5 4h4.086a1.5 1.5 0 0 1 1.06.44l1.415 1.414a.5.5 0 0 0 .353.146H16.5A1.5 1.5 0 0 1 18 7.5v7A1.5 1.5 0 0 1 16.5 16h-13A1.5 1.5 0 0 1 2 14.5v-9Z" />
    </svg>
  )
}

/** Right-pointing chevron shown at the end of folder rows. */
export function ChevronIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 20 20"
      fill="currentColor"
      className="ml-auto h-4 w-4 shrink-0 text-zinc-400 transition group-hover:translate-x-0.5 group-hover:text-zinc-600 dark:text-zinc-500 dark:group-hover:text-zinc-300"
    >
      <path
        fillRule="evenodd"
        d="M7.21 14.77a.75.75 0 0 1 .02-1.06L11.168 10 7.23 6.29a.75.75 0 1 1 1.04-1.08l4.5 4.25a.75.75 0 0 1 0 1.08l-4.5 4.25a.75.75 0 0 1-1.06-.02Z"
        clipRule="evenodd"
      />
    </svg>
  )
}
