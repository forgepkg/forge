import { Link } from '@tanstack/react-router'

import type { DetailDependencyGroup } from '~/api/packages'
import { Text } from '~/components/catalyst/text'

/**
 * Dependency groups for a single package version, grouped by target framework.
 * Each dependency links to its own package within the same repository (the most
 * useful default; cross-repo resolution is not modeled in the browse API).
 */
export function DependencyGroups({
  repo,
  groups,
}: {
  repo: string
  groups: DetailDependencyGroup[]
}) {
  if (groups.length === 0) {
    return <Text>No dependencies.</Text>
  }

  return (
    <div className="space-y-4">
      {groups.map((group, idx) => (
        <div key={group.target_framework ?? `group-${idx}`}>
          <h4 className="text-xs/6 font-semibold tracking-wide text-zinc-500 uppercase dark:text-zinc-400">
            {group.target_framework ?? 'Any framework'}
          </h4>
          {group.dependencies.length === 0 ? (
            <p className="mt-1 text-sm/6 text-zinc-400 dark:text-zinc-500">
              No dependencies.
            </p>
          ) : (
            <ul className="mt-1 space-y-1 text-sm/6">
              {group.dependencies.map((dep) => (
                <li key={dep.id} className="flex items-baseline gap-2">
                  <Link
                    to="/packages/$repo/$id"
                    params={{ repo, id: dep.id.toLowerCase() }}
                    className="font-mono text-sky-600 hover:underline dark:text-sky-400"
                  >
                    {dep.id}
                  </Link>
                  {dep.range && (
                    <span className="font-mono text-xs text-zinc-500 dark:text-zinc-400">
                      {dep.range}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  )
}
