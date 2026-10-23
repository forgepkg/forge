import { Link } from '@tanstack/react-router'

import type { Action, GrantView, RoleView, SelectorView } from '~/api/rbac'
import { Badge } from '~/components/catalyst/badge'

/**
 * Display pieces shared by the RBAC screens. The API names repositories,
 * selectors and roles by id; these resolve the ids against the lists the
 * screens already load, and say so plainly when an id is not among them.
 */

/** A repository by id → its name, for the labels below. */
export type RepoNames = ReadonlyMap<number, string>

export function repoNames(
  repos: ReadonlyArray<{ id: number; name: string }> | undefined,
): RepoNames {
  return new Map((repos ?? []).map((r) => [r.id, r.name]))
}

export function byId<T extends { id: number }>(
  items: ReadonlyArray<T> | undefined,
): ReadonlyMap<number, T> {
  return new Map((items ?? []).map((i) => [i.id, i]))
}

const ACTION_COLORS: Record<Action, 'red' | 'amber' | 'sky' | 'zinc'> = {
  admin: 'red',
  delete: 'amber',
  write: 'sky',
  read: 'zinc',
}

export function ActionBadge({ action }: { action: Action }) {
  return <Badge color={ACTION_COLORS[action] ?? 'zinc'}>{action}</Badge>
}

/** The repository a grant covers: every repository, a linked name, or an id. */
export function RepositoryLabel({
  id,
  names,
}: {
  id: number | null
  names: RepoNames
}) {
  if (id == null) {
    return <span className="font-medium">All repositories</span>
  }
  const name = names.get(id)
  if (name == null) {
    return (
      <span className="text-zinc-500 dark:text-zinc-400">repository #{id}</span>
    )
  }
  return (
    <Link
      to="/manage/repositories/$repo"
      params={{ repo: name }}
      className="font-mono text-sky-600 hover:underline dark:text-sky-400"
    >
      {name}
    </Link>
  )
}

/**
 * The packages a grant covers: all of them, or those of a content selector
 * (linked by name; its patterns when the selector is not in the list).
 */
export function SelectorLabel({
  id,
  selectors,
  includes,
  excludes,
}: {
  id: number | null
  selectors: ReadonlyMap<number, SelectorView>
  includes?: string[] | null
  excludes?: string[] | null
}) {
  if (id == null) {
    return <span className="text-zinc-500 dark:text-zinc-400">All packages</span>
  }
  const selector = selectors.get(id)
  if (selector == null) {
    const parts = [
      includes && includes.length > 0 ? includes.join(', ') : null,
      excludes && excludes.length > 0 ? `not ${excludes.join(', ')}` : null,
    ].filter(Boolean)
    return (
      <span className="text-zinc-500 dark:text-zinc-400">
        selector #{id}
        {parts.length > 0 && ` (${parts.join('; ')})`}
      </span>
    )
  }
  return (
    <Link
      to="/manage/content-selectors/$selectorId"
      params={{ selectorId: String(id) }}
      className="text-sky-600 hover:underline dark:text-sky-400"
    >
      {selector.name}
    </Link>
  )
}

/** A role linked by name (or its id when not in the list). */
export function RoleLabel({
  id,
  roles,
}: {
  id: number
  roles: ReadonlyMap<number, RoleView>
}) {
  const role = roles.get(id)
  return (
    <Link
      to="/manage/roles/$roleId"
      params={{ roleId: String(id) }}
      className="font-medium text-sky-600 hover:underline dark:text-sky-400"
    >
      {role?.name ?? `role #${id}`}
    </Link>
  )
}

/**
 * A grant in words, for a confirmation that names what a deletion removes:
 * `write on nuget-internal (packages of acme)`.
 */
export function grantText(
  grant: Pick<GrantView, 'action' | 'repository_id' | 'selector_id'>,
  names: RepoNames,
  selectors: ReadonlyMap<number, SelectorView>,
): string {
  const repo =
    grant.repository_id == null
      ? 'all repositories'
      : (names.get(grant.repository_id) ?? `repository #${grant.repository_id}`)
  const packages =
    grant.selector_id == null
      ? ''
      : ` (packages of ${selectors.get(grant.selector_id)?.name ?? `selector #${grant.selector_id}`})`
  return `${grant.action} on ${repo}${packages}`
}

export function InlineError({ children }: { children: React.ReactNode }) {
  return (
    <p
      role="alert"
      className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
    >
      {children}
    </p>
  )
}
