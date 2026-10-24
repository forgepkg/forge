import type { ReactNode } from 'react'
import { Link } from '@tanstack/react-router'

import {
  LEVEL_COVERS,
  type GrantView,
  type Level,
  type RoleView,
  type SelectorView,
} from '~/api/rbac'
import { Notice, StatusBadge, type Tone } from '~/components/ui'

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

/** `delete`, the level that removes versions, as a warning. */
const LEVEL_TONES: Record<Level, Tone> = {
  delete: 'warn',
  write: 'neutral',
  read: 'neutral',
}

/** A grant's level as a badge, titled with the Nexus actions it covers. */
export function LevelBadge({ level }: { level: Level }) {
  return (
    <StatusBadge
      tone={LEVEL_TONES[level] ?? 'neutral'}
      dot={false}
      title={`Covers ${LEVEL_COVERS[level]}`}
    >
      {level}
    </StatusBadge>
  )
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
    return <span className="font-medium text-ink">All repositories</span>
  }
  const name = names.get(id)
  if (name == null) {
    return <span className="fg-muted">repository #{id}</span>
  }
  return (
    <Link to="/manage/repositories/$repo" params={{ repo: name }} className="fg-link">
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
    return <span className="fg-muted">All packages</span>
  }
  const selector = selectors.get(id)
  if (selector == null) {
    const parts = [
      includes && includes.length > 0 ? includes.join(', ') : null,
      excludes && excludes.length > 0 ? `not ${excludes.join(', ')}` : null,
    ].filter(Boolean)
    return (
      <span className="fg-muted">
        selector #{id}
        {parts.length > 0 && ` (${parts.join('; ')})`}
      </span>
    )
  }
  return (
    <Link
      to="/manage/content-selectors/$selectorId"
      params={{ selectorId: String(id) }}
      className="fg-link"
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
    <Link to="/manage/roles/$roleId" params={{ roleId: String(id) }} className="fg-link">
      {role?.name ?? `role #${id}`}
    </Link>
  )
}

/**
 * A grant in words, for a confirmation that names what a deletion removes:
 * `write on nuget-internal (packages of acme)`.
 */
export function grantText(
  grant: Pick<GrantView, 'level' | 'repository_id' | 'selector_id'>,
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
  return `${grant.level} on ${repo}${packages}`
}

/** A refused write or a failed load, where it happened (`role="alert"`). */
export function InlineError({ children }: { children: ReactNode }) {
  return <Notice tone="danger">{children}</Notice>
}
