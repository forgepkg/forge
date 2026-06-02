import type { MemberView } from '~/api/repositories'
import { RepoKindBadge } from '~/components/RepoKindBadge'

/**
 * Read-only ordered group-member list (plan §6, §Phase 4). Members are shown
 * sorted by descending priority — the highest-priority member wins ties per
 * slice-1 §7. Each row offers a remove action.
 *
 * **Reconciliation note:** slice-1's group API exposes only *add* (`POST .../members`
 * with a unique `priority`) and *remove* (`DELETE .../members/{member}`) — there
 * is **no** priority-update / reorder endpoint (`repository_dao` has
 * `add_group_member` / `remove_group_member` and no update). So this list does
 * not offer in-place reorder (which would require a priority-update call that
 * does not exist); changing a member's priority is expressed as remove + re-add
 * at the new priority via the add form. The priority is *displayed* here so the
 * winner ordering is visible, and the add form enforces uniqueness.
 */
export interface PriorityListProps {
  members: MemberView[]
  /** Disable the remove control while a mutation is in flight. */
  busy: boolean
  onRemove: (member: string) => void
}

/** Members sorted by descending priority (highest first = wins ties). */
export function sortByPriority(members: MemberView[]): MemberView[] {
  return [...members].sort((a, b) => b.priority - a.priority)
}

export function PriorityList({ members, busy, onRemove }: PriorityListProps) {
  const ordered = sortByPriority(members)

  if (ordered.length === 0) {
    return (
      <p className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-500">
        This group has no members yet. Add one below.
      </p>
    )
  }

  return (
    <ul className="divide-y divide-slate-100 rounded border border-slate-200">
      {ordered.map((m) => (
        <li key={m.name} className="flex items-center gap-3 px-3 py-2 text-sm">
          <span className="w-10 font-mono text-slate-500" aria-label="priority">
            {m.priority}
          </span>
          <span className="flex items-center gap-2">
            <span className="font-medium text-slate-800">{m.name}</span>
            <RepoKindBadge kind={m.kind} />
          </span>
          <button
            type="button"
            disabled={busy}
            onClick={() => onRemove(m.name)}
            className="ml-auto text-red-700 hover:underline disabled:opacity-60"
          >
            Remove
          </button>
        </li>
      ))}
    </ul>
  )
}
