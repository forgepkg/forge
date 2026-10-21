import type { MemberView } from '~/api/repositories'
import { Checkbox } from '~/components/catalyst/checkbox'
import { RepoKindBadge } from '~/components/RepoKindBadge'

/**
 * Ordered group-member list (plan §6, §Phase 4). Members are shown sorted by
 * descending priority — the highest-priority member wins ties per slice-1 §7.
 * Each row offers an owner toggle and a remove action.
 *
 * **Reconciliation note:** the group API has *add* (`POST .../members` with a
 * unique `priority`), *remove* (`DELETE .../members/{member}`) and an
 * owner-only update (`PATCH .../members/{member}` `{"owner": bool}`) — there
 * is **no** priority-update / reorder endpoint. So this list does not offer
 * in-place reorder; changing a member's priority is expressed as remove +
 * re-add at the new priority via the add form. The priority is *displayed*
 * here so the winner ordering is visible, and the add form enforces
 * uniqueness. A proxy cannot own package ids, so its toggle is disabled.
 */
export interface PriorityListProps {
  members: MemberView[]
  /** Disable the row controls while a mutation is in flight. */
  busy: boolean
  onRemove: (member: string) => void
  onToggleOwner: (member: string, owner: boolean) => void
}

/** Members sorted by descending priority (highest first = wins ties). */
export function sortByPriority(members: MemberView[]): MemberView[] {
  return [...members].sort((a, b) => b.priority - a.priority)
}

export function PriorityList({
  members,
  busy,
  onRemove,
  onToggleOwner,
}: PriorityListProps) {
  const ordered = sortByPriority(members)

  if (ordered.length === 0) {
    return (
      <p className="rounded-lg bg-zinc-950/[2.5%] px-3 py-2 text-sm/6 text-zinc-500 ring-1 ring-zinc-950/5 dark:bg-white/[2.5%] dark:text-zinc-400 dark:ring-white/10">
        This group has no members yet. Add one below.
      </p>
    )
  }

  return (
    <ul className="divide-y divide-zinc-950/5 overflow-hidden rounded-xl ring-1 ring-zinc-950/5 dark:divide-white/5 dark:ring-white/10">
      {ordered.map((m) => (
        <li
          key={m.name}
          className="flex items-center gap-3 px-3 py-2 text-sm/6"
        >
          <span
            className="w-10 font-mono text-zinc-500 dark:text-zinc-400"
            aria-label="priority"
          >
            {m.priority}
          </span>
          <span className="flex items-center gap-2">
            <span className="font-medium text-zinc-950 dark:text-white">
              {m.name}
            </span>
            <RepoKindBadge kind={m.kind} />
          </span>
          <span
            className="ml-auto flex items-center gap-2 text-zinc-600 dark:text-zinc-400"
            title={
              m.kind === 'proxy'
                ? 'A proxy member cannot own package ids'
                : "Owns this group's package ids"
            }
          >
            <Checkbox
              checked={m.owner}
              disabled={busy || (m.kind === 'proxy' && !m.owner)}
              onChange={(owner) => onToggleOwner(m.name, owner)}
              aria-label={`${m.name} owner`}
            />
            owner
          </span>
          <button
            type="button"
            disabled={busy}
            onClick={() => onRemove(m.name)}
            className="font-medium text-red-600 hover:underline disabled:opacity-60 dark:text-red-400"
          >
            Remove
          </button>
        </li>
      ))}
    </ul>
  )
}
