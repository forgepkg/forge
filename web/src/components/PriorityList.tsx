import { useState } from 'react'

import type { MemberView } from '~/api/repositories'
import { Checkbox } from '~/components/catalyst/checkbox'
import { RepoKindBadge } from '~/components/RepoKindBadge'

/**
 * Ordered group-member list. Members are shown sorted by descending priority —
 * the highest-priority member wins ties. Each row offers an owner toggle and a
 * remove action. Removing asks first, and so does unflagging the last owner: a
 * group without owners trusts every hosted member equally. `onRemove` /
 * `onToggleOwner` fire only once confirmed.
 *
 * **No in-place reorder:** the group API has *add* (`POST .../members` with a
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
  const ownerCount = members.filter((m) => m.owner).length
  // The one member waiting for a confirmation, and what for.
  const [pending, setPending] = useState<{
    member: string
    action: 'remove' | 'unflag'
  } | null>(null)

  function toggleOwner(member: string, owner: boolean) {
    // Without a flagged member every hosted leaf counts as an owner, so
    // unflagging the last owner widens the group's trust: ask first.
    if (!owner && ownerCount === 1) {
      setPending({ member, action: 'unflag' })
      return
    }
    setPending(null)
    onToggleOwner(member, owner)
  }

  function confirmed() {
    if (!pending) return
    setPending(null)
    if (pending.action === 'remove') onRemove(pending.member)
    else onToggleOwner(pending.member, false)
  }

  if (ordered.length === 0) {
    return (
      <p className="rounded-lg bg-zinc-950/[2.5%] px-3 py-2 text-sm/6 text-zinc-500 ring-1 ring-zinc-950/5 dark:bg-white/[2.5%] dark:text-zinc-400 dark:ring-white/10">
        This group has no members yet. Add one below.
      </p>
    )
  }

  return (
    <ul className="divide-y divide-zinc-950/5 overflow-hidden rounded-xl ring-1 ring-zinc-950/5 dark:divide-white/5 dark:ring-white/10">
      {ordered.map((m) => {
        const confirming = pending?.member === m.name ? pending.action : null
        return (
          <li key={m.name} className="px-3 py-2 text-sm/6">
            <div className="flex items-center gap-3">
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
                  disabled={
                    busy ||
                    confirming === 'unflag' ||
                    (m.kind === 'proxy' && !m.owner)
                  }
                  onChange={(owner) => toggleOwner(m.name, owner)}
                  aria-label={`${m.name} owner`}
                />
                owner
              </span>
              {confirming === 'remove' ? (
                <span className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={confirmed}
                    className="font-medium text-red-600 hover:underline disabled:opacity-60 dark:text-red-400"
                  >
                    Confirm
                  </button>
                  <button
                    type="button"
                    onClick={() => setPending(null)}
                    className="text-zinc-500 hover:underline dark:text-zinc-400"
                  >
                    Cancel
                  </button>
                </span>
              ) : (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => setPending({ member: m.name, action: 'remove' })}
                  className="font-medium text-red-600 hover:underline disabled:opacity-60 dark:text-red-400"
                >
                  Remove
                </button>
              )}
            </div>
            {confirming === 'unflag' && (
              <div className="mt-1 space-y-1">
                <p className="text-zinc-700 dark:text-zinc-300">
                  {m.name} is the last owner. Without one, the group trusts
                  every hosted member equally: each can serve package ids
                  under the reserved prefixes and, with &ldquo;Prefer hosted
                  packages&rdquo;, claim any public package id.
                </p>
                <span className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={confirmed}
                    className="font-medium text-red-600 hover:underline disabled:opacity-60 dark:text-red-400"
                  >
                    Unflag
                  </button>
                  <button
                    type="button"
                    onClick={() => setPending(null)}
                    className="text-zinc-500 hover:underline dark:text-zinc-400"
                  >
                    Cancel
                  </button>
                </span>
              </div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
