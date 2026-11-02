import { useState } from 'react'

import type { MemberView } from '~/api/repositories'
import {
  Button,
  Checkbox,
  Code,
  Dialog,
  EmptyState,
  KindBadge,
  TextareaField,
} from '~/components/ui'
import { parsePrefixes } from '~/components/RepositoryForm'

/**
 * Ordered group-member list. Members are shown sorted by descending priority —
 * the highest-priority member wins ties. Each row offers an owner toggle, the
 * package ids the group asks the member about (its scope, edited in a
 * `Dialog`) and a remove action. Removing asks first, and so does unflagging
 * the last owner: a group without owners trusts every hosted member equally.
 * Both ask in a `Dialog`; `onRemove` / `onToggleOwner` fire only once
 * confirmed.
 *
 * **No in-place reorder:** the group API has *add* (`POST .../members` with a
 * unique `priority`), *remove* (`DELETE .../members/{member}`) and an
 * update of the owner flag and the scope (`PATCH .../members/{member}`
 * `{"owner": bool, "packages": [...]}`) — there is **no** priority-update /
 * reorder endpoint. So this list does not offer in-place reorder; changing a
 * member's priority is expressed as remove + re-add at the new priority via
 * the add form. The priority is *displayed* here so the winner ordering is
 * visible, and the add form enforces uniqueness. A proxy cannot own package
 * ids, so its toggle is disabled.
 */
export interface PriorityListProps {
  members: MemberView[]
  /** Disable the row controls while a mutation is in flight. */
  busy: boolean
  onRemove: (member: string) => void
  onToggleOwner: (member: string, owner: boolean) => void
  /**
   * Set the package patterns the group asks a member about (`[]`: every id).
   * Absent for a group without scopes (files, raw): no row offers them.
   */
  onSetPackages?: (member: string, packages: string[]) => void
  /** Example patterns for the group's format, for the scope dialog. */
  packagesPlaceholder?: string
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
  onSetPackages,
  packagesPlaceholder,
}: PriorityListProps) {
  const ordered = sortByPriority(members)
  const ownerCount = members.filter((m) => m.owner).length
  // The one member waiting for a confirmation, and what for.
  const [pending, setPending] = useState<{
    member: string
    action: 'remove' | 'unflag'
  } | null>(null)
  // The member whose scope is being edited, and the patterns typed so far.
  const [scoping, setScoping] = useState<{ member: string; text: string } | null>(null)

  function saveScope() {
    if (!scoping || !onSetPackages) return
    setScoping(null)
    onSetPackages(scoping.member, parsePrefixes(scoping.text))
  }

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
      <EmptyState title="No members yet" icon="Layers" bordered={false}>
        The group serves nothing until it has members. Add one below.
      </EmptyState>
    )
  }

  return (
    <>
      <ol className="fg-prio" aria-label="Members, highest priority first">
        {ordered.map((m) => (
          <li key={m.name} className="fg-prio-row">
            <span
              className="fg-prio-num w-auto min-w-6 px-2"
              aria-label="priority"
              title="Priority"
            >
              {m.priority}
            </span>
            <span className="fg-prio-main">
              <span className="flex min-w-0 flex-wrap items-center gap-2">
                <span className="fg-prio-name">{m.name}</span>
                <KindBadge kind={m.kind} />
              </span>
              {onSetPackages && m.packages.length > 0 && (
                <span className="fg-prio-meta">
                  Asked only about{' '}
                  {m.packages.map((p, i) => (
                    <span key={p}>
                      {i > 0 && ', '}
                      <Code>{p}</Code>
                    </span>
                  ))}
                </span>
              )}
              {m.kind === 'proxy' && (
                <span className="fg-prio-meta">A proxy cannot own package ids.</span>
              )}
            </span>
            <span className="fg-prio-actions items-center gap-3">
              <span
                title={
                  m.kind === 'proxy'
                    ? 'A proxy member cannot own package ids'
                    : "Owns this group's package ids"
                }
              >
                <Checkbox
                  label="owner"
                  checked={m.owner}
                  disabled={busy || (m.kind === 'proxy' && !m.owner)}
                  onChange={(owner) => toggleOwner(m.name, owner)}
                  aria-label={`${m.name} owner`}
                />
              </span>
              {onSetPackages && (
                <Button
                  size="sm"
                  variant="ghost"
                  icon="Filter"
                  disabled={busy}
                  onClick={() => setScoping({ member: m.name, text: m.packages.join('\n') })}
                >
                  Packages
                </Button>
              )}
              <Button
                size="sm"
                variant="ghost"
                icon="Trash"
                disabled={busy}
                onClick={() => setPending({ member: m.name, action: 'remove' })}
              >
                Remove
              </Button>
            </span>
          </li>
        ))}
      </ol>

      <Dialog
        open={pending?.action === 'remove'}
        onClose={() => setPending(null)}
        title={`Remove ${pending?.member ?? ''} from the group?`}
        icon="Trash"
        tone="danger"
        description="The group stops serving what this member holds. Add it again, at a priority of your choice, to undo this."
        confirmLabel={`Remove ${pending?.member ?? ''}`}
        confirmVariant="danger-solid"
        confirmDisabled={busy}
        onConfirm={confirmed}
      />
      <Dialog
        open={pending?.action === 'unflag'}
        onClose={() => setPending(null)}
        title={`Unflag ${pending?.member ?? ''} as owner?`}
        icon="Alert"
        tone="warn"
        description={
          <>
            {pending?.member} is the last owner. Without one, the group trusts
            every hosted member equally: each can serve package ids under the
            reserved prefixes and, with &ldquo;Prefer hosted packages&rdquo;,
            claim any public package id.
          </>
        }
        confirmLabel={`Unflag ${pending?.member ?? ''}`}
        confirmVariant="danger-solid"
        confirmDisabled={busy}
        onConfirm={confirmed}
      />
      <Dialog
        open={scoping !== null}
        onClose={() => setScoping(null)}
        title={`Packages the group asks ${scoping?.member ?? ''} about`}
        icon="Filter"
        description="The group asks this member only about package ids that match one of these patterns, and never about any other: no upstream request for them. Leave it empty to ask it about every package."
        confirmLabel="Save packages"
        confirmDisabled={busy}
        onConfirm={saveScope}
      >
        <TextareaField
          label="Patterns"
          mono
          rows={4}
          value={scoping?.text ?? ''}
          onChange={(e) => setScoping((s) => (s ? { ...s, text: e.target.value } : s))}
          placeholder={packagesPlaceholder}
          description="One per line, or comma separated. * matches any characters; a pattern without one is a single package id. Matched case-insensitively."
        />
      </Dialog>
    </>
  )
}
