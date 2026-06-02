import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import {
  useAddMember,
  useMembers,
  useRemoveMember,
  useRepositories,
} from '~/queries/useRepositories'
import { PriorityList } from '~/components/PriorityList'
import { ErrorState } from '~/components/ErrorState'

export const Route = createFileRoute(
  '/_app/admin/repositories/$repo/members',
)({
  component: GroupMembers,
})

/**
 * Group-members editor (plan §Phase 4). Lists the group's members ordered by
 * priority and lets an admin add a member (a repository name + a unique
 * priority) or remove one. Priority is **unique per group** (the server returns
 * 409 on a duplicate); the add form pre-empts that with client-side validation,
 * and still surfaces a server 409 inline if a race slips through.
 */
function GroupMembers() {
  const { repo: name } = Route.useParams()
  const navigate = useNavigate()
  const members = useMembers(name)
  const add = useAddMember(name)
  const remove = useRemoveMember(name)

  // Candidate members = non-group repos that are not already members.
  const allRepos = useRepositories()
  const memberNames = new Set((members.data ?? []).map((m) => m.name))
  const usedPriorities = new Set((members.data ?? []).map((m) => m.priority))
  const candidates = (allRepos.data ?? []).filter(
    (r) => r.kind !== 'group' && r.name !== name && !memberNames.has(r.name),
  )

  const [member, setMember] = useState('')
  const [priority, setPriority] = useState('100')
  const [formError, setFormError] = useState<string | null>(null)

  function handleAdd(e: React.FormEvent) {
    e.preventDefault()
    setFormError(null)
    if (member === '') {
      setFormError('Choose a repository to add.')
      return
    }
    const p = Number(priority)
    if (!Number.isInteger(p)) {
      setFormError('Priority must be a whole number.')
      return
    }
    if (usedPriorities.has(p)) {
      setFormError(`Priority ${p} is already used in this group.`)
      return
    }
    add.mutate(
      { member, priority: p },
      {
        onSuccess: () => {
          setMember('')
        },
      },
    )
  }

  if (members.isError) {
    return (
      <ErrorState
        title="Could not load group members"
        message={members.error?.message}
        onRetry={() => void members.refetch()}
      />
    )
  }

  return (
    <section className="space-y-6">
      <div>
        <Link
          to="/admin/repositories/$repo"
          params={{ repo: name }}
          className="text-sm text-sky-700 hover:underline"
        >
          ← Back to {name}
        </Link>
        <h1 className="mt-1 text-2xl font-semibold">
          Members of <span className="font-mono">{name}</span>
        </h1>
        <p className="mt-1 text-slate-600">
          Higher priority wins when the same package id + version is present in
          more than one member.
        </p>
      </div>

      {members.isLoading ? (
        <p className="text-slate-500">Loading members…</p>
      ) : (
        <PriorityList
          members={members.data ?? []}
          busy={remove.isPending}
          onRemove={(m) => remove.mutate(m)}
        />
      )}

      {remove.isError && (
        <p role="alert" className="text-sm text-red-600">
          {remove.error.body || remove.error.message}
        </p>
      )}

      <form
        onSubmit={handleAdd}
        className="space-y-3 border-t border-slate-100 pt-4"
      >
        <h2 className="text-sm font-medium text-slate-700">Add a member</h2>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label
              htmlFor="add-member"
              className="block text-xs font-medium text-slate-600"
            >
              Repository
            </label>
            <select
              id="add-member"
              value={member}
              onChange={(e) => setMember(e.target.value)}
              className="mt-1 rounded border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500"
            >
              <option value="">Select a repository…</option>
              {candidates.map((r) => (
                <option key={r.id} value={r.name}>
                  {r.name} ({r.kind})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label
              htmlFor="add-priority"
              className="block text-xs font-medium text-slate-600"
            >
              Priority
            </label>
            <input
              id="add-priority"
              type="number"
              value={priority}
              onChange={(e) => setPriority(e.target.value)}
              className="mt-1 w-28 rounded border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500"
            />
          </div>
          <button
            type="submit"
            disabled={add.isPending}
            className="rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-60"
          >
            {add.isPending ? 'Adding…' : 'Add member'}
          </button>
        </div>
        {formError && (
          <p role="alert" className="text-sm text-red-600">
            {formError}
          </p>
        )}
        {add.isError && (
          <p role="alert" className="text-sm text-red-600">
            {add.error.body || add.error.message}
          </p>
        )}
        {candidates.length === 0 && !allRepos.isLoading && (
          <p className="text-xs text-slate-500">
            No eligible repositories to add (groups cannot be nested, and a group
            cannot contain itself).
          </p>
        )}
      </form>

      <div>
        <button
          type="button"
          onClick={() => void navigate({ to: '/admin/repositories' })}
          className="text-sm text-slate-500 hover:underline"
        >
          Done
        </button>
      </div>
    </section>
  )
}
