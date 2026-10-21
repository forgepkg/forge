import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import {
  useAddMember,
  useMembers,
  useRemoveMember,
  useRepositories,
  useUpdateMember,
} from '~/queries/useRepositories'
import { Button } from '~/components/catalyst/button'
import { Field, Label } from '~/components/catalyst/fieldset'
import { Heading, Subheading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
import { Select } from '~/components/catalyst/select'
import { Text } from '~/components/catalyst/text'
import { PriorityList } from '~/components/PriorityList'
import { ErrorState } from '~/components/ErrorState'

export const Route = createFileRoute(
  '/_app/manage/repositories/$repo/members',
)({
  component: GroupMembers,
})

/**
 * Group-members editor (plan §Phase 4). Lists the group's members ordered by
 * priority and lets an admin add a member (a repository name + a unique
 * priority), flag or unflag it as an owner of the group's package ids, or
 * remove one. Priority is **unique per group** (the server returns 409 on a
 * duplicate); the add form pre-empts that with client-side validation, and
 * still surfaces a server 409 inline if a race slips through. Groups may be
 * nested: the server refuses (409) a member that would create a cycle or
 * exceed the nesting depth, and that reason is shown inline. An owner cannot
 * be removed until it is unflagged. Removing a member, and unflagging the
 * last owner (the group then trusts every hosted member equally), wait for
 * an inline confirmation.
 */
function GroupMembers() {
  const { repo: name } = Route.useParams()
  const navigate = useNavigate()
  const members = useMembers(name)
  const add = useAddMember(name)
  const remove = useRemoveMember(name)
  const update = useUpdateMember(name)

  // Candidate members = every other repository (groups included) that is not
  // already a member; the server guards cycles and the nesting depth.
  const allRepos = useRepositories()
  const memberNames = new Set((members.data ?? []).map((m) => m.name))
  const usedPriorities = new Set((members.data ?? []).map((m) => m.priority))
  const candidates = (allRepos.data ?? []).filter(
    (r) => r.name !== name && !memberNames.has(r.name),
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
          to="/manage/repositories/$repo"
          params={{ repo: name }}
          className="text-sm/6 text-sky-600 hover:underline dark:text-sky-400"
        >
          ← Back to {name}
        </Link>
        <Heading className="mt-1">
          Members of <span className="font-mono">{name}</span>
        </Heading>
        <Text className="mt-1">
          Higher priority wins when the same package id + version is present in
          more than one member. Once any member is an owner, only owners claim
          package ids under &ldquo;Prefer hosted packages&rdquo; and serve the
          reserved prefixes.
        </Text>
      </div>

      {members.isLoading ? (
        <Text>Loading members…</Text>
      ) : (
        <PriorityList
          members={members.data ?? []}
          busy={remove.isPending || update.isPending}
          onRemove={(m) => {
            update.reset()
            remove.mutate(m)
          }}
          onToggleOwner={(member, owner) => {
            remove.reset()
            update.mutate({ member, owner })
          }}
        />
      )}

      {update.isError && (
        <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
          Could not {update.variables?.owner ? 'flag' : 'unflag'}{' '}
          {update.variables?.member} as owner:{' '}
          {update.error.body || update.error.message}
        </p>
      )}

      {remove.isError && (
        <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
          {remove.error.body || remove.error.message}
          {/* 409 = the member is an owner; the toggle above unflags it. */}
          {remove.error.status === 409 &&
            ` Clear the owner box of ${remove.variables} first, then remove it.`}
        </p>
      )}

      <form
        onSubmit={handleAdd}
        className="space-y-3 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
      >
        <Subheading>Add a member</Subheading>
        <div className="flex flex-wrap items-end gap-3">
          <Field className="min-w-64">
            <Label>Repository</Label>
            <Select
              value={member}
              onChange={(e) => setMember(e.target.value)}
            >
              <option value="">Select a repository…</option>
              {candidates.map((r) => (
                <option key={r.id} value={r.name}>
                  {r.name} ({r.kind})
                </option>
              ))}
            </Select>
          </Field>
          <Field className="w-32">
            <Label>Priority</Label>
            <Input
              type="number"
              value={priority}
              onChange={(e) => setPriority(e.target.value)}
            />
          </Field>
          <Button type="submit" disabled={add.isPending}>
            {add.isPending ? 'Adding…' : 'Add member'}
          </Button>
        </div>
        {formError && (
          <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
            {formError}
          </p>
        )}
        {add.isError && (
          <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
            {add.error.body || add.error.message}
          </p>
        )}
        {candidates.length === 0 && !allRepos.isLoading && (
          <p className="text-xs text-zinc-500 dark:text-zinc-400">
            No eligible repositories to add (every other repository is already
            a member, and a group cannot contain itself).
          </p>
        )}
      </form>

      <div>
        <button
          type="button"
          onClick={() => void navigate({ to: '/manage/repositories' })}
          className="text-sm/6 text-zinc-500 hover:underline dark:text-zinc-400"
        >
          Done
        </button>
      </div>
    </section>
  )
}
