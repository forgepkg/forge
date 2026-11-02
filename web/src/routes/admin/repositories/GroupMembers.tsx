import { useState } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'

import {
  useAddMember,
  useMembers,
  useRemoveMember,
  useRepositories,
  useUpdateMember,
} from '~/queries/useRepositories'
import {
  Button,
  Code,
  FormActions,
  Notice,
  Page,
  PageHeader,
  Panel,
  SelectField,
  Skeleton,
  TextField,
} from '~/components/ui'
import { PriorityList } from '~/components/PriorityList'
import { ErrorState } from '~/components/ErrorState'
import {
  DOCKER_FORMAT,
  NPM_FORMAT,
  RAW_FORMAT,
  parsePrefixes,
} from '~/components/RepositoryForm'

export const Route = createFileRoute(
  '/_app/manage/repositories/$repo/members',
)({
  component: GroupMembers,
})

/**
 * Group-members editor. Lists the group's members ordered by
 * priority and lets an admin add a member (a repository name + a unique
 * priority), flag or unflag it as an owner of the group's package ids, or
 * remove one. Priority is **unique per group** (the server returns 409 on a
 * duplicate); the add form pre-empts that with client-side validation, and
 * still surfaces a server 409 inline if a race slips through. Groups may be
 * nested: the server refuses (409) a member that would create a cycle or
 * exceed the nesting depth, and that reason is shown inline. Members share
 * the group's format (a NuGet group holds NuGet repositories, a docker group
 * docker ones; the server answers 400 otherwise), so only those are offered.
 * An owner cannot be removed until it is unflagged. Removing a member, and
 * unflagging the last owner (the group then trusts every hosted member
 * equally), wait for a confirmation in a dialog.
 *
 * A member can be scoped to package ids (`packages`, glob patterns such as
 * `@fortawesome/*`): the group then asks it about those ids alone, which
 * keeps a proxy that passes a public registry through from being asked
 * about every public package. The scope is set in the add form or in a
 * row's Packages dialog; groups of files (raw) have none.
 */
function GroupMembers() {
  const { repo: name } = Route.useParams()
  const navigate = useNavigate()
  const members = useMembers(name)
  const add = useAddMember(name)
  const remove = useRemoveMember(name)
  const update = useUpdateMember(name)

  // Candidate members = every other repository of the group's format (groups
  // included) that is not already a member; the server guards cycles and the
  // nesting depth.
  const allRepos = useRepositories()
  const group = allRepos.data?.find((r) => r.name === name)
  const groupFormat = group?.format
  const memberNames = new Set((members.data ?? []).map((m) => m.name))
  const usedPriorities = new Set((members.data ?? []).map((m) => m.priority))
  const candidates = (allRepos.data ?? []).filter(
    (r) =>
      r.name !== name &&
      !memberNames.has(r.name) &&
      (groupFormat === undefined || r.format === groupFormat),
  )

  const [member, setMember] = useState('')
  const [priority, setPriority] = useState('100')
  const [packages, setPackages] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  // Groups of files serve a path from the first member that has it: no
  // scopes. The examples follow the format's ids.
  const scoped = groupFormat !== undefined && groupFormat !== RAW_FORMAT.id
  const packagesPlaceholder =
    groupFormat === NPM_FORMAT.id
      ? '@fortawesome/*'
      : groupFormat === DOCKER_FORMAT.id
        ? 'bitnami/*'
        : 'Contoso.*'

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
    const scope = scoped ? parsePrefixes(packages) : []
    add.mutate(
      { member, priority: p, ...(scope.length > 0 ? { packages: scope } : {}) },
      {
        onSuccess: () => {
          setMember('')
          setPackages('')
        },
      },
    )
  }

  const count = members.data?.length
  const owners = (members.data ?? []).filter((m) => m.owner).length
  const header = (
    <PageHeader
      title={`Members of ${name}`}
      icon="Layers"
      crumbs={[
        { label: 'Repositories', to: '/manage/repositories' },
        { label: name, to: '/manage/repositories/$repo', params: { repo: name } },
        { label: 'Members' },
      ]}
      kind={group?.kind}
      format={group?.format}
      meta={
        count === undefined
          ? undefined
          : [
              `${count} ${count === 1 ? 'member' : 'members'}`,
              owners > 0 && `${owners} ${owners === 1 ? 'owner' : 'owners'}`,
            ]
      }
    />
  )

  if (members.isError) {
    return (
      <Page>
        {header}
        <ErrorState
          title="Could not load group members"
          message={members.error?.message}
          onRetry={() => void members.refetch()}
        />
      </Page>
    )
  }

  return (
    <Page>
      {header}

      <Panel
        title="Members"
        count={count}
        description={
          <>
            Higher priority wins when the same package id + version is present in
            more than one member. Once any member is an owner, only owners claim
            package ids under &ldquo;Prefer hosted packages&rdquo; and serve the
            reserved prefixes.
            {scoped &&
              ' A member with packages is asked only about the ids they match.'}
          </>
        }
      >
        {members.isLoading ? (
          <Skeleton variant="table" rows={3} columns={3} label="Loading members…" />
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
            onSetPackages={
              scoped
                ? (member, packages) => {
                    remove.reset()
                    update.mutate({ member, packages })
                  }
                : undefined
            }
            packagesPlaceholder={packagesPlaceholder}
          />
        )}

        {update.isError && (
          <Notice tone="danger">
            {update.variables?.packages !== undefined
              ? `Could not change the packages of ${update.variables.member}: `
              : `Could not ${update.variables?.owner ? 'flag' : 'unflag'} ${update.variables?.member} as owner: `}
            {update.error.body || update.error.message}
          </Notice>
        )}

        {remove.isError && (
          <Notice tone="danger">
            {remove.error.body || remove.error.message}
            {/* 409 = the member is an owner; the toggle above unflags it. */}
            {remove.error.status === 409 &&
              ` Clear the owner box of ${remove.variables} first, then remove it.`}
          </Notice>
        )}
      </Panel>

      <Panel
        as="form"
        onSubmit={handleAdd}
        title="Add a member"
        description="A repository of the group's format, other groups included, at a priority no other member has."
      >
        <div className="flex flex-wrap items-end gap-4">
          <SelectField
            label="Repository"
            className="min-w-0 flex-[1_1_260px]"
            value={member}
            onChange={(e) => setMember(e.target.value)}
          >
            <option value="">Select a repository…</option>
            {candidates.map((r) => (
              <option key={r.id} value={r.name}>
                {r.name} ({r.kind})
              </option>
            ))}
          </SelectField>
          <TextField
            label="Priority"
            type="number"
            mono
            className="w-32 flex-none"
            value={priority}
            onChange={(e) => setPriority(e.target.value)}
          />
          {scoped && (
            <TextField
              label="Packages"
              optional
              mono
              className="min-w-0 flex-[1_1_220px]"
              value={packages}
              onChange={(e) => setPackages(e.target.value)}
              placeholder={packagesPlaceholder}
            />
          )}
          <Button
            type="submit"
            variant="primary"
            icon="Plus"
            disabled={add.isPending}
          >
            {add.isPending ? 'Adding…' : 'Add member'}
          </Button>
        </div>
        {scoped && (
          <p className="fg-field-desc">
            Packages: patterns of the package ids the group asks this member
            about, comma separated (<Code>*</Code> matches any characters).
            Empty: every package. Scope a proxy that passes a public registry
            through to its own packages, so the group does not ask it about
            every public one.
          </p>
        )}
        {candidates.length === 0 && !allRepos.isLoading && (
          <p className="fg-field-desc">
            No eligible repositories to add (every other repository of this
            format is already a member, and a group cannot contain itself).
          </p>
        )}
        {formError && <Notice tone="danger">{formError}</Notice>}
        {add.isError && (
          <Notice tone="danger" title="Could not add the member">
            {add.error.body || add.error.message}
          </Notice>
        )}
      </Panel>

      <FormActions>
        <Button onClick={() => void navigate({ to: '/manage/repositories' })}>
          Done
        </Button>
      </FormActions>
    </Page>
  )
}
