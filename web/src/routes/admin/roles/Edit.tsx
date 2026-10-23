import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import {
  ACTIONS,
  ANONYMOUS_ROLE,
  type Action,
  type RoleView,
} from '~/api/rbac'
import { authSourceLabel } from '~/api/users'
import { useRepositories } from '~/queries/useRepositories'
import { useUsers } from '~/queries/useUsers'
import {
  useAddGrant,
  useAssignRole,
  useRemoveGrant,
  useRole,
  useRoleGrants,
  useRoleMembers,
  useSelectors,
  useUnassignRole,
  useUpdateRole,
} from '~/queries/useRbac'
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
import { Description, Field, Label } from '~/components/catalyst/fieldset'
import { Heading, Subheading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
import { Select } from '~/components/catalyst/select'
import { Text } from '~/components/catalyst/text'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/catalyst/table'
import { ErrorState } from '~/components/ErrorState'
import {
  ActionBadge,
  byId,
  InlineError,
  RepositoryLabel,
  repoNames,
  SelectorLabel,
} from '~/components/RbacLabels'
import { RoleDeleteConfirm } from '~/components/RoleDeleteConfirm'

export const Route = createFileRoute('/_app/manage/roles/$roleId')({
  component: RolePage,
})

/** What each built-in role means, shown on its page. */
const BUILTIN_NOTES: Record<string, string> = {
  admin:
    'Its members may do everything, on every repository and in this administration, whatever its grants say.',
  anonymous:
    'Its grants apply to callers who do not sign in. Its read grants apply to every signed-in user too.',
  authenticated:
    'Installs upgraded from before roles existed give it to every user, for the open access they had.',
}

/**
 * One role: its description, its grants (repository or every repository, an
 * action, and optionally a content selector) and its members. Admins add and
 * remove grants and members here; a role that is not built in can be deleted
 * after a confirmation naming what it takes along.
 */
function RolePage() {
  const { roleId } = Route.useParams()
  const id = Number(roleId)
  const navigate = useNavigate()
  const role = useRole(id)
  const [confirmDelete, setConfirmDelete] = useState(false)

  if (role.isError) {
    return (
      <ErrorState
        title="Could not load role"
        message={role.error?.body || role.error?.message}
        onRetry={() => void role.refetch()}
      />
    )
  }
  if (role.isLoading || !role.data) {
    return <Text>Loading role…</Text>
  }
  const r = role.data

  return (
    <section className="space-y-8">
      <div>
        <Link
          to="/manage/roles"
          className="text-sm/6 text-sky-600 hover:underline dark:text-sky-400"
        >
          ← Roles
        </Link>
        <div className="mt-1 flex items-center justify-between gap-4">
          <Heading className="flex items-center gap-2">
            <span className="font-mono">{r.name}</span>
            {r.builtin && <Badge color="zinc">built-in</Badge>}
          </Heading>
          {!r.builtin && !confirmDelete && (
            <Button outline onClick={() => setConfirmDelete(true)}>
              Delete role…
            </Button>
          )}
        </div>
        {r.builtin && BUILTIN_NOTES[r.name] && (
          <Text className="mt-1">{BUILTIN_NOTES[r.name]}</Text>
        )}
      </div>

      {confirmDelete && (
        <RoleDeleteConfirm
          role={r}
          onCancel={() => setConfirmDelete(false)}
          onDeleted={() => void navigate({ to: '/manage/roles' })}
        />
      )}

      <DescriptionForm key={`${r.id}:${r.description}`} role={r} />
      <Grants role={r} />
      <Members role={r} />
    </section>
  )
}

function DescriptionForm({ role }: { role: RoleView }) {
  const update = useUpdateRole(role.id)
  const [description, setDescription] = useState(role.description)

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        update.mutate(description.trim())
      }}
      className="space-y-3"
    >
      <div className="flex items-end gap-3">
        <Field className="flex-1">
          <Label>Description</Label>
          <Input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <Button
          type="submit"
          disabled={update.isPending || description.trim() === role.description}
        >
          {update.isPending ? 'Saving…' : 'Save'}
        </Button>
      </div>
      {update.isError && (
        <InlineError>{update.error.body || update.error.message}</InlineError>
      )}
    </form>
  )
}

/** The role's grants, and the form that adds one. */
function Grants({ role }: { role: RoleView }) {
  const grants = useRoleGrants(role.id)
  const repos = useRepositories()
  const selectors = useSelectors()
  const remove = useRemoveGrant(role.id)
  const names = repoNames(repos.data)
  const selectorMap = byId(selectors.data)

  return (
    <div className="space-y-4">
      <div>
        <Subheading>Grants</Subheading>
        <Text className="mt-1">
          What the role&apos;s holders may do. A content selector narrows a
          grant to the packages it matches.
        </Text>
      </div>

      <AddGrantForm role={role} />

      {remove.isError && (
        <InlineError>{remove.error.body || remove.error.message}</InlineError>
      )}

      {grants.isError ? (
        <ErrorState
          title="Could not load grants"
          message={grants.error?.message}
          onRetry={() => void grants.refetch()}
        />
      ) : grants.isLoading ? (
        <Text>Loading grants…</Text>
      ) : (grants.data?.length ?? 0) === 0 ? (
        <Text>The role grants nothing yet.</Text>
      ) : (
        <Table striped>
          <TableHead>
            <TableRow>
              <TableHeader>Repository</TableHeader>
              <TableHeader>Action</TableHeader>
              <TableHeader>Packages</TableHeader>
              <TableHeader>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {grants.data!.map((g) => (
              <TableRow key={g.id}>
                <TableCell>
                  <RepositoryLabel id={g.repository_id} names={names} />
                </TableCell>
                <TableCell>
                  <ActionBadge action={g.action} />
                </TableCell>
                <TableCell>
                  <SelectorLabel id={g.selector_id} selectors={selectorMap} />
                </TableCell>
                <TableCell>
                  <button
                    type="button"
                    disabled={remove.isPending}
                    onClick={() => remove.mutate(g.id)}
                    className="font-medium text-red-600 hover:underline disabled:opacity-60 dark:text-red-400"
                  >
                    Remove
                  </button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}

/**
 * Add a grant: a repository (or all of them), an action and optionally a
 * content selector. `admin` is offered only with all repositories, as the
 * API accepts it.
 */
function AddGrantForm({ role }: { role: RoleView }) {
  const repos = useRepositories()
  const selectors = useSelectors()
  const add = useAddGrant(role.id)
  const [repository, setRepository] = useState('')
  const [action, setAction] = useState<Action>('read')
  const [selector, setSelector] = useState('')

  function chooseRepository(value: string) {
    setRepository(value)
    if (value !== '' && action === 'admin') setAction('read')
  }

  function submit(e: React.FormEvent) {
    e.preventDefault()
    add.mutate({
      action,
      ...(repository !== '' ? { repository_id: Number(repository) } : {}),
      ...(selector !== '' ? { selector_id: Number(selector) } : {}),
    })
  }

  const sortedRepos = [...(repos.data ?? [])].sort((a, b) =>
    a.name.localeCompare(b.name),
  )

  return (
    <form
      onSubmit={submit}
      aria-label="Add grant"
      className="space-y-3 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <div className="grid gap-4 sm:grid-cols-3">
        <Field>
          <Label>Repository</Label>
          <Select
            value={repository}
            onChange={(e) => chooseRepository(e.target.value)}
          >
            <option value="">All repositories</option>
            {sortedRepos.map((r) => (
              <option key={r.id} value={String(r.id)}>
                {r.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field>
          <Label>Action</Label>
          <Select
            value={action}
            onChange={(e) => setAction(e.target.value as Action)}
          >
            {ACTIONS.map((a) => (
              <option key={a} value={a} disabled={a === 'admin' && repository !== ''}>
                {a}
              </option>
            ))}
          </Select>
          {action === 'admin' && (
            <Description>
              Accepted on all repositories only. Administration itself comes
              from holding the built-in admin role.
            </Description>
          )}
        </Field>
        <Field>
          <Label>Content selector</Label>
          <Select value={selector} onChange={(e) => setSelector(e.target.value)}>
            <option value="">All packages</option>
            {(selectors.data ?? []).map((s) => (
              <option key={s.id} value={String(s.id)}>
                {s.name}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      {repos.isError && (
        <InlineError>
          Could not load repositories: {repos.error.body || repos.error.message}
        </InlineError>
      )}
      {add.isError && (
        <InlineError>{add.error.body || add.error.message}</InlineError>
      )}
      <Button type="submit" disabled={add.isPending}>
        {add.isPending ? 'Adding…' : 'Add grant'}
      </Button>
    </form>
  )
}

/** The users who hold the role; admins add and remove them here. */
function Members({ role }: { role: RoleView }) {
  const members = useRoleMembers(role.id)
  const users = useUsers()
  const assign = useAssignRole()
  const unassign = useUnassignRole()
  const [userId, setUserId] = useState('')

  const memberIds = new Set((members.data ?? []).map((m) => m.id))
  const candidates = (users.data ?? []).filter((u) => !memberIds.has(u.id))

  return (
    <div className="space-y-4">
      <div>
        <Subheading>Members</Subheading>
        <Text className="mt-1">
          {role.name === ANONYMOUS_ROLE
            ? 'Callers who do not sign in hold this role without being listed here.'
            : 'The users who hold this role.'}
        </Text>
      </div>

      <form
        aria-label="Add member"
        onSubmit={(e) => {
          e.preventDefault()
          if (userId === '') return
          assign.mutate(
            { userId: Number(userId), roleId: role.id },
            { onSuccess: () => setUserId('') },
          )
        }}
        className="flex items-end gap-3 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
      >
        <Field className="flex-1">
          <Label>User</Label>
          <Select value={userId} onChange={(e) => setUserId(e.target.value)}>
            <option value="">Choose a user…</option>
            {candidates.map((u) => (
              <option key={u.id} value={String(u.id)}>
                {u.username} ({authSourceLabel(u.auth_source)})
              </option>
            ))}
          </Select>
        </Field>
        <Button type="submit" disabled={assign.isPending || userId === ''}>
          {assign.isPending ? 'Adding…' : 'Add member'}
        </Button>
      </form>

      {assign.isError && (
        <InlineError>{assign.error.body || assign.error.message}</InlineError>
      )}
      {unassign.isError && (
        <InlineError>{unassign.error.body || unassign.error.message}</InlineError>
      )}

      {members.isError ? (
        <ErrorState
          title="Could not load members"
          message={members.error?.message}
          onRetry={() => void members.refetch()}
        />
      ) : members.isLoading ? (
        <Text>Loading members…</Text>
      ) : (members.data?.length ?? 0) === 0 ? (
        <Text>No user holds this role.</Text>
      ) : (
        <Table striped>
          <TableHead>
            <TableRow>
              <TableHeader>Username</TableHeader>
              <TableHeader>Sign-in</TableHeader>
              <TableHeader>Status</TableHeader>
              <TableHeader>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {members.data!.map((m) => (
              <TableRow key={m.id}>
                <TableCell>
                  <Link
                    to="/manage/users/$userId"
                    params={{ userId: String(m.id) }}
                    className="font-medium text-sky-600 hover:underline dark:text-sky-400"
                  >
                    {m.username}
                  </Link>
                </TableCell>
                <TableCell>{authSourceLabel(m.auth_source)}</TableCell>
                <TableCell>
                  {m.active ? (
                    <Badge color="emerald">active</Badge>
                  ) : (
                    <Badge color="zinc">inactive</Badge>
                  )}
                </TableCell>
                <TableCell>
                  <button
                    type="button"
                    disabled={unassign.isPending}
                    onClick={() =>
                      unassign.mutate({ userId: m.id, roleId: role.id })
                    }
                    className="font-medium text-red-600 hover:underline disabled:opacity-60 dark:text-red-400"
                    aria-label={`Remove ${m.username}`}
                  >
                    Remove
                  </button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}
