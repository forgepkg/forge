import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import {
  ANONYMOUS_ROLE,
  LEVEL_COVERS,
  LEVELS,
  levelLabel,
  type Level,
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
import {
  Avatar,
  Button,
  CellActions,
  Columns,
  Page,
  PageHeader,
  Panel,
  SelectField,
  Skeleton,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TextField,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import {
  byId,
  InlineError,
  LevelBadge,
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
    'Its members may do everything, on every repository and in this administration. Administration is this role, not a grant level.',
  anonymous:
    'Its grants apply to callers who do not sign in. They apply to every signed-in user too, as read only.',
  authenticated:
    'It reads and writes every repository: the open access from before roles existed. No user gets it automatically; assign it like any other role.',
}

/**
 * The add form at the top of a flush panel, above its table (a grant, a
 * member): padded like the panel body, ruled off from the table.
 */
const ADD_STRIP = 'grid gap-4 border-b border-line px-5 py-4'

/**
 * One role: its description, its grants (repository or every repository, a
 * level, and optionally a content selector) and its members. Admins add and
 * remove grants and members here; a role that is not built in can be deleted
 * after a confirmation dialog naming what it takes along.
 */
function RolePage() {
  const { roleId } = Route.useParams()
  const id = Number(roleId)
  const navigate = useNavigate()
  const role = useRole(id)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const crumbs = [{ label: 'Roles', to: '/manage/roles' }]

  if (role.isError) {
    return (
      <Page>
        <PageHeader title={`Role #${id}`} crumbs={crumbs} />
        <ErrorState
          title="Could not load role"
          message={role.error?.body || role.error?.message}
          onRetry={() => void role.refetch()}
        />
      </Page>
    )
  }
  if (role.isLoading || !role.data) {
    return <Skeleton lines={4} label="Loading role…" />
  }
  const r = role.data

  return (
    <Page>
      <PageHeader
        title={<span className="font-mono">{r.name}</span>}
        crumbs={[...crumbs, { label: r.name }]}
        description={r.builtin ? BUILTIN_NOTES[r.name] : undefined}
        actions={
          !r.builtin && (
            <Button variant="danger" icon="Trash" onClick={() => setConfirmDelete(true)}>
              Delete role…
            </Button>
          )
        }
      >
        {r.builtin && <StatusBadge dot={false}>built-in</StatusBadge>}
      </PageHeader>

      {confirmDelete && (
        <RoleDeleteConfirm
          role={r}
          onCancel={() => setConfirmDelete(false)}
          onDeleted={() => void navigate({ to: '/manage/roles' })}
        />
      )}

      <Columns
        asideLabel="Role details"
        aside={<DescriptionForm key={`${r.id}:${r.description}`} role={r} />}
      >
        <Grants role={r} />
        <Members role={r} />
      </Columns>
    </Page>
  )
}

/** The role's description, saved on its own. */
function DescriptionForm({ role }: { role: RoleView }) {
  const update = useUpdateRole(role.id)
  const [description, setDescription] = useState(role.description)

  return (
    <Panel
      as="form"
      title="General"
      onSubmit={(e) => {
        e.preventDefault()
        update.mutate(description.trim())
      }}
      footer={
        <Button
          type="submit"
          variant="primary"
          disabled={update.isPending || description.trim() === role.description}
        >
          {update.isPending ? 'Saving…' : 'Save'}
        </Button>
      }
    >
      <TextField
        label="Description"
        type="text"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
      />
      {update.isError && (
        <InlineError>{update.error.body || update.error.message}</InlineError>
      )}
    </Panel>
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
    <Panel
      title="Grants"
      count={grants.data?.length}
      description="What the role's holders may do: one level per repository, each level including the ones below it. A content selector narrows a grant to the packages it matches."
      flush
    >
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
        <Skeleton lines={3} label="Loading grants…" />
      ) : (grants.data?.length ?? 0) === 0 ? (
        <EmptyState title="The role grants nothing yet" icon="Lock" bordered={false} />
      ) : (
        <Table caption={`Grants of ${role.name}`}>
          <TableHead>
            <TableHeader>Repository</TableHeader>
            <TableHeader width="120px">Level</TableHeader>
            <TableHeader>Packages</TableHeader>
            <TableHeader align="right" width="96px">
              <span className="fg-sr">Actions</span>
            </TableHeader>
          </TableHead>
          <TableBody>
            {grants.data!.map((g) => (
              <TableRow key={g.id}>
                <TableCell lead>
                  <RepositoryLabel id={g.repository_id} names={names} />
                </TableCell>
                <TableCell>
                  <LevelBadge level={g.level} />
                </TableCell>
                <TableCell>
                  <SelectorLabel id={g.selector_id} selectors={selectorMap} />
                </TableCell>
                <TableCell align="right">
                  <CellActions>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={remove.isPending}
                      onClick={() => remove.mutate(g.id)}
                    >
                      Remove
                    </Button>
                  </CellActions>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  )
}

/**
 * Add a grant: a repository (or all of them), a level labelled with the Nexus
 * actions it covers, and optionally a content selector. A role holds one
 * grant per repository and selector, so adding one again sets its level.
 */
function AddGrantForm({ role }: { role: RoleView }) {
  const repos = useRepositories()
  const selectors = useSelectors()
  const add = useAddGrant(role.id)
  const [repository, setRepository] = useState('')
  const [level, setLevel] = useState<Level>('read')
  const [selector, setSelector] = useState('')

  function submit(e: React.FormEvent) {
    e.preventDefault()
    add.mutate({
      level,
      ...(repository !== '' ? { repository_id: Number(repository) } : {}),
      ...(selector !== '' ? { selector_id: Number(selector) } : {}),
    })
  }

  const sortedRepos = [...(repos.data ?? [])].sort((a, b) =>
    a.name.localeCompare(b.name),
  )

  return (
    <form onSubmit={submit} aria-label="Add grant" className={ADD_STRIP}>
      <div className="fg-fieldrow">
        <SelectField
          label="Repository"
          value={repository}
          onChange={(e) => setRepository(e.target.value)}
        >
          <option value="">All repositories</option>
          {sortedRepos.map((r) => (
            <option key={r.id} value={String(r.id)}>
              {r.name}
            </option>
          ))}
        </SelectField>
        <SelectField
          label="Level"
          value={level}
          onChange={(e) => setLevel(e.target.value as Level)}
          description={`Covers ${LEVEL_COVERS[level]}.`}
        >
          {LEVELS.map((l) => (
            <option key={l} value={l}>
              {levelLabel(l)}
            </option>
          ))}
        </SelectField>
        <SelectField
          label="Content selector"
          value={selector}
          onChange={(e) => setSelector(e.target.value)}
        >
          <option value="">All packages</option>
          {(selectors.data ?? []).map((s) => (
            <option key={s.id} value={String(s.id)}>
              {s.name}
            </option>
          ))}
        </SelectField>
      </div>
      {repos.isError && (
        <InlineError>
          Could not load repositories: {repos.error.body || repos.error.message}
        </InlineError>
      )}
      {add.isError && (
        <InlineError>{add.error.body || add.error.message}</InlineError>
      )}
      <div>
        <Button type="submit" icon="Plus" disabled={add.isPending}>
          {add.isPending ? 'Adding…' : 'Add grant'}
        </Button>
      </div>
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
    <Panel
      title="Members"
      count={members.data?.length}
      description={
        role.name === ANONYMOUS_ROLE
          ? 'Callers who do not sign in hold this role without being listed here.'
          : 'The users who hold this role.'
      }
      flush
    >
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
        className={ADD_STRIP}
      >
        <div className="flex flex-wrap items-end gap-3">
          <SelectField
            label="User"
            className="min-w-0 flex-[1_1_240px]"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
          >
            <option value="">Choose a user…</option>
            {candidates.map((u) => (
              <option key={u.id} value={String(u.id)}>
                {u.username} ({authSourceLabel(u.auth_source)})
              </option>
            ))}
          </SelectField>
          <Button type="submit" icon="Plus" disabled={assign.isPending || userId === ''}>
            {assign.isPending ? 'Adding…' : 'Add member'}
          </Button>
        </div>
        {assign.isError && (
          <InlineError>{assign.error.body || assign.error.message}</InlineError>
        )}
        {unassign.isError && (
          <InlineError>{unassign.error.body || unassign.error.message}</InlineError>
        )}
      </form>

      {members.isError ? (
        <ErrorState
          title="Could not load members"
          message={members.error?.message}
          onRetry={() => void members.refetch()}
        />
      ) : members.isLoading ? (
        <Skeleton lines={3} label="Loading members…" />
      ) : (members.data?.length ?? 0) === 0 ? (
        <EmptyState title="No user holds this role" icon="Users" bordered={false} />
      ) : (
        <Table caption={`Members of ${role.name}`}>
          <TableHead>
            <TableHeader>Username</TableHeader>
            <TableHeader>Sign-in</TableHeader>
            <TableHeader width="120px">Status</TableHeader>
            <TableHeader align="right" width="96px">
              <span className="fg-sr">Actions</span>
            </TableHeader>
          </TableHead>
          <TableBody>
            {members.data!.map((m) => (
              <TableRow key={m.id}>
                <TableCell lead>
                  <span className="fg-cell-user">
                    <Avatar name={m.username} decorative />
                    <Link
                      to="/manage/users/$userId"
                      params={{ userId: String(m.id) }}
                      className="fg-link-strong"
                    >
                      {m.username}
                    </Link>
                  </span>
                </TableCell>
                <TableCell>{authSourceLabel(m.auth_source)}</TableCell>
                <TableCell>
                  {m.active ? (
                    <StatusBadge tone="ok">active</StatusBadge>
                  ) : (
                    <StatusBadge tone="neutral">inactive</StatusBadge>
                  )}
                </TableCell>
                <TableCell align="right">
                  <CellActions>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={unassign.isPending}
                      aria-label={`Remove ${m.username}`}
                      onClick={() => unassign.mutate({ userId: m.id, roleId: role.id })}
                    >
                      Remove
                    </Button>
                  </CellActions>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  )
}
