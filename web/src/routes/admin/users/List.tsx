import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import { ApiError } from '~/lib/httpClient'
import { accessLevel, ADMIN_ROLE, WRITER_ROLE } from '~/api/rbac'
import { authSourceLabel, upnError, type UserView } from '~/api/users'
import {
  PartialCreate,
  useCreateUser,
  useDeleteUser,
  useUsers,
} from '~/queries/useUsers'
import { useRoles } from '~/queries/useRbac'
import { useRealms } from '~/queries/useRealms'
import { AccessBadge } from '~/components/AccessBadge'
import {
  Avatar,
  Button,
  CellActions,
  Checkbox,
  Dialog,
  Fieldset,
  Page,
  PageHeader,
  Panel,
  SelectField,
  Skeleton,
  StatusBadge,
  Switch,
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
import { InlineError } from '~/components/RbacLabels'

export const Route = createFileRoute('/_app/manage/users')({
  component: UsersList,
})

/**
 * Admin users screen. Lists every user with how they sign in (password,
 * identity provider, credential forwarding: look-alike usernames from
 * different sources are different accounts), their built-in access level
 * (admin, writer or reader, from their role assignments), the other roles
 * they hold and their active flag, offers an inline create form
 * (`CreateUser`, then the chosen roles), links each user to its
 * roles-and-tokens screen, and deletes after a confirmation dialog. There is
 * no edit-in-place beyond create/delete + the per-user screen. Every account
 * is named by a UPN.
 */
function UsersList() {
  const users = useUsers()
  const roles = useRoles()
  const roleIds = new Map((roles.data ?? []).map((r) => [r.name, r.id]))
  const del = useDeleteUser()
  const [pendingDelete, setPendingDelete] = useState<number | null>(null)
  const doomed = users.data?.find((u) => u.id === pendingDelete)

  function confirmDelete(id: number) {
    del.mutate(id, { onSettled: () => setPendingDelete(null) })
  }

  return (
    <Page>
      <PageHeader
        title="Users"
        description="Create and remove users, assign their roles, and manage each user's API tokens."
      />

      <CreateUserForm />

      {del.isError && (
        <InlineError>{del.error.body || del.error.message}</InlineError>
      )}

      {doomed && (
        <Dialog
          open
          onClose={() => setPendingDelete(null)}
          icon="Trash"
          tone="danger"
          title={`Delete ${doomed.username}?`}
          description="Their sessions, tokens and role assignments go with the account, and clients that use its tokens start failing. This cannot be undone."
          confirmLabel={del.isPending ? 'Deleting…' : 'Delete user'}
          confirmVariant="danger-solid"
          confirmDisabled={del.isPending}
          onConfirm={() => confirmDelete(doomed.id)}
        />
      )}

      {users.isError ? (
        <ErrorState
          title="Could not load users"
          message={users.error?.message}
          onRetry={() => void users.refetch()}
        />
      ) : users.isLoading ? (
        <Skeleton variant="table" rows={4} columns={5} label="Loading users…" />
      ) : (users.data?.length ?? 0) === 0 ? (
        <EmptyState title="No users yet" icon="Users">
          Create the first user with the form above.
        </EmptyState>
      ) : (
        <Panel title="All users" count={users.data!.length} flush>
          <Table caption="Users">
            <TableHead>
              <TableHeader>Username</TableHeader>
              <TableHeader>Sign-in</TableHeader>
              <TableHeader width="110px">Access</TableHeader>
              <TableHeader>Roles</TableHeader>
              <TableHeader width="110px">Status</TableHeader>
              <TableHeader align="right">
                <span className="fg-sr">Actions</span>
              </TableHeader>
            </TableHead>
            <TableBody>
              {users.data!.map((user) => (
                <UserRow
                  key={user.id}
                  user={user}
                  roleIds={roleIds}
                  onRequestDelete={() => setPendingDelete(user.id)}
                />
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}
    </Page>
  )
}

function UserRow({
  user,
  roleIds,
  onRequestDelete,
}: {
  user: UserView
  roleIds: ReadonlyMap<string, number>
  onRequestDelete: () => void
}) {
  return (
    <TableRow>
      <TableCell lead>
        <span className="fg-cell-user">
          <Avatar name={user.username} decorative />
          <Link
            to="/manage/users/$userId"
            params={{ userId: String(user.id) }}
            className="fg-link-strong"
          >
            {user.username}
          </Link>
        </span>
      </TableCell>
      <TableCell>{authSourceLabel(user.auth_source)}</TableCell>
      <TableCell>
        <AccessBadge level={accessLevel(user.roles, user.is_admin)} />
      </TableCell>
      <TableCell>
        <RoleBadges user={user} roleIds={roleIds} />
      </TableCell>
      <TableCell>
        {user.active ? (
          <StatusBadge tone="ok">active</StatusBadge>
        ) : (
          <StatusBadge tone="neutral">inactive</StatusBadge>
        )}
      </TableCell>
      <TableCell align="right" nowrap>
        <CellActions>
          <Button size="sm" variant="ghost" href={`/manage/users/${user.id}`}>
            Roles &amp; tokens
          </Button>
          <Button size="sm" variant="ghost" icon="Trash" onClick={onRequestDelete}>
            Delete
          </Button>
        </CellActions>
      </TableCell>
    </TableRow>
  )
}

/**
 * The roles a user holds besides the access level's (`admin`, `writer`),
 * each linked to its role page. A user with the legacy `is_admin` flag but
 * without the `admin` role is still an administrator (the server reads
 * both), so that shows too.
 */
function RoleBadges({
  user,
  roleIds,
}: {
  user: UserView
  roleIds: ReadonlyMap<string, number>
}) {
  const legacyAdmin = user.is_admin && !user.roles.includes(ADMIN_ROLE)
  const others = user.roles.filter(
    (name) => name !== ADMIN_ROLE && name !== WRITER_ROLE,
  )
  if (others.length === 0 && !legacyAdmin) {
    return <span className="text-ink-faint">—</span>
  }
  return (
    <span className="fg-cell-badges">
      {legacyAdmin && (
        <StatusBadge
          tone="heat"
          dot={false}
          title="The legacy is_admin flag, without the admin role"
        >
          admin (flag)
        </StatusBadge>
      )}
      {others.map((name) => {
        const id = roleIds.get(name)
        return id == null ? (
          <span key={name} className="fg-chip">
            {name}
          </span>
        ) : (
          <Link
            key={name}
            to="/manage/roles/$roleId"
            params={{ roleId: String(id) }}
            className="fg-chip fg-link"
          >
            {name}
          </Link>
        )
      })}
    </span>
  )
}

/**
 * Inline create-user form, a "New user" panel. Controlled state (matching the
 * codebase's Login / RepositoryForm pattern); on success the fields reset so
 * several users can be added in a row. The username/password requirements
 * mirror the server's 400s: the username is a UPN (`upnError`), checked once
 * the field was left. An account signs in with a Forge password, or through
 * a credential-forwarding realm (`realm`, no password): such a realm signs in
 * only the accounts created for it here.
 */
function CreateUserForm() {
  const create = useCreateUser()
  const roles = useRoles()
  const realms = useRealms()
  const forwarding = (realms.data ?? []).filter(
    (r) => r.kind === 'credential_forwarding',
  )
  const [username, setUsername] = useState('')
  const [usernameTouched, setUsernameTouched] = useState(false)
  // '' = a Forge password; otherwise the credential-forwarding realm's name.
  const [realm, setRealm] = useState('')
  const [password, setPassword] = useState('')
  const [chosen, setChosen] = useState<ReadonlySet<number>>(new Set())
  const [active, setActive] = useState(true)
  const usernameError = username.trim() ? upnError(username) : null
  const showUsernameError = usernameTouched && usernameError !== null

  function toggle(id: number, on: boolean) {
    setChosen((prev) => {
      const next = new Set(prev)
      if (on) next.add(id)
      else next.delete(id)
      return next
    })
  }

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!username.trim() || (!realm && !password)) return
    if (usernameError) {
      setUsernameTouched(true)
      return
    }
    create.mutate(
      {
        body: realm
          ? { username: username.trim(), realm, active }
          : { username: username.trim(), password, active },
        roles: (roles.data ?? []).filter((r) => chosen.has(r.id)),
      },
      {
        onSettled: (created, error) => {
          if (!created && !(error instanceof PartialCreate)) return
          setUsername('')
          setUsernameTouched(false)
          setRealm('')
          setPassword('')
          setChosen(new Set())
          setActive(true)
        },
      },
    )
  }

  return (
    <Panel
      as="form"
      onSubmit={submit}
      title="New user"
      footer={
        <Button
          type="submit"
          variant="primary"
          icon="Plus"
          disabled={
            create.isPending ||
            !username.trim() ||
            (!realm && !password) ||
            !!usernameError
          }
        >
          {create.isPending ? 'Creating…' : 'Create user'}
        </Button>
      }
    >
      <div className="fg-form">
        <TextField
          label="Username"
          type="text"
          autoComplete="off"
          placeholder="alice@example.com"
          value={username}
          error={showUsernameError ? usernameError : undefined}
          onChange={(e) => setUsername(e.target.value)}
          onBlur={() => setUsernameTouched(true)}
        />
        {forwarding.length > 0 && (
          <SelectField
            label="Sign-in"
            value={realm}
            onChange={(e) => setRealm(e.target.value)}
            description={
              realm
                ? "Signs in with the upstream's password, which gets the part of the username before the @."
                : undefined
            }
          >
            <option value="">Forge password</option>
            {forwarding.map((r) => (
              <option key={r.id} value={r.name}>
                Credential forwarding: {r.name}
              </option>
            ))}
          </SelectField>
        )}
        {!realm && (
          <TextField
            label="Password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        )}
        <Fieldset legend="Roles">
          {roles.isError ? (
            <p className="fg-text">
              Could not load the roles; assign them on the user&apos;s page once
              it is created.
            </p>
          ) : (
            <div className="fg-choice-list">
              {(roles.data ?? []).map((role) => (
                <Checkbox
                  key={role.id}
                  label={role.name}
                  description={role.description || undefined}
                  checked={chosen.has(role.id)}
                  onChange={(c) => toggle(role.id, c)}
                />
              ))}
            </div>
          )}
        </Fieldset>
        <Switch label="Active" checked={active} onChange={(c) => setActive(c)} />
      </div>
      {create.isError && (
        <InlineError>
          {create.error instanceof ApiError
            ? create.error.body || create.error.message
            : create.error.message}
        </InlineError>
      )}
    </Panel>
  )
}
