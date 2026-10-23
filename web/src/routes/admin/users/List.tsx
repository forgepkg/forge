import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import { ApiError } from '~/lib/httpClient'
import { ADMIN_ROLE } from '~/api/rbac'
import {
  authSourceLabel,
  isUpn,
  upnError,
  type UserView,
} from '~/api/users'
import {
  PartialCreate,
  useCreateUser,
  useDeleteUser,
  useUsers,
} from '~/queries/useUsers'
import { useRoles } from '~/queries/useRbac'
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
import {
  Checkbox,
  CheckboxField,
  CheckboxGroup,
} from '~/components/catalyst/checkbox'
import {
  Description,
  ErrorMessage,
  Field,
  Fieldset,
  Label,
  Legend,
} from '~/components/catalyst/fieldset'
import { Heading, Subheading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
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
import { EmptyState } from '~/components/EmptyState'

export const Route = createFileRoute('/_app/manage/users')({
  component: UsersList,
})

/**
 * Admin users screen (plan §Phase 5). Lists every user with how they sign in
 * (password, identity provider, credential forwarding: look-alike usernames
 * from different sources are different accounts), the roles they hold and
 * their active flag, offers an inline create form (`CreateUser`, then the
 * chosen roles), links each user to its roles-and-tokens screen, and deletes
 * with a confirm step. There is no edit-in-place beyond create/delete + the
 * per-user screen. A new account is named by a UPN; one created before that
 * rule (`alice`) is marked "legacy name".
 */
function UsersList() {
  const users = useUsers()
  const roles = useRoles()
  const roleIds = new Map((roles.data ?? []).map((r) => [r.name, r.id]))
  const del = useDeleteUser()
  const [pendingDelete, setPendingDelete] = useState<number | null>(null)

  function confirmDelete(id: number) {
    del.mutate(id, { onSettled: () => setPendingDelete(null) })
  }

  return (
    <section className="space-y-6">
      <div>
        <Heading>Users</Heading>
        <Text className="mt-1">
          Create and remove users, assign their roles, and manage each
          user&apos;s API tokens.
        </Text>
      </div>

      <CreateUserForm />

      {del.isError && (
        <InlineError>{del.error.body || del.error.message}</InlineError>
      )}

      {users.isError ? (
        <ErrorState
          title="Could not load users"
          message={users.error?.message}
          onRetry={() => void users.refetch()}
        />
      ) : users.isLoading ? (
        <Text>Loading users…</Text>
      ) : (users.data?.length ?? 0) === 0 ? (
        <EmptyState title="No users yet">
          Create the first user with the form above.
        </EmptyState>
      ) : (
        <Table striped>
          <TableHead>
            <TableRow>
              <TableHeader>Username</TableHeader>
              <TableHeader>Sign-in</TableHeader>
              <TableHeader>Roles</TableHeader>
              <TableHeader>Status</TableHeader>
              <TableHeader>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.data!.map((user) => (
              <UserRow
                key={user.id}
                user={user}
                roleIds={roleIds}
                isDeleting={del.isPending && pendingDelete === user.id}
                pendingDelete={pendingDelete === user.id}
                onRequestDelete={() => setPendingDelete(user.id)}
                onCancelDelete={() => setPendingDelete(null)}
                onConfirmDelete={() => confirmDelete(user.id)}
              />
            ))}
          </TableBody>
        </Table>
      )}
    </section>
  )
}

function InlineError({ children }: { children: React.ReactNode }) {
  return (
    <p
      role="alert"
      className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
    >
      {children}
    </p>
  )
}

function UserRow({
  user,
  roleIds,
  isDeleting,
  pendingDelete,
  onRequestDelete,
  onCancelDelete,
  onConfirmDelete,
}: {
  user: UserView
  roleIds: ReadonlyMap<string, number>
  isDeleting: boolean
  pendingDelete: boolean
  onRequestDelete: () => void
  onCancelDelete: () => void
  onConfirmDelete: () => void
}) {
  const navigate = useNavigate()
  return (
    <TableRow>
      <TableCell>
        <button
          type="button"
          onClick={() =>
            void navigate({
              to: '/manage/users/$userId',
              params: { userId: String(user.id) },
            })
          }
          className="font-medium text-sky-600 hover:underline dark:text-sky-400"
        >
          {user.username}
        </button>
        {!isUpn(user.username) && user.auth_source !== 'upstream-basic' && (
          <Badge
            color="amber"
            className="ml-2"
            title="Created before Forge named new accounts by a UPN (alice@example.com). It keeps signing in."
          >
            legacy name
          </Badge>
        )}
      </TableCell>
      <TableCell>{authSourceLabel(user.auth_source)}</TableCell>
      <TableCell>
        <RoleBadges user={user} roleIds={roleIds} />
      </TableCell>
      <TableCell>
        {user.active ? (
          <Badge color="emerald">active</Badge>
        ) : (
          <Badge color="zinc">inactive</Badge>
        )}
      </TableCell>
      <TableCell>
        <span className="flex items-center gap-3">
          <Link
            to="/manage/users/$userId"
            params={{ userId: String(user.id) }}
            className="text-sky-600 hover:underline dark:text-sky-400"
          >
            Roles &amp; tokens
          </Link>
          {pendingDelete ? (
            <span className="flex items-center gap-2">
              <button
                type="button"
                onClick={onConfirmDelete}
                disabled={isDeleting}
                className="font-medium text-red-600 hover:underline disabled:opacity-60 dark:text-red-400"
              >
                {isDeleting ? 'Deleting…' : 'Confirm'}
              </button>
              <button
                type="button"
                onClick={onCancelDelete}
                className="text-zinc-500 hover:underline dark:text-zinc-400"
              >
                Cancel
              </button>
            </span>
          ) : (
            <button
              type="button"
              onClick={onRequestDelete}
              className="font-medium text-red-600 hover:underline dark:text-red-400"
            >
              Delete
            </button>
          )}
        </span>
      </TableCell>
    </TableRow>
  )
}

/**
 * The roles a user holds, each linked to its role page. A user with the
 * legacy `is_admin` flag but without the `admin` role is still an
 * administrator (the server reads both), so that shows too.
 */
function RoleBadges({
  user,
  roleIds,
}: {
  user: UserView
  roleIds: ReadonlyMap<string, number>
}) {
  const legacyAdmin = user.is_admin && !user.roles.includes(ADMIN_ROLE)
  if (user.roles.length === 0 && !legacyAdmin) {
    return <span className="text-zinc-500 dark:text-zinc-400">no roles</span>
  }
  return (
    <span className="flex flex-wrap items-center gap-1">
      {legacyAdmin && (
        <Badge color="red" title="The legacy is_admin flag, without the admin role">
          admin (flag)
        </Badge>
      )}
      {user.roles.map((name) => {
        const id = roleIds.get(name)
        const badge = (
          <Badge color={name === ADMIN_ROLE ? 'red' : 'zinc'}>{name}</Badge>
        )
        return id == null ? (
          <span key={name}>{badge}</span>
        ) : (
          <Link
            key={name}
            to="/manage/roles/$roleId"
            params={{ roleId: String(id) }}
          >
            {badge}
          </Link>
        )
      })}
    </span>
  )
}

/**
 * Inline create-user form. Controlled state (matching the codebase's Login /
 * RepositoryForm pattern); on success the fields reset so several users can be
 * added in a row. The username/password requirements mirror the server's 400s:
 * the username is a UPN (`upnError`), checked once the field was left.
 */
function CreateUserForm() {
  const create = useCreateUser()
  const roles = useRoles()
  const [username, setUsername] = useState('')
  const [usernameTouched, setUsernameTouched] = useState(false)
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
    if (!username.trim() || !password) return
    if (usernameError) {
      setUsernameTouched(true)
      return
    }
    create.mutate(
      {
        body: { username: username.trim(), password, active },
        roles: (roles.data ?? []).filter((r) => chosen.has(r.id)),
      },
      {
        onSettled: (created, error) => {
          if (!created && !(error instanceof PartialCreate)) return
          setUsername('')
          setUsernameTouched(false)
          setPassword('')
          setChosen(new Set())
          setActive(true)
        },
      },
    )
  }

  return (
    <form
      onSubmit={submit}
      className="space-y-4 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <Subheading>New user</Subheading>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field>
          <Label>Username</Label>
          <Input
            type="text"
            autoComplete="off"
            placeholder="alice@example.com"
            value={username}
            invalid={showUsernameError}
            onChange={(e) => setUsername(e.target.value)}
            onBlur={() => setUsernameTouched(true)}
          />
          {showUsernameError && <ErrorMessage>{usernameError}</ErrorMessage>}
        </Field>
        <Field>
          <Label>Password</Label>
          <Input
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
      </div>
      <Fieldset>
        <Legend>Roles</Legend>
        {roles.isError ? (
          <Text>
            Could not load the roles; assign them on the user&apos;s page once
            it is created.
          </Text>
        ) : (
          <CheckboxGroup className="grid gap-x-6 sm:grid-cols-2">
            {(roles.data ?? []).map((role) => (
              <CheckboxField key={role.id}>
                <Checkbox
                  checked={chosen.has(role.id)}
                  onChange={(c) => toggle(role.id, c)}
                />
                <Label>{role.name}</Label>
                {role.description && (
                  <Description>{role.description}</Description>
                )}
              </CheckboxField>
            ))}
          </CheckboxGroup>
        )}
      </Fieldset>
      <CheckboxField>
        <Checkbox checked={active} onChange={(c) => setActive(c)} />
        <Label>Active</Label>
      </CheckboxField>
      {create.isError && (
        <InlineError>
          {create.error instanceof ApiError
            ? create.error.body || create.error.message
            : create.error.message}
        </InlineError>
      )}
      <Button
        type="submit"
        disabled={
          create.isPending || !username.trim() || !password || !!usernameError
        }
      >
        {create.isPending ? 'Creating…' : 'Create user'}
      </Button>
    </form>
  )
}
