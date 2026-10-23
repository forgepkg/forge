import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import { accessLevel, ADMIN_ROLE, WRITER_ROLE } from '~/api/rbac'
import { authSourceLabel, type UserStatus, type UserView } from '~/api/users'
import { useDeleteUser, useUsers } from '~/queries/useUsers'
import { useRoles } from '~/queries/useRbac'
import { AccessBadge } from '~/components/AccessBadge'
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
import { Heading } from '~/components/catalyst/heading'
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
 * Admin users screen. Lists every user with how they sign in (password,
 * identity provider, credential forwarding: look-alike usernames from
 * different sources are different accounts), their built-in access level
 * (admin, writer or reader, from their role assignments), the other roles
 * they hold and their status (active, inactive, or invited: their user has
 * not chosen a password yet), links to the create page
 * (`/manage/users/new`) and each user's roles-and-tokens screen, and deletes
 * with a confirm step. Every account is named by a UPN.
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
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <Heading>Users</Heading>
          <Text className="mt-1">
            Invite and remove users, assign their roles, and manage each
            user&apos;s API tokens.
          </Text>
        </div>
        <Button href="/manage/users/new">New user</Button>
      </div>

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
          Invite the first one with <strong>New user</strong>.
        </EmptyState>
      ) : (
        <Table striped>
          <TableHead>
            <TableRow>
              <TableHeader>Username</TableHeader>
              <TableHeader>Sign-in</TableHeader>
              <TableHeader>Access</TableHeader>
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

const STATUS: Record<UserStatus, { color: 'emerald' | 'zinc' | 'sky' | 'amber'; label: string }> =
  {
    active: { color: 'emerald', label: 'active' },
    inactive: { color: 'zinc', label: 'inactive' },
    invited: { color: 'sky', label: 'invited' },
    invitation_expired: { color: 'amber', label: 'invitation expired' },
  }

/** A user's status; an older server's view without one falls back to `active`. */
export function StatusBadge({ status }: { status: UserStatus | undefined }) {
  const { color, label } = STATUS[status ?? 'active'] ?? STATUS.active
  return <Badge color={color}>{label}</Badge>
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
      </TableCell>
      <TableCell>{authSourceLabel(user.auth_source)}</TableCell>
      <TableCell>
        <AccessBadge level={accessLevel(user.roles, user.is_admin)} />
      </TableCell>
      <TableCell>
        <RoleBadges user={user} roleIds={roleIds} />
      </TableCell>
      <TableCell>
        <StatusBadge status={user.status} />
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
    return <span className="text-zinc-500 dark:text-zinc-400">—</span>
  }
  return (
    <span className="flex flex-wrap items-center gap-1">
      {legacyAdmin && (
        <Badge color="red" title="The legacy is_admin flag, without the admin role">
          admin (flag)
        </Badge>
      )}
      {others.map((name) => {
        const id = roleIds.get(name)
        const badge = <Badge color="zinc">{name}</Badge>
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
