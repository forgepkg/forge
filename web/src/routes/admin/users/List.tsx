import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import { accessLevel, ADMIN_ROLE, WRITER_ROLE } from '~/api/rbac'
import {
  authSourceLabel,
  isServiceAccount,
  type UserStatus,
  type UserView,
} from '~/api/users'
import { useDeleteUser, useUsers } from '~/queries/useUsers'
import { useRoles } from '~/queries/useRbac'
import { AccessBadge } from '~/components/AccessBadge'
import {
  Avatar,
  Button,
  CellActions,
  Dialog,
  Page,
  PageHeader,
  Panel,
  Skeleton,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  type Tone,
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
 * they hold and their status (active, inactive, or invited: their user has
 * not chosen a password yet), links to the create page
 * (`/manage/users/new`) and each user's page (where an account is
 * deactivated, reactivated or signed out everywhere), and deletes after a
 * confirmation dialog, which suggests deactivating an active account instead
 * when it should be kept. Every account is named by a UPN. Service accounts
 * are listed on their own screen (`/manage/service-accounts`).
 */
function UsersList() {
  const users = useUsers()
  const people = users.data?.filter((u) => !isServiceAccount(u))
  const roles = useRoles()
  const roleIds = new Map((roles.data ?? []).map((r) => [r.name, r.id]))
  const del = useDeleteUser()
  const [pendingDelete, setPendingDelete] = useState<number | null>(null)
  const doomed = people?.find((u) => u.id === pendingDelete)

  function confirmDelete(id: number) {
    del.mutate(id, { onSettled: () => setPendingDelete(null) })
  }

  return (
    <Page>
      <PageHeader
        title="Users"
        description="Invite and remove users, assign their roles, and manage each user's API tokens."
        actions={
          <Button variant="primary" icon="Plus" href="/manage/users/new">
            New user
          </Button>
        }
      />

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
          description={
            <>
              Their sessions, tokens and role assignments go with the account,
              and clients that use its tokens start failing. This cannot be
              undone.
              {doomed.active && (
                <>
                  {' '}
                  To keep the account, deactivate it on{' '}
                  <Link
                    to="/manage/users/$userId"
                    params={{ userId: String(doomed.id) }}
                    className="fg-link"
                  >
                    its page
                  </Link>{' '}
                  instead: every sign-in is refused, and it can be reactivated.
                </>
              )}
            </>
          }
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
      ) : (people?.length ?? 0) === 0 ? (
        <EmptyState title="No users yet" icon="Users">
          Invite the first one with <strong>New user</strong>.
        </EmptyState>
      ) : (
        <Panel title="All users" count={people!.length} flush>
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
              {people!.map((user) => (
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

const STATUS: Record<UserStatus, { tone: Tone; label: string }> = {
  active: { tone: 'ok', label: 'active' },
  inactive: { tone: 'neutral', label: 'inactive' },
  invited: { tone: 'neutral', label: 'invited' },
  invitation_expired: { tone: 'warn', label: 'invitation expired' },
}

/** A user's status; an older server's view without one falls back to `active`. */
export function UserStatusBadge({ status }: { status: UserStatus | undefined }) {
  const { tone, label } = STATUS[status ?? 'active'] ?? STATUS.active
  return (
    <StatusBadge tone={tone} icon={status === 'invited' ? 'Mail' : undefined}>
      {label}
    </StatusBadge>
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
        <UserStatusBadge status={user.status} />
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
