import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import { accessLevel } from '~/api/rbac'
import { isServiceAccount, type UserView } from '~/api/users'
import { useDeleteUser, useUsers } from '~/queries/useUsers'
import { AccessBadge } from '~/components/AccessBadge'
import {
  Avatar,
  Button,
  CellActions,
  CellStack,
  Dialog,
  Page,
  PageHeader,
  Panel,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { InlineError } from '~/components/RbacLabels'
import { UserStatusBadge } from '../users/List'

export const Route = createFileRoute('/_app/manage/service-accounts')({
  component: ServiceAccountsList,
})

/**
 * Admin service accounts screen (#508). A service account stands for a
 * machine or a network (a CI pipeline, a build agent, a network the load
 * balancer admits): nobody signs in to it. It authenticates with the API
 * tokens an administrator issues for it on its page, or through the
 * trusted-header realm it belongs to. Lists every service account with what
 * it is for, its realm, its access level, when it was last used and its
 * status; links to the create page (`/manage/service-accounts/new`) and each
 * account's page, and deletes after a confirmation dialog.
 */
function ServiceAccountsList() {
  const users = useUsers()
  const accounts = users.data?.filter(isServiceAccount)
  const del = useDeleteUser()
  const [pendingDelete, setPendingDelete] = useState<number | null>(null)
  const doomed = accounts?.find((u) => u.id === pendingDelete)

  return (
    <Page>
      <PageHeader
        title="Service accounts"
        description="Accounts for machines and networks that nobody signs in to: a CI pipeline authenticates with the API tokens issued here, a network the load balancer admits through a trusted-header realm."
        actions={
          <Button variant="primary" icon="Plus" href="/manage/service-accounts/new">
            New service account
          </Button>
        }
      />

      {del.isError && <InlineError>{del.error.body || del.error.message}</InlineError>}

      {doomed && (
        <Dialog
          open
          onClose={() => setPendingDelete(null)}
          icon="Trash"
          tone="danger"
          title={`Delete ${doomed.username}?`}
          description={
            <>
              Its tokens and role assignments go with the account, and the
              clients and networks that use it start failing. This cannot be
              undone.
              {doomed.active && (
                <>
                  {' '}
                  To keep the account, deactivate it on{' '}
                  <Link
                    to="/manage/service-accounts/$userId"
                    params={{ userId: String(doomed.id) }}
                    className="fg-link"
                  >
                    its page
                  </Link>{' '}
                  instead: its tokens and its realm stop authenticating it,
                  and it can be reactivated.
                </>
              )}
            </>
          }
          confirmLabel={del.isPending ? 'Deleting…' : 'Delete service account'}
          confirmVariant="danger-solid"
          confirmDisabled={del.isPending}
          onConfirm={() =>
            del.mutate(doomed.id, { onSettled: () => setPendingDelete(null) })
          }
        />
      )}

      {users.isError ? (
        <ErrorState
          title="Could not load service accounts"
          message={users.error?.message}
          onRetry={() => void users.refetch()}
        />
      ) : users.isLoading ? (
        <Skeleton variant="table" rows={3} columns={5} label="Loading service accounts…" />
      ) : (accounts?.length ?? 0) === 0 ? (
        <EmptyState title="No service accounts yet" icon="Terminal">
          Create one with <strong>New service account</strong> for a CI
          pipeline, a build agent or a network your load balancer admits.
        </EmptyState>
      ) : (
        <Panel title="All service accounts" count={accounts!.length} flush>
          <Table caption="Service accounts">
            <TableHead>
              <TableHeader>Name</TableHeader>
              <TableHeader>Trusted-header realm</TableHeader>
              <TableHeader width="110px">Access</TableHeader>
              <TableHeader>Last used</TableHeader>
              <TableHeader width="110px">Status</TableHeader>
              <TableHeader align="right">
                <span className="fg-sr">Actions</span>
              </TableHeader>
            </TableHead>
            <TableBody>
              {accounts!.map((account) => (
                <ServiceAccountRow
                  key={account.id}
                  account={account}
                  onRequestDelete={() => setPendingDelete(account.id)}
                />
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}
    </Page>
  )
}

function ServiceAccountRow({
  account,
  onRequestDelete,
}: {
  account: UserView
  onRequestDelete: () => void
}) {
  return (
    <TableRow>
      <TableCell lead>
        <span className="fg-cell-user">
          <Avatar name={account.username} decorative />
          <CellStack sub={account.description || undefined}>
            <Link
              to="/manage/service-accounts/$userId"
              params={{ userId: String(account.id) }}
              className="fg-link-strong"
            >
              {account.username}
            </Link>
          </CellStack>
        </span>
      </TableCell>
      <TableCell>
        {account.realm ?? <span className="text-ink-faint">— (tokens only)</span>}
      </TableCell>
      <TableCell>
        <AccessBadge level={accessLevel(account.roles)} />
      </TableCell>
      <TableCell nowrap>{formatLastUsed(account.last_used_at)}</TableCell>
      <TableCell>
        <UserStatusBadge status={account.status} />
      </TableCell>
      <TableCell align="right" nowrap>
        <CellActions>
          <Button size="sm" variant="ghost" href={`/manage/service-accounts/${account.id}`}>
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

/** When a service account last authenticated; "never" before its first use. */
export function formatLastUsed(ts: string | null | undefined): string {
  if (!ts) return 'never'
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString()
}
