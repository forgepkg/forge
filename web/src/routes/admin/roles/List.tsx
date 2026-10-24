import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { RoleView } from '~/api/rbac'
import { useCreateRole, useRoles } from '~/queries/useRbac'
import {
  Button,
  CellActions,
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
  TextField,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { InlineError } from '~/components/RbacLabels'
import { RoleDeleteConfirm } from '~/components/RoleDeleteConfirm'

export const Route = createFileRoute('/_app/manage/roles')({
  component: RolesList,
})

/**
 * Admin roles screen. Lists every role with its description, whether it is
 * built in, and how many grants and users it holds; creates a role (then
 * opens it, to add its grants and members); and deletes a role that is not
 * built in after a confirmation dialog that names the users and grants it
 * takes along.
 */
function RolesList() {
  const roles = useRoles()
  const [pendingDelete, setPendingDelete] = useState<RoleView | null>(null)

  return (
    <Page>
      <PageHeader
        title="Roles"
        description={
          <>
            A role gives the users who hold it a level on repositories:{' '}
            <strong>read</strong>, <strong>write</strong> or{' '}
            <strong>delete</strong>, each including the ones below it. The
            built-in roles cannot be deleted: <strong>admin</strong> may do
            everything, <strong>anonymous</strong> applies to callers who do not
            sign in (and its reads to everyone), and{' '}
            <strong>authenticated</strong> reads and writes every repository,
            the open access from before roles existed; no user gets it
            automatically.
          </>
        }
      />

      <CreateRoleForm />

      {pendingDelete && (
        <RoleDeleteConfirm
          key={pendingDelete.id}
          role={pendingDelete}
          onCancel={() => setPendingDelete(null)}
          onDeleted={() => setPendingDelete(null)}
        />
      )}

      {roles.isError ? (
        <ErrorState
          title="Could not load roles"
          message={roles.error?.message}
          onRetry={() => void roles.refetch()}
        />
      ) : roles.isLoading ? (
        <Skeleton variant="table" rows={4} columns={4} label="Loading roles…" />
      ) : (roles.data?.length ?? 0) === 0 ? (
        <EmptyState title="No roles" icon="Lock">
          Create a role with the form above.
        </EmptyState>
      ) : (
        <Panel title="All roles" count={roles.data!.length} flush>
          <Table caption="Roles">
            <TableHead>
              <TableHeader>Name</TableHeader>
              <TableHeader>Description</TableHeader>
              <TableHeader align="right" width="96px">
                Grants
              </TableHeader>
              <TableHeader align="right" width="96px">
                Users
              </TableHeader>
              <TableHeader align="right" width="96px">
                <span className="fg-sr">Actions</span>
              </TableHeader>
            </TableHead>
            <TableBody>
              {roles.data!.map((role) => (
                <TableRow key={role.id}>
                  <TableCell lead>
                    <span className="flex flex-wrap items-center gap-2">
                      <Link
                        to="/manage/roles/$roleId"
                        params={{ roleId: String(role.id) }}
                        className="fg-link-strong"
                      >
                        {role.name}
                      </Link>
                      {role.builtin && <StatusBadge dot={false}>built-in</StatusBadge>}
                    </span>
                  </TableCell>
                  <TableCell>{role.description || '—'}</TableCell>
                  <TableCell align="right">{role.grant_count}</TableCell>
                  <TableCell align="right">{role.user_count}</TableCell>
                  <TableCell align="right">
                    {role.builtin ? (
                      <span className="text-ink-faint">—</span>
                    ) : (
                      <CellActions>
                        <Button
                          size="sm"
                          variant="ghost"
                          icon="Trash"
                          aria-label={`Delete ${role.name}`}
                          onClick={() => setPendingDelete(role)}
                        >
                          Delete
                        </Button>
                      </CellActions>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}
    </Page>
  )
}

/** Inline create-role form; a created role opens for its grants and members. */
function CreateRoleForm() {
  const create = useCreateRole()
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    create.mutate(
      { name: name.trim(), description: description.trim() },
      {
        onSuccess: (role) =>
          void navigate({
            to: '/manage/roles/$roleId',
            params: { roleId: String(role.id) },
          }),
      },
    )
  }

  return (
    <Panel
      as="form"
      onSubmit={submit}
      title="New role"
      description="Create the role here, then add its grants and members on its page."
      footer={
        <Button
          type="submit"
          variant="primary"
          icon="Plus"
          disabled={create.isPending || !name.trim()}
        >
          {create.isPending ? 'Creating…' : 'Create role'}
        </Button>
      }
    >
      <div className="fg-form">
        <div className="fg-fieldrow">
          <TextField
            label="Name"
            type="text"
            mono
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. ci-pushers"
          />
          <TextField
            label="Description"
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
      </div>
      {create.isError && (
        <InlineError>{create.error.body || create.error.message}</InlineError>
      )}
    </Panel>
  )
}
