import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { RoleView } from '~/api/rbac'
import { useCreateRole, useRoles } from '~/queries/useRbac'
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
import { Field, Label } from '~/components/catalyst/fieldset'
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
import { InlineError } from '~/components/RbacLabels'
import { RoleDeleteConfirm } from '~/components/RoleDeleteConfirm'

export const Route = createFileRoute('/_app/manage/roles')({
  component: RolesList,
})

/**
 * Admin roles screen. Lists every role with its description, whether it is
 * built in, and how many grants and users it holds; creates a role (then
 * opens it, to add its grants and members); and deletes a role that is not
 * built in after a confirmation that names the users and grants it takes
 * along.
 */
function RolesList() {
  const roles = useRoles()
  const [pendingDelete, setPendingDelete] = useState<RoleView | null>(null)

  return (
    <section className="space-y-6">
      <div>
        <Heading>Roles</Heading>
        <Text className="mt-1">
          A role grants actions on repositories to the users who hold it. The
          built-in roles cannot be deleted: <strong>admin</strong> may do
          everything, <strong>anonymous</strong> applies to callers who do not
          sign in (and its reads to everyone), and{' '}
          <strong>authenticated</strong> is the open access of installs
          upgraded from before roles existed.
        </Text>
      </div>

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
        <Text>Loading roles…</Text>
      ) : (roles.data?.length ?? 0) === 0 ? (
        <EmptyState title="No roles">Create a role with the form above.</EmptyState>
      ) : (
        <Table striped>
          <TableHead>
            <TableRow>
              <TableHeader>Name</TableHeader>
              <TableHeader>Description</TableHeader>
              <TableHeader>Grants</TableHeader>
              <TableHeader>Users</TableHeader>
              <TableHeader>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {roles.data!.map((role) => (
              <TableRow key={role.id}>
                <TableCell>
                  <span className="flex items-center gap-2">
                    <Link
                      to="/manage/roles/$roleId"
                      params={{ roleId: String(role.id) }}
                      className="font-medium text-sky-600 hover:underline dark:text-sky-400"
                    >
                      {role.name}
                    </Link>
                    {role.builtin && <Badge color="zinc">built-in</Badge>}
                  </span>
                </TableCell>
                <TableCell className="whitespace-normal text-zinc-500 dark:text-zinc-400">
                  {role.description || '—'}
                </TableCell>
                <TableCell>{role.grant_count}</TableCell>
                <TableCell>{role.user_count}</TableCell>
                <TableCell>
                  {role.builtin ? (
                    <span className="text-zinc-400 dark:text-zinc-500">—</span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setPendingDelete(role)}
                      className="font-medium text-red-600 hover:underline dark:text-red-400"
                      aria-label={`Delete ${role.name}`}
                    >
                      Delete
                    </button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </section>
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
    <form
      onSubmit={submit}
      className="space-y-4 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <Subheading>New role</Subheading>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field>
          <Label>Name</Label>
          <Input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. ci-pushers"
          />
        </Field>
        <Field>
          <Label>Description</Label>
          <Input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
      </div>
      {create.isError && (
        <InlineError>{create.error.body || create.error.message}</InlineError>
      )}
      <Button type="submit" disabled={create.isPending || !name.trim()}>
        {create.isPending ? 'Creating…' : 'Create role'}
      </Button>
    </form>
  )
}
