import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { UserView } from '~/api/users'
import { useCreateUser, useDeleteUser, useUsers } from '~/queries/useUsers'
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
import { Checkbox, CheckboxField } from '~/components/catalyst/checkbox'
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

export const Route = createFileRoute('/_app/manage/users')({
  component: UsersList,
})

/**
 * Admin users screen (plan §Phase 5). Lists every user with their admin / active
 * flags, offers an inline create form (`CreateUser`), links each user to its
 * token-management screen, and deletes with a confirm step. Slice 1 has no
 * update-user endpoint, so there is no edit-in-place beyond create/delete + the
 * per-user token screen.
 */
function UsersList() {
  const users = useUsers()
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
          Create and remove users, and manage each user&apos;s API tokens.
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
              <TableHeader>Role</TableHeader>
              <TableHeader>Status</TableHeader>
              <TableHeader>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.data!.map((user) => (
              <UserRow
                key={user.id}
                user={user}
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
  isDeleting,
  pendingDelete,
  onRequestDelete,
  onCancelDelete,
  onConfirmDelete,
}: {
  user: UserView
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
      <TableCell className="text-zinc-500 dark:text-zinc-400">
        {user.is_admin ? 'admin' : 'reader'}
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
            Tokens
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
 * Inline create-user form. Controlled state (matching the codebase's Login /
 * RepositoryForm pattern); on success the fields reset so several users can be
 * added in a row. The username/password requirements mirror the server's 400s.
 */
function CreateUserForm() {
  const create = useCreateUser()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isAdmin, setIsAdmin] = useState(false)
  const [active, setActive] = useState(true)

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!username.trim() || !password) return
    create.mutate(
      { username: username.trim(), password, is_admin: isAdmin, active },
      {
        onSuccess: () => {
          setUsername('')
          setPassword('')
          setIsAdmin(false)
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
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
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
      <div className="flex items-center gap-6">
        <CheckboxField>
          <Checkbox checked={isAdmin} onChange={(c) => setIsAdmin(c)} />
          <Label>Administrator</Label>
        </CheckboxField>
        <CheckboxField>
          <Checkbox checked={active} onChange={(c) => setActive(c)} />
          <Label>Active</Label>
        </CheckboxField>
      </div>
      {create.isError && (
        <InlineError>{create.error.body || create.error.message}</InlineError>
      )}
      <Button
        type="submit"
        disabled={create.isPending || !username.trim() || !password}
      >
        {create.isPending ? 'Creating…' : 'Create user'}
      </Button>
    </form>
  )
}
