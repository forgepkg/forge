import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { UserView } from '~/api/users'
import { useCreateUser, useDeleteUser, useUsers } from '~/queries/useUsers'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'

export const Route = createFileRoute('/_app/admin/users')({
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
        <h1 className="text-2xl font-semibold">Users</h1>
        <p className="mt-1 text-slate-600">
          Create and remove users, and manage each user&apos;s API tokens.
        </p>
      </div>

      <CreateUserForm />

      {del.isError && (
        <p
          role="alert"
          className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700"
        >
          {del.error.body || del.error.message}
        </p>
      )}

      {users.isError ? (
        <ErrorState
          title="Could not load users"
          message={users.error?.message}
          onRetry={() => void users.refetch()}
        />
      ) : users.isLoading ? (
        <p className="text-slate-500">Loading users…</p>
      ) : (users.data?.length ?? 0) === 0 ? (
        <EmptyState title="No users yet">
          Create the first user with the form above.
        </EmptyState>
      ) : (
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-slate-200 text-left text-slate-500">
              <th className="py-2 pr-4 font-medium">Username</th>
              <th className="py-2 pr-4 font-medium">Role</th>
              <th className="py-2 pr-4 font-medium">Status</th>
              <th className="py-2 pr-4 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
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
          </tbody>
        </table>
      )}
    </section>
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
    <tr className="border-b border-slate-100 last:border-0">
      <td className="py-2 pr-4">
        <button
          type="button"
          onClick={() =>
            void navigate({
              to: '/admin/users/$userId',
              params: { userId: String(user.id) },
            })
          }
          className="font-medium text-sky-700 hover:underline"
        >
          {user.username}
        </button>
      </td>
      <td className="py-2 pr-4 text-slate-600">
        {user.is_admin ? 'admin' : 'reader'}
      </td>
      <td className="py-2 pr-4">
        <span className={user.active ? 'text-emerald-700' : 'text-slate-400'}>
          {user.active ? 'active' : 'inactive'}
        </span>
      </td>
      <td className="py-2 pr-4">
        <span className="flex items-center gap-3">
          <Link
            to="/admin/users/$userId"
            params={{ userId: String(user.id) }}
            className="text-sky-700 hover:underline"
          >
            Tokens
          </Link>
          {pendingDelete ? (
            <span className="flex items-center gap-2">
              <button
                type="button"
                onClick={onConfirmDelete}
                disabled={isDeleting}
                className="text-red-700 hover:underline disabled:opacity-60"
              >
                {isDeleting ? 'Deleting…' : 'Confirm'}
              </button>
              <button
                type="button"
                onClick={onCancelDelete}
                className="text-slate-500 hover:underline"
              >
                Cancel
              </button>
            </span>
          ) : (
            <button
              type="button"
              onClick={onRequestDelete}
              className="text-red-700 hover:underline"
            >
              Delete
            </button>
          )}
        </span>
      </td>
    </tr>
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
      className="space-y-4 rounded-lg border border-slate-200 bg-white p-4"
    >
      <h2 className="font-medium text-slate-900">New user</h2>
      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block text-sm">
          <span className="mb-1 block font-medium text-slate-700">
            Username
          </span>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded border border-slate-300 px-3 py-2"
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block font-medium text-slate-700">
            Password
          </span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded border border-slate-300 px-3 py-2"
          />
        </label>
      </div>
      <div className="flex items-center gap-6 text-sm">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={isAdmin}
            onChange={(e) => setIsAdmin(e.target.checked)}
          />
          <span className="text-slate-700">Administrator</span>
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={active}
            onChange={(e) => setActive(e.target.checked)}
          />
          <span className="text-slate-700">Active</span>
        </label>
      </div>
      {create.isError && (
        <p
          role="alert"
          className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700"
        >
          {create.error.body || create.error.message}
        </p>
      )}
      <button
        type="submit"
        disabled={create.isPending || !username.trim() || !password}
        className="rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-60"
      >
        {create.isPending ? 'Creating…' : 'Create user'}
      </button>
    </form>
  )
}
