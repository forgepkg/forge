import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'
import clsx from 'clsx'

import type { RealmView } from '~/api/realms'
import {
  useDeleteRealm,
  useRealms,
  useReorderRealms,
  useUpdateRealm,
} from '~/queries/useRealms'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'

export const Route = createFileRoute('/_app/admin/realms')({
  component: RealmsList,
})

/**
 * Admin authentication-realms screen (§12.7). Lists realms in priority order
 * (lower = tried/listed first) with up/down reordering (the full new id order
 * is PUT to `/admin/realms/order`), an enable/disable toggle, edit links, and
 * delete-with-confirm. The built-in `local` realm cannot be deleted — only
 * disabled.
 */
function RealmsList() {
  const realms = useRealms()
  const reorder = useReorderRealms()
  const del = useDeleteRealm()
  const [pendingDelete, setPendingDelete] = useState<number | null>(null)

  function move(index: number, direction: -1 | 1) {
    const list = realms.data
    if (!list) return
    const target = index + direction
    if (target < 0 || target >= list.length) return
    // The PUT must contain every realm id exactly once: swap in the full order.
    const order = list.map((r) => r.id)
    ;[order[index], order[target]] = [order[target], order[index]]
    reorder.mutate(order)
  }

  function confirmDelete(id: number) {
    del.mutate(id, { onSettled: () => setPendingDelete(null) })
  }

  const mutationError = reorder.error ?? del.error

  return (
    <section className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Authentication</h1>
          <p className="mt-1 text-slate-600">
            Realms are tried in this order when checking credentials and
            routing sign-ins.
          </p>
        </div>
        <Link
          to="/admin/realms/new"
          className="rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700"
        >
          New realm
        </Link>
      </div>

      {mutationError && (
        <p
          role="alert"
          className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700"
        >
          {mutationError.body || mutationError.message}
        </p>
      )}

      {realms.isError ? (
        <ErrorState
          title="Could not load realms"
          message={realms.error?.message}
          onRetry={() => void realms.refetch()}
        />
      ) : realms.isLoading ? (
        <p className="text-slate-500">Loading realms…</p>
      ) : (realms.data?.length ?? 0) === 0 ? (
        <EmptyState title="No realms configured">
          Create an OIDC or credential-forwarding realm with the button above.
        </EmptyState>
      ) : (
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-slate-200 text-left text-slate-500">
              <th className="py-2 pr-4 font-medium">Order</th>
              <th className="py-2 pr-4 font-medium">Name</th>
              <th className="py-2 pr-4 font-medium">Kind</th>
              <th className="py-2 pr-4 font-medium">Enabled</th>
              <th className="py-2 pr-4 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {realms.data!.map((realm, index) => (
              <RealmRow
                key={realm.id}
                realm={realm}
                isFirst={index === 0}
                isLast={index === realms.data!.length - 1}
                reordering={reorder.isPending}
                onMoveUp={() => move(index, -1)}
                onMoveDown={() => move(index, 1)}
                isDeleting={del.isPending && pendingDelete === realm.id}
                pendingDelete={pendingDelete === realm.id}
                onRequestDelete={() => setPendingDelete(realm.id)}
                onCancelDelete={() => setPendingDelete(null)}
                onConfirmDelete={() => confirmDelete(realm.id)}
              />
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function RealmRow({
  realm,
  isFirst,
  isLast,
  reordering,
  onMoveUp,
  onMoveDown,
  isDeleting,
  pendingDelete,
  onRequestDelete,
  onCancelDelete,
  onConfirmDelete,
}: {
  realm: RealmView
  isFirst: boolean
  isLast: boolean
  reordering: boolean
  onMoveUp: () => void
  onMoveDown: () => void
  isDeleting: boolean
  pendingDelete: boolean
  onRequestDelete: () => void
  onCancelDelete: () => void
  onConfirmDelete: () => void
}) {
  const update = useUpdateRealm(realm.id)

  return (
    <tr className="border-b border-slate-100 last:border-0">
      <td className="py-2 pr-4">
        <span className="flex items-center gap-1">
          <button
            type="button"
            onClick={onMoveUp}
            disabled={isFirst || reordering}
            aria-label={`Move ${realm.name} up`}
            title="Move up"
            className="rounded border border-slate-300 px-2 py-0.5 text-slate-600 hover:bg-slate-100 disabled:opacity-40"
          >
            ↑
          </button>
          <button
            type="button"
            onClick={onMoveDown}
            disabled={isLast || reordering}
            aria-label={`Move ${realm.name} down`}
            title="Move down"
            className="rounded border border-slate-300 px-2 py-0.5 text-slate-600 hover:bg-slate-100 disabled:opacity-40"
          >
            ↓
          </button>
        </span>
      </td>
      <td className="py-2 pr-4">
        <Link
          to="/admin/realms/$realmId"
          params={{ realmId: String(realm.id) }}
          className="font-medium text-sky-700 hover:underline"
        >
          {realm.name}
        </Link>
      </td>
      <td className="py-2 pr-4">
        <RealmKindBadge kind={realm.kind} />
      </td>
      <td className="py-2 pr-4">
        <label className="flex items-center gap-2 text-slate-700">
          <input
            type="checkbox"
            checked={realm.enabled}
            disabled={update.isPending}
            onChange={(e) => update.mutate({ enabled: e.target.checked })}
            aria-label={`${realm.name} enabled`}
            className="rounded border-slate-300"
          />
          {realm.enabled ? 'enabled' : 'disabled'}
        </label>
      </td>
      <td className="py-2 pr-4">
        <span className="flex items-center gap-3">
          <Link
            to="/admin/realms/$realmId"
            params={{ realmId: String(realm.id) }}
            className="text-sky-700 hover:underline"
          >
            Edit
          </Link>
          {realm.kind !== 'local' &&
            (pendingDelete ? (
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
            ))}
        </span>
      </td>
    </tr>
  )
}

/** Color-coded kind badge (local = built-in, oidc, credential_forwarding). */
function RealmKindBadge({ kind }: { kind: RealmView['kind'] }) {
  return (
    <span
      className={clsx(
        'rounded px-1.5 py-0.5 text-xs font-medium',
        kind === 'local' && 'bg-slate-100 text-slate-700',
        kind === 'oidc' && 'bg-sky-100 text-sky-800',
        kind === 'credential_forwarding' && 'bg-violet-100 text-violet-800',
        kind === 'workload_identity' && 'bg-amber-100 text-amber-800',
      )}
    >
      {kind}
    </span>
  )
}
