import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type { RealmView } from '~/api/realms'
import {
  useDeleteRealm,
  useRealms,
  useReorderRealms,
  useUpdateRealm,
} from '~/queries/useRealms'
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
import { Checkbox } from '~/components/catalyst/checkbox'
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

export const Route = createFileRoute('/_app/manage/realms')({
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
      <div className="flex items-start justify-between gap-4">
        <div>
          <Heading>Authentication</Heading>
          <Text className="mt-1">
            Realms are tried in this order when checking credentials and
            routing sign-ins.
          </Text>
        </div>
        <Button href="/manage/realms/new">New realm</Button>
      </div>

      {mutationError && (
        <p
          role="alert"
          className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
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
        <Text>Loading realms…</Text>
      ) : (realms.data?.length ?? 0) === 0 ? (
        <EmptyState title="No realms configured">
          Create an OIDC or credential-forwarding realm with the button above.
        </EmptyState>
      ) : (
        <Table striped>
          <TableHead>
            <TableRow>
              <TableHeader>Order</TableHeader>
              <TableHeader>Name</TableHeader>
              <TableHeader>Kind</TableHeader>
              <TableHeader>Enabled</TableHeader>
              <TableHeader>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
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
          </TableBody>
        </Table>
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
    <TableRow>
      <TableCell>
        <span className="flex items-center gap-1">
          <Button
            plain
            onClick={onMoveUp}
            disabled={isFirst || reordering}
            aria-label={`Move ${realm.name} up`}
            title="Move up"
          >
            ↑
          </Button>
          <Button
            plain
            onClick={onMoveDown}
            disabled={isLast || reordering}
            aria-label={`Move ${realm.name} down`}
            title="Move down"
          >
            ↓
          </Button>
        </span>
      </TableCell>
      <TableCell>
        <Link
          to="/manage/realms/$realmId"
          params={{ realmId: String(realm.id) }}
          className="font-medium text-sky-600 hover:underline dark:text-sky-400"
        >
          {realm.name}
        </Link>
      </TableCell>
      <TableCell>
        <RealmKindBadge kind={realm.kind} />
      </TableCell>
      <TableCell>
        <span className="flex items-center gap-2 text-zinc-600 dark:text-zinc-400">
          <Checkbox
            checked={realm.enabled}
            disabled={update.isPending}
            onChange={(checked) => update.mutate({ enabled: checked })}
            aria-label={`${realm.name} enabled`}
          />
          {realm.enabled ? 'enabled' : 'disabled'}
        </span>
      </TableCell>
      <TableCell>
        <span className="flex items-center gap-3">
          <Link
            to="/manage/realms/$realmId"
            params={{ realmId: String(realm.id) }}
            className="text-sky-600 hover:underline dark:text-sky-400"
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
            ))}
        </span>
      </TableCell>
    </TableRow>
  )
}

/** Color-coded kind badge (local = built-in, oidc, credential_forwarding). */
const KIND_COLORS: Record<
  string,
  React.ComponentProps<typeof Badge>['color']
> = {
  local: 'zinc',
  oidc: 'sky',
  credential_forwarding: 'violet',
  workload_identity: 'amber',
}

function RealmKindBadge({ kind }: { kind: RealmView['kind'] }) {
  return <Badge color={KIND_COLORS[kind] ?? 'zinc'}>{kind}</Badge>
}
