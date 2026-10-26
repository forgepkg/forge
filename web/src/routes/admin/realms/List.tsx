import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type {
  CredentialForwardingConfig,
  OidcRealmConfig,
  RealmView,
  TrustedHeaderConfig,
  WorkloadIdentityConfig,
} from '~/api/realms'
import {
  useDeleteRealm,
  useRealms,
  useReorderRealms,
  useUpdateRealm,
} from '~/queries/useRealms'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { disableRealmWarning, REALM_KINDS } from '~/components/RealmForm'
import {
  Button,
  CellActions,
  CellStack,
  Chip,
  Dialog,
  Icon,
  Notice,
  Page,
  PageHeader,
  Panel,
  Skeleton,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/ui'

export const Route = createFileRoute('/_app/manage/realms')({
  component: RealmsList,
})

/**
 * Admin authentication-realms screen. Lists realms in priority order
 * (lower = tried/listed first) with up/down reordering (the full new id order
 * is PUT to `/admin/realms/order`), an enable/disable switch, edit links, and
 * delete-with-confirm (a dialog). The built-in `local` realm cannot be
 * deleted — only disabled. Disabling a realm people sign in with (local,
 * OIDC, credential forwarding) asks first in a dialog and says whose logins
 * stop. The server refuses (409) a disable or delete that would leave no
 * enabled realm to sign in with interactively (local or OIDC); its reason is
 * shown inline.
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
  const list = realms.data ?? []
  const deleting = list.find((r) => r.id === pendingDelete)

  return (
    <Page>
      <PageHeader
        title="Authentication"
        description="Realms are tried in this order when checking credentials and routing sign-ins."
        actions={
          <Button variant="primary" icon="Plus" href="/manage/realms/new">
            New realm
          </Button>
        }
      />

      {mutationError && (
        <Notice
          tone="danger"
          title={reorder.error ? 'Could not reorder the realms' : 'Could not delete the realm'}
        >
          {mutationError.body || mutationError.message}
        </Notice>
      )}

      {realms.isError ? (
        <ErrorState
          title="Could not load realms"
          message={realms.error?.message}
          onRetry={() => void realms.refetch()}
        />
      ) : realms.isLoading ? (
        <Skeleton variant="table" rows={3} columns={4} label="Loading realms…" />
      ) : list.length === 0 ? (
        <EmptyState title="No realms configured" icon="Shield">
          Create an OIDC or credential-forwarding realm with the button above.
        </EmptyState>
      ) : (
        <Panel title="Realms" count={list.length} flush>
          <Table caption="Authentication realms, in the order they are tried">
            <TableHead>
              <TableHeader width="128px">Order</TableHeader>
              <TableHeader>Name</TableHeader>
              <TableHeader width="200px">Kind</TableHeader>
              <TableHeader width="120px">Enabled</TableHeader>
              {/* `relative` keeps the visually hidden name inside the table's
                  scroll box, so it never widens the page on a phone. */}
              <TableHeader align="right" width="200px" className="relative">
                <span className="fg-sr">Actions</span>
              </TableHeader>
            </TableHead>
            <TableBody>
              {list.map((realm, index) => (
                <RealmRow
                  key={realm.id}
                  realm={realm}
                  position={index + 1}
                  isFirst={index === 0}
                  isLast={index === list.length - 1}
                  reordering={reorder.isPending}
                  onMoveUp={() => move(index, -1)}
                  onMoveDown={() => move(index, 1)}
                  onRequestDelete={() => setPendingDelete(realm.id)}
                />
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}

      <Dialog
        open={deleting !== undefined}
        onClose={() => setPendingDelete(null)}
        title={`Delete ${deleting?.name}?`}
        description="Forge stops using it for sign-in and credential checks, and its settings are lost. This cannot be undone."
        icon="Trash"
        tone="danger"
        confirmLabel={del.isPending ? 'Deleting…' : `Delete ${deleting?.name}`}
        confirmVariant="danger-solid"
        confirmIcon="Trash"
        confirmDisabled={del.isPending}
        onConfirm={() => deleting && confirmDelete(deleting.id)}
      />
    </Page>
  )
}

/**
 * One realm in the list: its place in the order with move up / down, its
 * name (linking to the edit screen) over what it connects to, its kind, the
 * enabled switch (asking first before disabling a realm people sign in
 * with), and the edit and delete actions.
 */
function RealmRow({
  realm,
  position,
  isFirst,
  isLast,
  reordering,
  onMoveUp,
  onMoveDown,
  onRequestDelete,
}: {
  realm: RealmView
  position: number
  isFirst: boolean
  isLast: boolean
  reordering: boolean
  onMoveUp: () => void
  onMoveDown: () => void
  onRequestDelete: () => void
}) {
  const update = useUpdateRealm(realm.id)
  // Disabling a realm people sign in with ends their logins (in the browser,
  // over NuGet Basic, or both), and disabling a workload-identity realm
  // revokes the API keys it issued for good, so it waits for an explicit
  // confirmation.
  const disableWarning = disableRealmWarning(realm.kind, realm.name)
  const [confirmDisable, setConfirmDisable] = useState(false)

  function toggle(checked: boolean) {
    if (!checked && disableWarning) {
      setConfirmDisable(true)
      return
    }
    update.mutate({ enabled: checked })
  }

  function disableConfirmed() {
    update.mutate(
      { enabled: false },
      { onSettled: () => setConfirmDisable(false) },
    )
  }

  return (
    <TableRow>
      <TableCell nowrap>
        <span className="flex items-center gap-1">
          <span className="fg-prio-num mr-1">{position}</span>
          <Button
            size="sm"
            variant="ghost"
            icon="ArrowUp"
            iconOnly
            title="Move up"
            aria-label={`Move ${realm.name} up`}
            onClick={onMoveUp}
            disabled={isFirst || reordering}
          >
            Move up
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon="ArrowDown"
            iconOnly
            title="Move down"
            aria-label={`Move ${realm.name} down`}
            onClick={onMoveDown}
            disabled={isLast || reordering}
          >
            Move down
          </Button>
        </span>
      </TableCell>
      <TableCell lead>
        <CellStack sub={realmSummary(realm)}>
          <Link
            to="/manage/realms/$realmId"
            params={{ realmId: String(realm.id) }}
            className="fg-link-strong"
          >
            {realm.name}
          </Link>
        </CellStack>
      </TableCell>
      <TableCell>
        <Chip>{realm.kind}</Chip>
      </TableCell>
      <TableCell>
        <Switch
          label={`${realm.name} enabled`}
          hideLabel
          checked={realm.enabled}
          disabled={update.isPending || confirmDisable}
          onChange={toggle}
        />
        {/* The server refuses a toggle that would leave no enabled realm to
            sign in with interactively (local or OIDC); the switch stays at
            the stored state, so say why instead of silently snapping back. */}
        {update.isError && (
          <p role="alert" className="fg-field-error mt-2 max-w-xs whitespace-normal">
            <Icon name="Alert" size={14} />
            <span>
              Could not {update.variables?.enabled ? 'enable' : 'disable'}{' '}
              {realm.name}: {update.error.body || update.error.message}
            </span>
          </p>
        )}
        {disableWarning && (
          <Dialog
            open={confirmDisable}
            onClose={() => setConfirmDisable(false)}
            title={`Disable ${realm.name}?`}
            description={disableWarning}
            icon="Alert"
            tone="warn"
            confirmLabel={update.isPending ? 'Disabling…' : `Disable ${realm.name}`}
            confirmVariant="danger-solid"
            confirmDisabled={update.isPending}
            onConfirm={disableConfirmed}
          />
        )}
      </TableCell>
      <TableCell align="right">
        <CellActions>
          <Button size="sm" variant="ghost" icon="Pencil" href={`/manage/realms/${realm.id}`}>
            Edit
          </Button>
          {realm.kind !== 'local' && (
            <Button size="sm" variant="ghost" icon="Trash" onClick={onRequestDelete}>
              Delete
            </Button>
          )}
        </CellActions>
      </TableCell>
    </TableRow>
  )
}

/**
 * The line under a realm's name: what it connects to (the IdP's or CI
 * provider's issuer, the upstream URL, the header the proxy names the account
 * in), or what the built-in local realm is.
 */
function realmSummary(realm: RealmView): string | undefined {
  switch (realm.kind) {
    case 'local':
      return REALM_KINDS.local.description
    case 'oidc':
      return (realm.config as OidcRealmConfig).issuer || undefined
    case 'credential_forwarding':
      return (realm.config as CredentialForwardingConfig).url || undefined
    case 'workload_identity':
      return (realm.config as WorkloadIdentityConfig).issuer || undefined
    case 'trusted_header': {
      const header = (realm.config as TrustedHeaderConfig).username_header
      return header ? `Names the account in ${header}` : undefined
    }
    default:
      return undefined
  }
}
