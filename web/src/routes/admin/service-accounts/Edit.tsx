import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import { isServiceAccount, type UserView } from '~/api/users'
import { useSetUserActive, useUpdateServiceAccount, useUsers } from '~/queries/useUsers'
import { useRealms } from '~/queries/useRealms'
import { useTokens } from '~/queries/useTokens'
import { tokenStatus } from '~/components/TokenBadges'
import {
  Button,
  Columns,
  Dialog,
  Notice,
  Page,
  PageHeader,
  Panel,
  SelectField,
  TextareaField,
} from '~/components/ui'
import { EmptyState } from '~/components/EmptyState'
import { InlineError } from '~/components/RbacLabels'
import { UserStatusBadge } from '../users/List'
import { EffectiveAccess, UserAccess, UserRoles, UserTokens } from '../users/Edit'
import { formatLastUsed } from './List'

export const Route = createFileRoute('/_app/manage/service-accounts/$userId')({
  component: ServiceAccountPage,
})

/**
 * One service account (#508): what it is for and the trusted-header realm
 * whose proxy names it (both edited here), deactivating and reactivating it,
 * its built-in access level (reader or writer, never admin), the roles it
 * holds and its effective access, and its API tokens: issued here (the
 * secret shown once), re-scoped and revoked. Nobody signs in to it, so there
 * is no invitation and no "sign out everywhere".
 */
function ServiceAccountPage() {
  const { userId } = Route.useParams()
  const id = Number(userId)

  // The account comes from the cached users list (there is no per-user GET).
  const users = useUsers()
  const account = users.data?.find((u) => u.id === id)
  const name = account ? account.username : `Service account #${id}`

  if (account && !isServiceAccount(account)) {
    return (
      <Page>
        <PageHeader
          title={name}
          crumbs={[{ label: 'Service accounts', to: '/manage/service-accounts' }, { label: name }]}
        />
        <EmptyState title="Not a service account" icon="Users">
          {account.username} is a user: manage it under{' '}
          <Link
            to="/manage/users/$userId"
            params={{ userId: String(account.id) }}
            className="fg-link"
          >
            Users
          </Link>
          .
        </EmptyState>
      </Page>
    )
  }

  return (
    <Page>
      <PageHeader
        title={name}
        crumbs={[{ label: 'Service accounts', to: '/manage/service-accounts' }, { label: name }]}
        meta={
          account
            ? [
                <>
                  Realm:{' '}
                  <span className="fg-strong">{account.realm ?? 'none (API tokens only)'}</span>
                </>,
                <>
                  Last used:{' '}
                  <span className="fg-strong">{formatLastUsed(account.last_used_at)}</span>
                </>,
              ]
            : undefined
        }
      >
        {account && <UserStatusBadge status={account.status} />}
      </PageHeader>

      {account && <ServiceAccountSettings key={account.id} account={account} />}

      <Columns asideLabel="Access" aside={<UserAccess userId={id} serviceAccount />}>
        <UserRoles userId={id} legacyAdmin={false} serviceAccount />
        <EffectiveAccess userId={id} />
        <UserTokens userId={id} inactive={account?.active === false} />
      </Columns>
    </Page>
  )
}

/**
 * The account's description and trusted-header realm (`PATCH
 * /admin/users/{id}`, with the fields that changed), and its state: deactivating stops its tokens and its
 * realm from authenticating it (the tokens are suspended, not revoked);
 * reactivating lets both work again. Each after a confirmation.
 */
function ServiceAccountSettings({ account }: { account: UserView }) {
  const realms = useRealms()
  const tokens = useTokens(account.id)
  const update = useUpdateServiceAccount()
  const setActive = useSetUserActive()
  const trustedHeaderRealms = (realms.data ?? []).filter((r) => r.kind === 'trusted_header')
  const [description, setDescription] = useState(account.description ?? '')
  const [realm, setRealm] = useState(account.realm ?? '')
  const [confirming, setConfirming] = useState<'deactivate' | 'reactivate' | null>(null)
  const [done, setDone] = useState<string | null>(null)
  const descriptionChanged = description.trim() !== (account.description ?? '')
  const realmChanged = realm !== (account.realm ?? '')
  const changed = descriptionChanged || realmChanged
  const liveTokens = tokens.data?.filter((t) => tokenStatus(t) === 'active').length

  // Only what was changed is sent: a realm renamed or deleted since the page
  // loaded would refuse the save of a new description.
  function save(e: React.FormEvent) {
    e.preventDefault()
    setDone(null)
    update.mutate(
      {
        id: account.id,
        ...(descriptionChanged && { description: description.trim() || null }),
        ...(realmChanged && { realm: realm || null }),
      },
      { onSuccess: () => setDone(`Saved ${account.username}.`) },
    )
  }

  function confirmState() {
    const active = confirming === 'reactivate'
    setActive.mutate(
      { id: account.id, active },
      {
        onSettled: () => setConfirming(null),
        onSuccess: () =>
          setDone(
            active
              ? `Reactivated ${account.username}.`
              : `Deactivated ${account.username}: its tokens and its realm no longer authenticate it.`,
          ),
      },
    )
  }

  const error = update.error ?? setActive.error

  return (
    <Panel
      as="form"
      onSubmit={save}
      title="Service account"
      description={
        account.active
          ? `${account.username} is active: its tokens${account.realm ? ' and its realm' : ''} authenticate it.`
          : `${account.username} is inactive: its tokens and its realm do not authenticate it, and its tokens are suspended, not revoked.`
      }
      footer={
        <>
          {account.active ? (
            <Button
              variant="danger"
              icon="Lock"
              className="mr-auto"
              disabled={setActive.isPending}
              onClick={() => {
                setDone(null)
                setConfirming('deactivate')
              }}
            >
              Deactivate…
            </Button>
          ) : (
            <Button
              className="mr-auto"
              disabled={setActive.isPending}
              onClick={() => {
                setDone(null)
                setConfirming('reactivate')
              }}
            >
              Reactivate…
            </Button>
          )}
          <Button type="submit" variant="primary" disabled={update.isPending || !changed}>
            {update.isPending ? 'Saving…' : 'Save'}
          </Button>
        </>
      }
    >
      <div className="fg-form">
        <TextareaField
          label="Description"
          optional
          rows={2}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          description="What it is for and who owns it."
        />
        <SelectField
          label="Trusted-header realm"
          value={realm}
          onChange={(e) => setRealm(e.target.value)}
          description="The realm whose proxy names the account; no other realm may. None: only its API tokens authenticate it."
        >
          <option value="">None (API tokens only)</option>
          {account.realm && !trustedHeaderRealms.some((r) => r.name === account.realm) && (
            <option value={account.realm}>{account.realm}</option>
          )}
          {trustedHeaderRealms.map((r) => (
            <option key={r.id} value={r.name}>
              {r.name}
            </option>
          ))}
        </SelectField>
      </div>
      {error ? (
        <InlineError>{error.body || error.message}</InlineError>
      ) : (
        done && <Notice tone="ok">{done}</Notice>
      )}

      <Dialog
        open={confirming === 'deactivate'}
        onClose={() => setConfirming(null)}
        icon="Lock"
        tone="warn"
        title={`Deactivate ${account.username}?`}
        description="Its API tokens and its trusted-header realm stop authenticating it now. The tokens are suspended, not revoked: they work again if the account is reactivated."
        confirmLabel={setActive.isPending ? 'Deactivating…' : 'Deactivate service account'}
        confirmVariant="danger"
        confirmDisabled={setActive.isPending}
        onConfirm={confirmState}
      />
      <Dialog
        open={confirming === 'reactivate'}
        onClose={() => setConfirming(null)}
        icon="Refresh"
        title={`Reactivate ${account.username}?`}
        description={
          liveTokens === 0
            ? 'Its realm authenticates it again. It has no token that would work again.'
            : `Its realm authenticates it again, and ${
                liveTokens === undefined
                  ? 'its unrevoked tokens work'
                  : liveTokens === 1
                    ? 'its 1 unrevoked token works'
                    : `its ${liveTokens} unrevoked tokens work`
              } again.`
        }
        confirmLabel={setActive.isPending ? 'Reactivating…' : 'Reactivate service account'}
        confirmDisabled={setActive.isPending}
        onConfirm={confirmState}
      />
    </Panel>
  )
}
