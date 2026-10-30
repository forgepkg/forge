import { useState } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'

import type { CredentialForwardingConfig, UpdateRealm } from '~/api/realms'
import { formatDateTime } from '~/lib/oci'
import {
  useCapturedPasswords,
  useConvertRealmToLocal,
  useRealm,
  useUpdateRealm,
} from '~/queries/useRealms'
import {
  REALM_KINDS,
  RealmForm,
  toRealmConfig,
  type RealmFormValues,
} from '~/components/RealmForm'
import { ErrorState } from '~/components/ErrorState'
import {
  Button,
  Dialog,
  FactList,
  Notice,
  Page,
  PageHeader,
  Panel,
  Skeleton,
  StatusBadge,
  useToast,
} from '~/components/ui'

export const Route = createFileRoute('/_app/manage/realms/$realmId')({
  component: EditRealmScreen,
})

/**
 * Edit-realm screen. Loads the (redacted) realm, seeds the shared
 * form, and PATCHes an `UpdateRealm`; a save is confirmed with a toast.
 * Secrets are **write-only**: never seeded from the GET and only included
 * when the admin typed a new one (a blank field keeps the stored secret). The
 * built-in local realm's config is only whether it accepts passwords from
 * clients. The side
 * column holds the realm's facts; a credential-forwarding realm's also shows
 * how many of its accounts keep a password hash and can switch them to local
 * accounts.
 */
function EditRealmScreen() {
  const { realmId } = Route.useParams()
  const id = Number(realmId)
  const navigate = useNavigate()
  const realm = useRealm(id)
  const update = useUpdateRealm(id)
  const toast = useToast()

  if (realm.isError) {
    return (
      <Page>
        <ErrorState
          title="Could not load realm"
          message={realm.error?.message}
          onRetry={() => void realm.refetch()}
        />
      </Page>
    )
  }
  if (realm.isLoading || !realm.data) {
    return (
      <Page>
        <Skeleton lines={6} label="Loading realm…" />
      </Page>
    )
  }

  function handleSubmit(values: RealmFormValues) {
    // The full config (a blank secret is omitted by toRealmConfig, keeping
    // the stored one).
    const body: UpdateRealm = {
      name: values.name.trim(),
      enabled: values.enabled,
      config: toRealmConfig(values),
    }
    update.mutate(body, {
      onSuccess: () => toast({ tone: 'ok', title: 'Realm saved' }),
    })
  }

  const data = realm.data
  const kind = REALM_KINDS[data.kind]
  return (
    <Page>
      <PageHeader
        title={data.name}
        icon={kind?.icon}
        crumbs={[{ label: 'Authentication', to: '/manage/realms' }, { label: data.name }]}
        description={kind?.description}
      >
        <StatusBadge tone={data.enabled ? 'ok' : 'neutral'}>
          {data.enabled ? 'enabled' : 'disabled'}
        </StatusBadge>
      </PageHeader>

      <RealmForm
        mode="edit"
        existing={data}
        submitting={update.isPending}
        serverError={
          update.isError ? update.error.body || update.error.message : null
        }
        onSubmit={handleSubmit}
        onCancel={() => void navigate({ to: '/manage/realms' })}
        aside={
          <>
            <Panel title="Details">
              <FactList
                items={[
                  { term: 'Kind', value: data.kind, mono: true },
                  { term: 'Created', value: formatDateTime(data.created_at) },
                  { term: 'Last changed', value: formatDateTime(data.updated_at) },
                ]}
              />
            </Panel>
            {data.kind === 'credential_forwarding' && (
              <KeptPasswords
                realmId={id}
                keeping={
                  (data.config as CredentialForwardingConfig).capture_password_hash ?? false
                }
              />
            )}
          </>
        }
      />
    </Page>
  )
}

/**
 * The realm's kept password hashes (`capture_password_hash`): how many of its
 * accounts keep one, and the switch of those accounts to local accounts with
 * the same password — the step that lets the upstream be retired. Asks for a
 * confirmation first, in a dialog: the switch cannot be undone from the UI.
 */
function KeptPasswords({ realmId, keeping }: { realmId: number; keeping: boolean }) {
  const counts = useCapturedPasswords(realmId)
  const convert = useConvertRealmToLocal(realmId)
  const [confirming, setConfirming] = useState(false)

  const captured = counts.data?.captured ?? 0
  return (
    <Panel title="Kept passwords">
      {counts.isError ? (
        <Notice tone="danger" title="Could not load the kept passwords">
          {counts.error.message}
        </Notice>
      ) : !counts.data ? (
        <Skeleton lines={1} label="Loading the kept passwords…" />
      ) : (
        <p className="fg-text">
          {captured} of {counts.data.accounts}{' '}
          {counts.data.accounts === 1 ? 'account keeps' : 'accounts keep'} a password hash.
          {!keeping &&
            captured === 0 &&
            ' Check “Keep a password hash of successful logins” to start keeping them.'}
        </p>
      )}
      <p className="fg-text fg-text--small">
        Switching an account to a local one moves its kept hash into a Forge
        password: the user signs in with the last password the upstream
        accepted, through the local realm (which must be enabled and, while
        this realm still asks the upstream, come before it), and the
        upstream is never asked about it again.
      </p>

      {convert.isSuccess && (
        <Notice tone="ok">
          Switched {convert.data.converted} to local passwords;{' '}
          {convert.data.remaining} left on this realm.
        </Notice>
      )}
      {convert.isError && (
        <Notice tone="danger" title="Could not switch the accounts">
          {convert.error.body || convert.error.message}
        </Notice>
      )}

      <div>
        <Button disabled={captured === 0} onClick={() => setConfirming(true)}>
          Switch accounts to local passwords…
        </Button>
      </div>

      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={`Switch ${captured} ${captured === 1 ? 'account' : 'accounts'} to local passwords?`}
        description="Each one then signs in with the last password the upstream accepted for it, through the local realm, and the upstream is never asked about it again. This cannot be undone from the UI."
        icon="Alert"
        tone="warn"
        confirmLabel={
          convert.isPending ? 'Switching…' : `Switch ${captured} to local passwords`
        }
        confirmVariant="danger-solid"
        confirmDisabled={convert.isPending}
        onConfirm={() =>
          convert.mutate(undefined, { onSettled: () => setConfirming(false) })
        }
      />
    </Panel>
  )
}
