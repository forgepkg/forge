import { useState } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'

import type { CredentialForwardingConfig, UpdateRealm } from '~/api/realms'
import {
  useCapturedPasswords,
  useConvertRealmToLocal,
  useRealm,
  useUpdateRealm,
} from '~/queries/useRealms'
import {
  RealmForm,
  toRealmConfig,
  type RealmFormValues,
} from '~/components/RealmForm'
import { Button } from '~/components/catalyst/button'
import { Heading, Subheading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { ErrorState } from '~/components/ErrorState'

export const Route = createFileRoute('/_app/manage/realms/$realmId')({
  component: EditRealmScreen,
})

/**
 * Edit-realm screen. Loads the (redacted) realm, seeds the shared
 * form, and PATCHes an `UpdateRealm`. Secrets are **write-only**: never seeded
 * from the GET and only included when the admin typed a new one (a blank field
 * keeps the stored secret). The built-in local realm has no config — only
 * name/enabled are sent. A credential-forwarding realm also shows how many of
 * its accounts keep a password hash and can switch them to local accounts.
 */
function EditRealmScreen() {
  const { realmId } = Route.useParams()
  const id = Number(realmId)
  const navigate = useNavigate()
  const realm = useRealm(id)
  const update = useUpdateRealm(id)

  if (realm.isError) {
    return (
      <ErrorState
        title="Could not load realm"
        message={realm.error?.message}
        onRetry={() => void realm.refetch()}
      />
    )
  }
  if (realm.isLoading || !realm.data) {
    return <Text>Loading realm…</Text>
  }

  function handleSubmit(values: RealmFormValues) {
    const body: UpdateRealm = {
      name: values.name.trim(),
      enabled: values.enabled,
    }
    // The local realm is config-less; for the others send the full config (a
    // blank secret is omitted by toRealmConfig, keeping the stored one).
    if (values.kind !== 'local') {
      body.config = toRealmConfig(values)
    }
    update.mutate(body)
  }

  return (
    <section className="space-y-6">
      <Heading>
        Edit <span className="font-mono">{realm.data.name}</span>
      </Heading>

      {update.isSuccess && (
        <p
          role="status"
          className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-sm/6 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
        >
          Saved.
        </p>
      )}

      <RealmForm
        mode="edit"
        existing={realm.data}
        submitting={update.isPending}
        serverError={
          update.isError ? update.error.body || update.error.message : null
        }
        onSubmit={handleSubmit}
        onCancel={() => void navigate({ to: '/manage/realms' })}
      />

      {realm.data.kind === 'credential_forwarding' && (
        <KeptPasswords
          realmId={id}
          keeping={
            (realm.data.config as CredentialForwardingConfig).capture_password_hash ?? false
          }
        />
      )}
    </section>
  )
}

/**
 * The realm's kept password hashes (`capture_password_hash`): how many of its
 * accounts keep one, and the switch of those accounts to local accounts with
 * the same password — the step that lets the upstream be retired. Asks for a
 * confirmation first: the switch cannot be undone from the UI.
 */
function KeptPasswords({ realmId, keeping }: { realmId: number; keeping: boolean }) {
  const counts = useCapturedPasswords(realmId)
  const convert = useConvertRealmToLocal(realmId)
  const [confirming, setConfirming] = useState(false)

  const captured = counts.data?.captured ?? 0
  return (
    <section className="space-y-3 border-t border-zinc-950/5 pt-6 dark:border-white/10">
      <Subheading>Kept passwords</Subheading>
      {counts.isError ? (
        <Text role="alert">Could not load the kept passwords: {counts.error.message}</Text>
      ) : !counts.data ? (
        <Text>Loading…</Text>
      ) : (
        <Text>
          {captured} of {counts.data.accounts}{' '}
          {counts.data.accounts === 1 ? 'account keeps' : 'accounts keep'} a password hash.
          {!keeping &&
            captured === 0 &&
            ' Check “Keep a password hash of successful logins” above to start keeping them.'}
        </Text>
      )}
      <Text>
        Switching an account to a local one moves its kept hash into a Forge
        password: the user signs in with the last password the upstream
        accepted, through the local realm (which must be enabled and, while
        this realm still asks the upstream, come before it), and the
        upstream is never asked about it again.
      </Text>

      {convert.isSuccess && (
        <p
          role="status"
          className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-sm/6 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
        >
          Switched {convert.data.converted} to local passwords;{' '}
          {convert.data.remaining} left on this realm.
        </p>
      )}
      {convert.isError && (
        <p
          role="alert"
          className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
        >
          {convert.error.body || convert.error.message}
        </p>
      )}

      {confirming ? (
        <div className="flex items-center gap-3">
          <Button
            color="red"
            disabled={convert.isPending}
            onClick={() =>
              convert.mutate(undefined, { onSettled: () => setConfirming(false) })
            }
          >
            {convert.isPending ? 'Switching…' : `Switch ${captured} to local passwords`}
          </Button>
          <Button plain onClick={() => setConfirming(false)}>
            Cancel
          </Button>
        </div>
      ) : (
        <Button outline disabled={captured === 0} onClick={() => setConfirming(true)}>
          Switch accounts to local passwords…
        </Button>
      )}
    </section>
  )
}
