import { createFileRoute, useNavigate } from '@tanstack/react-router'

import type { UpdateRealm } from '~/api/realms'
import { useRealm, useUpdateRealm } from '~/queries/useRealms'
import {
  RealmForm,
  toRealmConfig,
  type RealmFormValues,
} from '~/components/RealmForm'
import { Heading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { ErrorState } from '~/components/ErrorState'

export const Route = createFileRoute('/_app/admin/realms/$realmId')({
  component: EditRealmScreen,
})

/**
 * Edit-realm screen (§12.7). Loads the (redacted) realm, seeds the shared
 * form, and PATCHes an `UpdateRealm`. Secrets are **write-only**: never seeded
 * from the GET and only included when the admin typed a new one (a blank field
 * keeps the stored secret). The built-in local realm has no config — only
 * name/enabled are sent.
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
        onCancel={() => void navigate({ to: '/admin/realms' })}
      />
    </section>
  )
}
