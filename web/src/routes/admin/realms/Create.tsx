import { createFileRoute, useNavigate } from '@tanstack/react-router'

import { useCreateRealm } from '~/queries/useRealms'
import {
  RealmForm,
  toRealmConfig,
  type RealmFormValues,
} from '~/components/RealmForm'

export const Route = createFileRoute('/_app/admin/realms/new')({
  component: CreateRealmScreen,
})

/**
 * Create-realm screen (§12.7). Renders the shared kind-conditional `RealmForm`
 * (oidc | credential_forwarding — local is built in), posts a `CreateRealm`
 * body (the new realm is appended at the end of the order), and on success
 * navigates back to the list. Server errors (400 invalid config such as a
 * missing secret, 409 duplicate name) are surfaced inline by the form.
 */
function CreateRealmScreen() {
  const navigate = useNavigate()
  const create = useCreateRealm()

  function handleSubmit(values: RealmFormValues) {
    create.mutate(
      {
        kind: values.kind,
        name: values.name.trim(),
        enabled: values.enabled,
        config: toRealmConfig(values),
      },
      {
        onSuccess: () => {
          void navigate({ to: '/admin/realms' })
        },
      },
    )
  }

  return (
    <section className="space-y-6">
      <h1 className="text-2xl font-semibold">New realm</h1>
      <RealmForm
        mode="create"
        submitting={create.isPending}
        serverError={
          create.isError ? create.error.body || create.error.message : null
        }
        onSubmit={handleSubmit}
        onCancel={() => void navigate({ to: '/admin/realms' })}
      />
    </section>
  )
}
