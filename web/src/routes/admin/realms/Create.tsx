import { createFileRoute, useNavigate } from '@tanstack/react-router'

import { useCreateRealm } from '~/queries/useRealms'
import {
  RealmForm,
  toRealmConfig,
  type RealmFormValues,
} from '~/components/RealmForm'
import { Notice, Page, PageHeader } from '~/components/ui'

export const Route = createFileRoute('/_app/manage/realms/new')({
  component: CreateRealmScreen,
})

/**
 * Create-realm screen. Renders the shared kind-conditional `RealmForm` (oidc |
 * credential_forwarding | workload_identity — local is built in), posts a
 * `CreateRealm` body (the new realm is appended at the end of the order, as
 * the side column says), and on success navigates back to the list. Server
 * errors (400 invalid config such as a missing secret, 409 duplicate name)
 * are surfaced inline by the form.
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
          void navigate({ to: '/manage/realms' })
        },
      },
    )
  }

  return (
    <Page>
      <PageHeader
        title="New realm"
        crumbs={[{ label: 'Authentication', to: '/manage/realms' }, { label: 'New realm' }]}
        description="Choose how people or CI jobs authenticate through the realm. The kind cannot be changed later."
      />
      <RealmForm
        mode="create"
        submitting={create.isPending}
        serverError={
          create.isError ? create.error.body || create.error.message : null
        }
        onSubmit={handleSubmit}
        onCancel={() => void navigate({ to: '/manage/realms' })}
        aside={
          <Notice title="Added last">
            Realms are tried in order. A new realm comes after the existing ones;
            move it up under Authentication to try it earlier.
          </Notice>
        }
      />
    </Page>
  )
}
