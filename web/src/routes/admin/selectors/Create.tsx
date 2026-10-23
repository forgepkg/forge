import { createFileRoute, useNavigate } from '@tanstack/react-router'

import { useCreateSelector } from '~/queries/useRbac'
import { Page, PageHeader } from '~/components/ui'
import { SelectorForm } from '~/components/SelectorForm'

export const Route = createFileRoute('/_app/manage/content-selectors/new')({
  component: CreateSelector,
})

/** New content selector; a 400 (an invalid glob) or 409 (a taken name) shows inline. */
function CreateSelector() {
  const navigate = useNavigate()
  const create = useCreateSelector()

  return (
    <Page>
      <PageHeader
        title="New content selector"
        crumbs={[
          { label: 'Content selectors', to: '/manage/content-selectors' },
          { label: 'New content selector' },
        ]}
      />
      <SelectorForm
        mode="create"
        submitting={create.isPending}
        serverError={
          create.isError ? create.error.body || create.error.message : null
        }
        onSubmit={(values) =>
          create.mutate(values, {
            onSuccess: () => void navigate({ to: '/manage/content-selectors' }),
          })
        }
        onCancel={() => void navigate({ to: '/manage/content-selectors' })}
      />
    </Page>
  )
}
