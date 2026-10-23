import { useState } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'

import { useSelectors, useUpdateSelector } from '~/queries/useRbac'
import { Button, Notice, Page, PageHeader, Skeleton } from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'
import { SelectorDeleteConfirm } from '~/components/SelectorDeleteConfirm'
import { SelectorForm } from '~/components/SelectorForm'

export const Route = createFileRoute(
  '/_app/manage/content-selectors/$selectorId',
)({
  component: EditSelector,
})

/**
 * Edit a content selector's description and patterns (its name is fixed).
 * The save sends both lists, so an emptied include list is saved as the
 * match-every-package selector the form warns about. Deleting asks first,
 * in a dialog naming the grants that go with it.
 */
function EditSelector() {
  const { selectorId } = Route.useParams()
  const id = Number(selectorId)
  const navigate = useNavigate()
  const selectors = useSelectors()
  const update = useUpdateSelector(id)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const crumbs = [{ label: 'Content selectors', to: '/manage/content-selectors' }]

  if (selectors.isError) {
    return (
      <Page>
        <PageHeader title="Content selector" crumbs={crumbs} />
        <ErrorState
          title="Could not load content selector"
          message={selectors.error?.message}
          onRetry={() => void selectors.refetch()}
        />
      </Page>
    )
  }
  if (selectors.isLoading || !selectors.data) {
    return <Skeleton lines={4} label="Loading content selector…" />
  }
  const selector = selectors.data.find((s) => s.id === id)
  if (!selector) {
    return (
      <Page>
        <PageHeader title="Content selector" crumbs={crumbs} />
        <ErrorState
          title="Content selector not found"
          message="It may have been deleted."
        />
      </Page>
    )
  }

  return (
    <Page>
      <PageHeader
        title={
          <>
            Edit <span className="font-mono">{selector.name}</span>
          </>
        }
        crumbs={[...crumbs, { label: selector.name }]}
        actions={
          <Button variant="danger" icon="Trash" onClick={() => setConfirmDelete(true)}>
            Delete selector…
          </Button>
        }
      />

      {confirmDelete && (
        <SelectorDeleteConfirm
          selector={selector}
          onCancel={() => setConfirmDelete(false)}
          onDeleted={() => void navigate({ to: '/manage/content-selectors' })}
        />
      )}

      {update.isSuccess && <Notice tone="ok">Saved.</Notice>}

      <SelectorForm
        key={selector.id}
        mode="edit"
        existing={selector}
        submitting={update.isPending}
        serverError={
          update.isError ? update.error.body || update.error.message : null
        }
        onSubmit={({ description, includes, excludes }) =>
          update.mutate({ description, includes, excludes })
        }
        onCancel={() => void navigate({ to: '/manage/content-selectors' })}
      />
    </Page>
  )
}
