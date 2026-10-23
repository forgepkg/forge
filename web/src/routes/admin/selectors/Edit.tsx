import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import { useSelectors, useUpdateSelector } from '~/queries/useRbac'
import { Button } from '~/components/catalyst/button'
import { Heading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
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
 * naming the grants that go with it.
 */
function EditSelector() {
  const { selectorId } = Route.useParams()
  const id = Number(selectorId)
  const navigate = useNavigate()
  const selectors = useSelectors()
  const update = useUpdateSelector(id)
  const [confirmDelete, setConfirmDelete] = useState(false)

  if (selectors.isError) {
    return (
      <ErrorState
        title="Could not load content selector"
        message={selectors.error?.message}
        onRetry={() => void selectors.refetch()}
      />
    )
  }
  if (selectors.isLoading || !selectors.data) {
    return <Text>Loading content selector…</Text>
  }
  const selector = selectors.data.find((s) => s.id === id)
  if (!selector) {
    return (
      <ErrorState
        title="Content selector not found"
        message="It may have been deleted."
      />
    )
  }

  return (
    <section className="space-y-6">
      <div>
        <Link
          to="/manage/content-selectors"
          className="text-sm/6 text-sky-600 hover:underline dark:text-sky-400"
        >
          ← Content selectors
        </Link>
        <div className="mt-1 flex items-center justify-between gap-4">
          <Heading>
            Edit <span className="font-mono">{selector.name}</span>
          </Heading>
          {!confirmDelete && (
            <Button outline onClick={() => setConfirmDelete(true)}>
              Delete selector…
            </Button>
          )}
        </div>
      </div>

      {confirmDelete && (
        <SelectorDeleteConfirm
          selector={selector}
          onCancel={() => setConfirmDelete(false)}
          onDeleted={() => void navigate({ to: '/manage/content-selectors' })}
        />
      )}

      {update.isSuccess && (
        <p
          role="status"
          className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-sm/6 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
        >
          Saved.
        </p>
      )}

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
    </section>
  )
}
