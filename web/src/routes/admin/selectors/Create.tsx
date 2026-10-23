import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import { useCreateSelector } from '~/queries/useRbac'
import { Heading } from '~/components/catalyst/heading'
import { SelectorForm } from '~/components/SelectorForm'

export const Route = createFileRoute('/_app/manage/content-selectors/new')({
  component: CreateSelector,
})

/** New content selector; a 400 (an invalid glob) or 409 (a taken name) shows inline. */
function CreateSelector() {
  const navigate = useNavigate()
  const create = useCreateSelector()

  return (
    <section className="space-y-6">
      <div>
        <Link
          to="/manage/content-selectors"
          className="text-sm/6 text-sky-600 hover:underline dark:text-sky-400"
        >
          ← Content selectors
        </Link>
        <Heading className="mt-1">New content selector</Heading>
      </div>
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
    </section>
  )
}
