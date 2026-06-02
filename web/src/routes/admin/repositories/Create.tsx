import { createFileRoute, useNavigate } from '@tanstack/react-router'

import { useCreateRepository } from '~/queries/useRepositories'
import {
  RepositoryForm,
  toCreateBody,
  type RepoFormValues,
} from '~/components/RepositoryForm'

export const Route = createFileRoute('/_app/admin/repositories/new')({
  component: CreateRepository,
})

/**
 * Create-repository screen (plan §Phase 4). Renders the shared kind-conditional
 * `RepositoryForm`, posts a `CreateRepo` body, and on success navigates to the
 * new repository's edit page. Server errors (e.g. 409 name conflict, 400 invalid
 * remote URL) are surfaced inline by the form.
 */
function CreateRepository() {
  const navigate = useNavigate()
  const create = useCreateRepository()

  function handleSubmit(values: RepoFormValues) {
    create.mutate(toCreateBody(values), {
      onSuccess: (repo) => {
        void navigate({
          to: '/admin/repositories/$repo',
          params: { repo: repo.name },
        })
      },
    })
  }

  return (
    <section className="space-y-6">
      <h1 className="text-2xl font-semibold">New repository</h1>
      <RepositoryForm
        mode="create"
        submitting={create.isPending}
        serverError={
          create.isError ? create.error.body || create.error.message : null
        }
        onSubmit={handleSubmit}
        onCancel={() => void navigate({ to: '/admin/repositories' })}
      />
    </section>
  )
}
