import { createFileRoute, useNavigate } from '@tanstack/react-router'

import { useCreateRepository, useFormats } from '~/queries/useRepositories'
import { Page, PageHeader } from '~/components/ui'
import {
  RepositoryForm,
  toCreateBody,
  type RepoFormValues,
} from '~/components/RepositoryForm'

export const Route = createFileRoute('/_app/manage/repositories/new')({
  component: CreateRepository,
})

/**
 * Create-repository screen. Renders the shared kind-conditional
 * `RepositoryForm`, posts a `CreateRepo` body, and on success navigates to the
 * new repository's edit page. Server errors (e.g. 409 name conflict, 400 invalid
 * remote URL) are surfaced inline by the form.
 */
function CreateRepository() {
  const navigate = useNavigate()
  const create = useCreateRepository()
  // Without the list (loading, or an older server) the form offers NuGet.
  const formats = useFormats()

  function handleSubmit(values: RepoFormValues) {
    create.mutate(toCreateBody(values), {
      onSuccess: (repo) => {
        void navigate({
          to: '/manage/repositories/$repo',
          params: { repo: repo.name },
        })
      },
    })
  }

  return (
    <Page>
      <PageHeader
        title="New repository"
        crumbs={[
          { label: 'Repositories', to: '/manage/repositories' },
          { label: 'New repository' },
        ]}
        description="Choose what the repository serves and where its contents come from. The format and the kind cannot be changed later."
      />
      <RepositoryForm
        mode="create"
        formats={formats.data}
        submitting={create.isPending}
        serverError={
          create.isError ? create.error.body || create.error.message : null
        }
        onSubmit={handleSubmit}
        onCancel={() => void navigate({ to: '/manage/repositories' })}
      />
    </Page>
  )
}
