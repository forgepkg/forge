import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { RepoView } from '~/api/repositories'
import {
  useRepository,
  useUpdateRepository,
} from '~/queries/useRepositories'
import {
  RepositoryForm,
  capitalize,
  kindIcon,
  repositoryFacts,
  toUpdateBody,
  type RepoFormValues,
} from '~/components/RepositoryForm'
import {
  Columns,
  Icon,
  Page,
  PageHeader,
  Skeleton,
  StatusBadge,
  useToast,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'
import { ProxyCachePanel } from '~/components/ProxyCachePanel'
import { AnonymousAccessPanel } from '~/components/AnonymousAccessPanel'
import { IMPORT_FORMATS } from '~/api/imports'

export const Route = createFileRoute('/_app/manage/repositories/$repo')({
  component: EditRepository,
})

/**
 * Edit-repository screen. Loads the (redacted) repository, seeds the shared
 * form, and PUTs a partial `UpdateRepo` holding only the changed fields
 * (`toUpdateBody`); a save is confirmed with a toast. The `upstream_password`
 * is **write-only**: it is never seeded from the GET and is only included in
 * the update when the admin typed a new one (an empty field leaves the stored
 * secret unchanged); "Remove stored credentials" clears it explicitly. The
 * header links group repos to the Members editor, hosted NuGet, Helm and
 * Docker repositories to the import from Nexus, and every other repository to
 * its retention policy. Beside the form: for proxies,
 * their cache invalidation, and the repository's anonymous access (the flag
 * together with the anonymous role's grants that cover it, read-only, linking
 * to the role).
 */
function EditRepository() {
  const { repo: name } = Route.useParams()
  const navigate = useNavigate()
  const toast = useToast()
  const repo = useRepository(name)
  const update = useUpdateRepository(name)
  // The view the server returned for the last save: the form is re-seeded
  // from it, so a typed password or a "remove credentials" choice is not
  // re-sent by the next save.
  const [saved, setSaved] = useState<{ view: RepoView; n: number } | null>(
    null,
  )

  const crumbs = [
    { label: 'Repositories', to: '/manage/repositories' },
    { label: name },
  ]

  if (repo.isError) {
    return (
      <Page>
        <PageHeader title={`Edit ${name}`} crumbs={crumbs} />
        <ErrorState
          title="Could not load repository"
          message={repo.error?.message}
          onRetry={() => void repo.refetch()}
        />
      </Page>
    )
  }
  if (repo.isLoading || !repo.data) {
    return (
      <Page>
        <PageHeader title={`Edit ${name}`} crumbs={crumbs} />
        <Skeleton lines={6} label="Loading repository…" />
      </Page>
    )
  }

  // (Only while it is still this repository: the route can switch params.)
  const current = saved?.view.name === name ? saved.view : repo.data

  function handleSubmit(values: RepoFormValues) {
    update.mutate(toUpdateBody(values, current), {
      onSuccess: (updated) => {
        setSaved((prev) => ({ view: updated, n: (prev?.n ?? 0) + 1 }))
        toast({ tone: 'ok', title: `Saved ${updated.name}` })
        // The name may have changed; keep the URL in sync.
        if (updated.name !== name) {
          void navigate({
            to: '/manage/repositories/$repo',
            params: { repo: updated.name },
          })
        }
      },
    })
  }

  return (
    <Page>
      <PageHeader
        title={`Edit ${repo.data.name}`}
        icon={kindIcon(current.kind)}
        crumbs={crumbs}
        kind={current.kind}
        format={current.format}
        meta={repositoryFacts(current).map(capitalize)}
        actions={
          <>
            {repo.data.kind === 'group' && (
              <Link
                to="/manage/repositories/$repo/members"
                params={{ repo: repo.data.name }}
                className="fg-btn fg-btn--secondary fg-btn--md"
              >
                <Icon name="Users" size={16} />
                <span>Manage members</span>
              </Link>
            )}
            {repo.data.kind === 'hosted' &&
              IMPORT_FORMATS.includes(repo.data.format) && (
                <Link
                  to="/manage/repositories/$repo/import"
                  params={{ repo: repo.data.name }}
                  className="fg-btn fg-btn--secondary fg-btn--md"
                >
                  <Icon name="Download" size={16} />
                  <span>Import from Nexus</span>
                </Link>
              )}
            {repo.data.kind !== 'group' && (
              <Link
                to="/manage/repositories/$repo/retention"
                params={{ repo: repo.data.name }}
                className="fg-btn fg-btn--secondary fg-btn--md"
              >
                <Icon name="Clock" size={16} />
                <span>Retention</span>
              </Link>
            )}
          </>
        }
      >
        {!current.online && <StatusBadge>offline</StatusBadge>}
      </PageHeader>

      <Columns
        asideLabel={current.kind === 'proxy' ? 'Cache and access' : 'Access'}
        aside={
          <>
            {current.kind === 'proxy' && (
              <ProxyCachePanel key={current.name} repo={current} />
            )}
            <AnonymousAccessPanel repo={current} />
          </>
        }
      >
        <RepositoryForm
          key={`${name}:${saved?.n ?? 0}`}
          mode="edit"
          existing={current}
          submitting={update.isPending}
          serverError={
            update.isError ? update.error.body || update.error.message : null
          }
          onSubmit={handleSubmit}
          onCancel={() => void navigate({ to: '/manage/repositories' })}
        />
      </Columns>
    </Page>
  )
}
