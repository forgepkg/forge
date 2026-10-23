import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { RepoView } from '~/api/repositories'
import {
  useRepository,
  useUpdateRepository,
} from '~/queries/useRepositories'
import {
  RepositoryForm,
  toUpdateBody,
  type RepoFormValues,
} from '~/components/RepositoryForm'
import { Heading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { ErrorState } from '~/components/ErrorState'
import { ProxyCachePanel } from '~/components/ProxyCachePanel'
import { AnonymousAccessPanel } from '~/components/AnonymousAccessPanel'
import { IMPORT_FORMATS } from '~/api/imports'

export const Route = createFileRoute('/_app/manage/repositories/$repo')({
  component: EditRepository,
})

/**
 * Edit-repository screen (plan §Phase 4). Loads the (redacted) repository, seeds
 * the shared form, and PUTs a partial `UpdateRepo` holding only the changed
 * fields (`toUpdateBody`). The `upstream_password` is **write-only**: it is
 * never seeded from the GET and is only included in the update when the admin
 * typed a new one (an empty field leaves the stored secret unchanged — slice-1
 * redaction); "Remove stored credentials" clears it explicitly. Group repos
 * get a link to the Members editor; proxies, their cache invalidation; hosted
 * NuGet, Helm and Docker repositories, the import from Nexus. Below the form,
 * the repository's anonymous access: the flag together with the anonymous
 * role's grants that cover it (read-only, linking to the role).
 */
function EditRepository() {
  const { repo: name } = Route.useParams()
  const navigate = useNavigate()
  const repo = useRepository(name)
  const update = useUpdateRepository(name)
  // The view the server returned for the last save: the form is re-seeded
  // from it, so a typed password or a "remove credentials" choice is not
  // re-sent by the next save.
  const [saved, setSaved] = useState<{ view: RepoView; n: number } | null>(
    null,
  )

  if (repo.isError) {
    return (
      <ErrorState
        title="Could not load repository"
        message={repo.error?.message}
        onRetry={() => void repo.refetch()}
      />
    )
  }
  if (repo.isLoading || !repo.data) {
    return <Text>Loading repository…</Text>
  }

  // (Only while it is still this repository: the route can switch params.)
  const current = saved?.view.name === name ? saved.view : repo.data

  function handleSubmit(values: RepoFormValues) {
    update.mutate(toUpdateBody(values, current), {
      onSuccess: (updated) => {
        setSaved((prev) => ({ view: updated, n: (prev?.n ?? 0) + 1 }))
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
    <section className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <Heading>
          Edit <span className="font-mono">{repo.data.name}</span>
        </Heading>
        {repo.data.kind === 'group' && (
          <Link
            to="/manage/repositories/$repo/members"
            params={{ repo: repo.data.name }}
            className="rounded-lg border border-zinc-950/10 px-3 py-1.5 text-sm/6 font-medium text-zinc-950 hover:bg-zinc-950/[2.5%] dark:border-white/15 dark:text-white dark:hover:bg-white/5"
          >
            Manage members
          </Link>
        )}
        {repo.data.kind === 'hosted' &&
          IMPORT_FORMATS.includes(repo.data.format) && (
            <Link
              to="/manage/repositories/$repo/import"
              params={{ repo: repo.data.name }}
              className="rounded-lg border border-zinc-950/10 px-3 py-1.5 text-sm/6 font-medium text-zinc-950 hover:bg-zinc-950/[2.5%] dark:border-white/15 dark:text-white dark:hover:bg-white/5"
            >
              Import from Nexus
            </Link>
          )}
      </div>

      {update.isSuccess && (
        <p
          role="status"
          className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-sm/6 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
        >
          Saved.
        </p>
      )}

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

      <AnonymousAccessPanel repo={current} />

      {current.kind === 'proxy' && (
        <ProxyCachePanel key={current.name} repo={current} />
      )}
    </section>
  )
}
