import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { UpdateRepo } from '~/api/repositories'
import {
  useRepository,
  useUpdateRepository,
} from '~/queries/useRepositories'
import {
  RepositoryForm,
  type RepoFormValues,
} from '~/components/RepositoryForm'
import { Heading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { ErrorState } from '~/components/ErrorState'

export const Route = createFileRoute('/_app/admin/repositories/$repo')({
  component: EditRepository,
})

/**
 * Edit-repository screen (plan §Phase 4). Loads the (redacted) repository, seeds
 * the shared form, and PUTs a partial `UpdateRepo`. The `upstream_password` is
 * **write-only**: it is never seeded from the GET and is only included in the
 * update when the admin typed a new one (an empty field leaves the stored secret
 * unchanged — slice-1 redaction). Group repos get a link to the Members editor.
 */
function EditRepository() {
  const { repo: name } = Route.useParams()
  const navigate = useNavigate()
  const repo = useRepository(name)
  const update = useUpdateRepository(name)

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

  function handleSubmit(values: RepoFormValues) {
    update.mutate(toUpdateBody(values), {
      onSuccess: (updated) => {
        // The name may have changed; keep the URL in sync.
        if (updated.name !== name) {
          void navigate({
            to: '/admin/repositories/$repo',
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
            to="/admin/repositories/$repo/members"
            params={{ repo: repo.data.name }}
            className="rounded-lg border border-zinc-950/10 px-3 py-1.5 text-sm/6 font-medium text-zinc-950 hover:bg-zinc-950/[2.5%] dark:border-white/15 dark:text-white dark:hover:bg-white/5"
          >
            Manage members
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
        mode="edit"
        existing={repo.data}
        submitting={update.isPending}
        serverError={
          update.isError ? update.error.body || update.error.message : null
        }
        onSubmit={handleSubmit}
        onCancel={() => void navigate({ to: '/admin/repositories' })}
      />
    </section>
  )
}

/**
 * Map form values to a partial `UpdateRepo`. `kind` / `format` are identity
 * columns and never sent. An empty `upstream_password` is omitted so the stored
 * secret is left unchanged; an empty TTL becomes `null` (server default).
 */
function toUpdateBody(values: RepoFormValues): UpdateRepo {
  const body: UpdateRepo = {
    name: values.name.trim(),
    anonymous_read: values.anonymous_read,
    online: values.online,
  }
  if (values.kind === 'hosted') {
    body.allow_redeploy = values.allow_redeploy
  }
  if (values.kind === 'group') {
    body.prefer_hosted = values.prefer_hosted
  }
  if (values.kind === 'proxy') {
    body.remote_url = values.remote_url.trim()
    body.package_delay_seconds = Number(values.package_delay_seconds) || 0
    body.metadata_ttl_seconds = parseTtl(values.metadata_ttl_seconds)
    body.not_found_ttl_seconds = parseTtl(values.not_found_ttl_seconds)
    body.upstream_username =
      values.upstream_username.trim() === ''
        ? null
        : values.upstream_username.trim()
    // Only replace the password when a new one was typed.
    if (values.upstream_password !== '') {
      body.upstream_password = values.upstream_password
    }
  }
  return body
}

function parseTtl(raw: string): number | null {
  if (raw.trim() === '') return null
  const n = Number(raw)
  return Number.isFinite(n) ? n : null
}
