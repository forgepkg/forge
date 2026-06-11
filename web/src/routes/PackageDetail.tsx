import { createFileRoute } from '@tanstack/react-router'

import { ApiError } from '~/lib/httpClient'
import { usePackageDetail } from '~/queries/usePackageDetail'
import { Heading, Subheading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { Divider } from '~/components/catalyst/divider'
import { RepoKindBadge } from '~/components/RepoKindBadge'
import { VersionTable } from '~/components/VersionTable'
import { DependencyGroups } from '~/components/DependencyGroups'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { Breadcrumbs } from '~/components/Breadcrumbs'

export const Route = createFileRoute('/_app/packages/$repo/$id')({
  component: PackageDetailPage,
})

/**
 * Package-detail view (plan §4, §Phase 3): versions with per-version metadata +
 * delay/retention badges, and dependency groups per version. Loading / empty /
 * not-found / error states are all handled. Reachable by any reader.
 */
function PackageDetailPage() {
  const { repo, id } = Route.useParams()
  const detail = usePackageDetail(repo, id)

  if (detail.isLoading) {
    return <Text>Loading package…</Text>
  }

  if (detail.isError) {
    // A 404 means the package (or repo) is not visible / does not exist; render
    // it as a not-found empty state rather than a scary error panel.
    const notFound =
      detail.error instanceof ApiError && detail.error.status === 404
    if (notFound) {
      return (
        <EmptyState title="Package not found">
          No readable package <span className="font-mono">{id}</span> in
          repository <span className="font-mono">{repo}</span>.
        </EmptyState>
      )
    }
    return (
      <ErrorState
        title="Could not load package"
        message={detail.error?.message}
        onRetry={() => void detail.refetch()}
      />
    )
  }

  const pkg = detail.data
  if (!pkg) return null

  return (
    <section className="space-y-8">
      <div className="space-y-2">
        <Breadcrumbs
          items={[
            { label: 'Repositories', to: '/' },
            { label: pkg.repo, to: '/repos/$repo', params: { repo: pkg.repo } },
            { label: pkg.original_id },
          ]}
        />
        <div className="flex flex-wrap items-center gap-3">
          <Heading>{pkg.original_id}</Heading>
          <span className="flex items-center gap-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            {pkg.repo}
            <RepoKindBadge kind={pkg.repo_kind} />
          </span>
        </div>
      </div>

      <div>
        <Subheading>Versions</Subheading>
        {pkg.versions.length === 0 ? (
          <div className="mt-3">
            <EmptyState title="No visible versions" />
          </div>
        ) : (
          <div className="mt-3">
            <VersionTable versions={pkg.versions} />
          </div>
        )}
      </div>

      <Divider />

      <div>
        <Subheading>Dependencies</Subheading>
        <div className="mt-3 space-y-6">
          {Object.keys(pkg.dependency_groups_by_version).length === 0 ? (
            <Text>No dependency information available.</Text>
          ) : (
            Object.entries(pkg.dependency_groups_by_version).map(
              ([version, groups]) => (
                <div key={version}>
                  <h3 className="font-mono text-sm/6 font-medium text-zinc-700 dark:text-zinc-300">
                    {version}
                  </h3>
                  <div className="mt-2">
                    <DependencyGroups repo={pkg.repo} groups={groups} />
                  </div>
                </div>
              ),
            )
          )}
        </div>
      </div>
    </section>
  )
}
