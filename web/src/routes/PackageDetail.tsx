import { createFileRoute, Link } from '@tanstack/react-router'

import { ApiError } from '~/lib/httpClient'
import { usePackageDetail } from '~/queries/usePackageDetail'
import { RepoKindBadge } from '~/components/RepoKindBadge'
import { VersionTable } from '~/components/VersionTable'
import { DependencyGroups } from '~/components/DependencyGroups'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'

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
    return <p className="text-slate-500">Loading package…</p>
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
      <div>
        <nav className="text-sm text-slate-500">
          <Link to="/" className="text-sky-700 hover:underline">
            Repositories
          </Link>
          <span className="mx-1">/</span>
          <Link
            to="/repos/$repo"
            params={{ repo: pkg.repo }}
            className="text-sky-700 hover:underline"
          >
            {pkg.repo}
          </Link>
          <span className="mx-1">/</span>
          <span className="font-medium text-slate-700">{pkg.original_id}</span>
        </nav>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold">{pkg.original_id}</h1>
          <span className="flex items-center gap-2 text-sm text-slate-600">
            {pkg.repo}
            <RepoKindBadge kind={pkg.repo_kind} />
          </span>
        </div>
      </div>

      <div>
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-500">
          Versions
        </h2>
        {pkg.versions.length === 0 ? (
          <EmptyState title="No visible versions" />
        ) : (
          <div className="mt-3">
            <VersionTable versions={pkg.versions} />
          </div>
        )}
      </div>

      <div>
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-500">
          Dependencies
        </h2>
        <div className="mt-3 space-y-6">
          {Object.keys(pkg.dependency_groups_by_version).length === 0 ? (
            <p className="text-sm text-slate-500">
              No dependency information available.
            </p>
          ) : (
            Object.entries(pkg.dependency_groups_by_version).map(
              ([version, groups]) => (
                <div key={version}>
                  <h3 className="font-mono text-sm font-medium text-slate-700">
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
