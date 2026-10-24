import { useState } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'

import { ApiError } from '~/lib/httpClient'
import { isRepositoryOffline, type DetailVersion } from '~/api/packages'
import { useBrowseRepos } from '~/queries/useBrowseRepos'
import { useDeletePackageVersion, usePackageDetail } from '~/queries/usePackageDetail'
import { useMe } from '~/queries/useMe'
import { VersionTable } from '~/components/VersionTable'
import { DependencyGroups } from '~/components/DependencyGroups'
import { ErrorState, RepositoryOfflineState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import {
  Code,
  CodeBlock,
  Columns,
  CommandSnippet,
  Dialog,
  FactList,
  Page,
  PageHeader,
  Panel,
  SelectField,
  Skeleton,
  formatIcon,
} from '~/components/ui'

export const Route = createFileRoute('/_app/packages/$repo/$id')({
  component: PackageDetailPage,
})

/**
 * Package-detail view: versions with per-version metadata + delay/retention
 * badges, and dependency groups per version. Loading / empty / not-found /
 * repository-offline / error states are all handled. Reachable by any reader.
 */
function PackageDetailPage() {
  const { repo, id } = Route.useParams()
  const navigate = useNavigate()
  const me = useMe()
  const detail = usePackageDetail(repo, id)
  const del = useDeletePackageVersion(repo, id)
  const [pendingDelete, setPendingDelete] = useState<DetailVersion | null>(null)
  // The repository's format, from the (cached) list the rail shows too.
  const repos = useBrowseRepos()
  const format = Array.isArray(repos.data)
    ? repos.data.find((r) => r.name === repo)?.format
    : undefined
  const crumbs = [
    { label: 'Repositories', to: '/' },
    { label: repo, to: '/repos/$repo', params: { repo } },
  ]

  if (detail.isLoading) {
    return (
      <Page>
        <PageHeader title={id} crumbs={[...crumbs, { label: id }]} />
        <Skeleton variant="table" label="Loading package…" />
      </Page>
    )
  }

  if (detail.isError) {
    // A 404 means the package (or repo) is not visible / does not exist; render
    // it as a not-found empty state rather than a scary error panel.
    const notFound =
      detail.error instanceof ApiError && detail.error.status === 404
    return (
      <Page>
        <PageHeader title={id} crumbs={[...crumbs, { label: id }]} />
        {notFound ? (
          <EmptyState title="Package not found">
            No readable package <Code>{id}</Code> in repository <Code>{repo}</Code>.
          </EmptyState>
        ) : isRepositoryOffline(detail.error) ? (
          <RepositoryOfflineState onRetry={() => void detail.refetch()} />
        ) : (
          <ErrorState
            title="Could not load package"
            message={detail.error?.message}
            onRetry={() => void detail.refetch()}
          />
        )}
      </Page>
    )
  }

  const pkg = detail.data
  if (!pkg) return null
  const hasDependencies = Object.keys(pkg.dependency_groups_by_version).length > 0

  return (
    <Page>
      <PageHeader
        title={pkg.original_id}
        icon={formatIcon(format ?? 'nuget')}
        crumbs={[
          { label: 'Repositories', to: '/' },
          { label: pkg.repo, to: '/repos/$repo', params: { repo: pkg.repo } },
          { label: pkg.original_id },
        ]}
        kind={pkg.repo_kind}
        format={format}
        meta={[
          pkg.versions.length === 1 ? '1 version' : `${pkg.versions.length} versions`,
        ]}
      />
      <Columns
        aside={
          <>
            {pkg.versions.length > 0 && format && (
              <InstallPanel format={format} repo={pkg.repo} id={pkg.original_id} versions={pkg.versions} />
            )}
            <Panel title="Details">
              <FactList
                items={[
                  { term: 'Package id', value: pkg.original_id, mono: true },
                  { term: 'Repository', value: pkg.repo, mono: true },
                  { term: 'Kind', value: pkg.repo_kind },
                  { term: 'Versions', value: pkg.versions.length },
                ]}
              />
            </Panel>
          </>
        }
        asideLabel="Install and details"
      >
        <Panel
          title="Versions"
          count={pkg.versions.length}
          flush
          description="Unlisted versions stay restorable but are hidden from search and from floating version ranges."
        >
          {pkg.versions.length === 0 ? (
            <EmptyState title="No visible versions" bordered={false} />
          ) : (
            <VersionTable
              versions={pkg.versions}
              repoKind={pkg.repo_kind}
              caption={`Versions of ${pkg.original_id}`}
              onDelete={
                me.data?.is_admin && pkg.repo_kind === 'hosted' && format !== 'docker'
                  ? (version) => {
                      del.reset()
                      setPendingDelete(version)
                    }
                  : undefined
              }
              deletePending={del.isPending}
            />
          )}
        </Panel>

        <Panel
          title="Dependencies"
          flush
          description="Per version and target framework, as declared in the package."
        >
          {hasDependencies ? (
            <DependencyGroups
              repo={pkg.repo}
              byVersion={pkg.dependency_groups_by_version}
              caption={`Dependencies of ${pkg.original_id}`}
            />
          ) : (
            <EmptyState title="No dependency information" icon="Layers" bordered={false}>
              No dependency information available.
            </EmptyState>
          )}
        </Panel>
      </Columns>
      <Dialog
        open={pendingDelete !== null}
        onClose={() => {
          if (!del.isPending) setPendingDelete(null)
        }}
        title={`Delete ${pkg.original_id} ${pendingDelete?.version_original ?? ''}?`}
        description={
          <>
            Permanently delete version <Code>{pendingDelete?.version_original}</Code> of{' '}
            <Code>{pkg.original_id}</Code> from repository <Code>{pkg.repo}</Code>.
            This cannot be undone. Clients that already downloaded this version keep their copy.
          </>
        }
        icon="Trash"
        tone="danger"
        confirmLabel={del.isPending ? 'Deleting…' : 'Delete version'}
        confirmVariant="danger-solid"
        confirmDisabled={del.isPending}
        onConfirm={() => pendingDelete && del.mutate(pendingDelete.version_original, {
          onSuccess: async () => {
            setPendingDelete(null)
            const remaining = await detail.refetch({ cancelRefetch: false })
            if (
              remaining.data?.versions.length === 0 ||
              (remaining.error instanceof ApiError && remaining.error.status === 404)
            ) {
              void navigate({ to: '/repos/$repo', params: { repo } })
            }
          },
        })}
      >
        {del.isError && (
          <ErrorState title="Could not delete version" message={del.error.body || del.error.message} />
        )}
      </Dialog>
    </Page>
  )
}

/**
 * The version the install commands start with: the last listed one that can
 * be downloaded, a stable one before a prerelease (as `dotnet add package`
 * without `--version` picks), else the last one. The detail API lists the
 * versions oldest first.
 */
function defaultVersion(versions: DetailVersion[]): string {
  const ready = versions.filter((v) => v.listed && v.delay_status !== 'delayed_until')
  const stable = ready.filter((v) => !v.version_original.includes('-'))
  return (stable.at(-1) ?? ready.at(-1) ?? versions.at(-1))?.version_original ?? ''
}

/**
 * The install commands of one version, for the format Forge knows a client
 * command of (NuGet). The source is added once per machine with the
 * repository's Connect commands.
 */
function InstallPanel({
  format,
  repo,
  id,
  versions,
}: {
  format: string
  repo: string
  id: string
  versions: DetailVersion[]
}) {
  const [version, setVersion] = useState(() => defaultVersion(versions))
  const selectedVersion = versions.some((v) => v.version_original === version)
    ? version
    : defaultVersion(versions)
  if (format !== 'nuget') return null
  return (
    <Panel
      title="Install"
      description={`Add the ${repo} source once per machine; see Connect on the repository.`}
    >
      {versions.length > 1 && (
        <SelectField label="Version" value={selectedVersion} onChange={(e) => setVersion(e.target.value)}>
          {versions.map((v) => (
            <option key={v.version} value={v.version_original}>
              {v.version_original}
            </option>
          ))}
        </SelectField>
      )}
      <CommandSnippet
        label="dotnet CLI"
        command={`dotnet add package ${id} --version ${selectedVersion}`}
        copyLabel="Copy add-package command"
      />
      <CodeBlock
        title="PackageReference"
        copyLabel="Copy PackageReference"
        code={`<PackageReference\n  Include="${id}"\n  Version="${selectedVersion}" />`}
        placeholders={[]}
      />
    </Panel>
  )
}
