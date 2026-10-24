import { useState } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import { ApiError } from '~/lib/httpClient'
import { isRepositoryOffline, type DetailVersion } from '~/api/packages'
import { useBrowseRepos } from '~/queries/useBrowseRepos'
import { usePackageDetail } from '~/queries/usePackageDetail'
import { VersionTable } from '~/components/VersionTable'
import { DependencyGroups } from '~/components/DependencyGroups'
import { ErrorState, RepositoryOfflineState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import {
  Code,
  CodeBlock,
  Columns,
  CommandSnippet,
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
 * badges, and dependency groups per version; the package's tags (npm's
 * dist-tags), deprecations and README when its format has them. Loading /
 * empty / not-found / repository-offline / error states are all handled.
 * Reachable by any reader.
 */
function PackageDetailPage() {
  const { repo, id } = Route.useParams()
  const detail = usePackageDetail(repo, id)
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
  const npm = format === 'npm'
  const tags = pkg.tags ?? {}
  const latest = tags.latest

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
          ...(latest ? [`latest ${latest}`] : []),
        ]}
      />
      <Columns
        aside={
          <>
            {pkg.versions.length > 0 && format && (
              <InstallPanel
                format={format}
                repo={pkg.repo}
                id={pkg.original_id}
                versions={pkg.versions}
                latest={latest}
              />
            )}
            <Panel title="Details">
              <FactList
                items={[
                  { term: npm ? 'Package' : 'Package id', value: pkg.original_id, mono: true },
                  { term: 'Repository', value: pkg.repo, mono: true },
                  { term: 'Kind', value: pkg.repo_kind },
                  { term: 'Versions', value: pkg.versions.length },
                  ...(pkg.description ? [{ term: 'Description', value: pkg.description }] : []),
                ]}
              />
            </Panel>
            {Object.keys(tags).length > 0 && (
              <Panel
                title={npm ? 'Dist-tags' : 'Tags'}
                description={
                  npm ? (
                    <>
                      What <Code>npm install {pkg.original_id}@&lt;tag&gt;</Code> installs;{' '}
                      <Code>latest</Code> is the default.
                    </>
                  ) : undefined
                }
              >
                <FactList
                  items={Object.entries(tags).map(([tag, version]) => ({
                    term: tag,
                    value: version,
                    mono: true,
                  }))}
                />
              </Panel>
            )}
          </>
        }
        asideLabel="Install and details"
      >
        <Panel
          title="Versions"
          count={pkg.versions.length}
          flush
          description={
            npm
              ? 'A deprecated version still installs; npm warns about it with the message shown on its badge.'
              : 'Unlisted versions stay restorable but are hidden from search and from floating version ranges.'
          }
        >
          {pkg.versions.length === 0 ? (
            <EmptyState title="No visible versions" bordered={false} />
          ) : (
            <VersionTable
              versions={pkg.versions}
              repoKind={pkg.repo_kind}
              caption={`Versions of ${pkg.original_id}`}
              distTags={pkg.tags}
              deprecated={pkg.deprecated}
            />
          )}
        </Panel>

        {(npm || pkg.readme) && (
          <Panel title="README" description={latest ? `Of version ${latest}, as published.` : undefined}>
            {pkg.readme ? (
              <pre className="fg-readme" aria-label={`README of ${pkg.original_id}`}>
                {pkg.readme}
              </pre>
            ) : (
              <EmptyState title="No README" icon="File" bordered={false}>
                The latest version was published without one.
              </EmptyState>
            )}
          </Panel>
        )}

        <Panel
          title="Dependencies"
          flush
          description={
            npm
              ? 'Per version, as its package.json declares them: dependencies, optional and peer dependencies.'
              : 'Per version and target framework, as declared in the package.'
          }
        >
          {hasDependencies ? (
            <DependencyGroups
              repo={pkg.repo}
              byVersion={pkg.dependency_groups_by_version}
              caption={`Dependencies of ${pkg.original_id}`}
              npm={npm}
            />
          ) : (
            <EmptyState title="No dependency information" icon="Layers" bordered={false}>
              No dependency information available.
            </EmptyState>
          )}
        </Panel>
      </Columns>
    </Page>
  )
}

/**
 * The version the install commands start with: the one npm's `latest`
 * dist-tag names, else the last listed one that can be downloaded, a stable
 * one before a prerelease (as `dotnet add package` without `--version`
 * picks), else the last one. The detail API lists the versions oldest first.
 */
function defaultVersion(versions: DetailVersion[], latest?: string): string {
  const tagged = latest ? versions.find((v) => v.version === latest) : undefined
  if (tagged) return tagged.version_original
  const ready = versions.filter((v) => v.listed && v.delay_status !== 'delayed_until')
  const stable = ready.filter((v) => !v.version_original.includes('-'))
  return (stable.at(-1) ?? ready.at(-1) ?? versions.at(-1))?.version_original ?? ''
}

/**
 * The install commands of one version, for the formats Forge knows a client
 * command of (NuGet, npm). The source or registry is added once per machine
 * with the repository's Connect commands.
 */
function InstallPanel({
  format,
  repo,
  id,
  versions,
  latest,
}: {
  format: string
  repo: string
  id: string
  versions: DetailVersion[]
  /** npm: the version the `latest` dist-tag names. */
  latest?: string
}) {
  const [version, setVersion] = useState(() => defaultVersion(versions, latest))
  if (format !== 'nuget' && format !== 'npm') return null
  return (
    <Panel
      title="Install"
      description={
        format === 'npm'
          ? `Point your client at the ${repo} registry once; see Connect on the repository.`
          : `Add the ${repo} source once per machine; see Connect on the repository.`
      }
    >
      {versions.length > 1 && (
        <SelectField label="Version" value={version} onChange={(e) => setVersion(e.target.value)}>
          {versions.map((v) => (
            <option key={v.version} value={v.version_original}>
              {v.version_original}
            </option>
          ))}
        </SelectField>
      )}
      {format === 'npm' ? (
        npmInstallCommands(id, version).map((snippet) => (
          <CommandSnippet key={snippet.label} {...snippet} />
        ))
      ) : (
        <>
          <CommandSnippet
            label="dotnet CLI"
            command={`dotnet add package ${id} --version ${version}`}
            copyLabel="Copy add-package command"
          />
          <CodeBlock
            title="PackageReference"
            copyLabel="Copy PackageReference"
            code={`<PackageReference\n  Include="${id}"\n  Version="${version}" />`}
            placeholders={[]}
          />
        </>
      )}
    </Panel>
  )
}

/** The commands that add `id` at `version` to a project, per npm client. */
function npmInstallCommands(id: string, version: string) {
  const spec = `${id}@${version}`
  return [
    { label: 'npm', command: `npm install ${spec}`, copyLabel: 'Copy npm command' },
    { label: 'pnpm', command: `pnpm add ${spec}`, copyLabel: 'Copy pnpm command' },
    { label: 'Yarn', command: `yarn add ${spec}`, copyLabel: 'Copy Yarn command' },
    { label: 'Bun', command: `bun add ${spec}`, copyLabel: 'Copy Bun command' },
  ]
}
