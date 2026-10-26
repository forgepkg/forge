import type { ReactNode } from 'react'
import { Link } from '@tanstack/react-router'

import type {
  ChartDetail,
  ChartMetadata,
  ImageDetail,
  ImageManifest,
  ImageTag,
} from '~/api/images'
import { isRepositoryOffline } from '~/api/packages'
import {
  cappedNote,
  chartVersion,
  chartVersions,
  defaultChartVersion,
  httpUrl,
} from '~/lib/oci'
import { useChart } from '~/queries/useChart'
import { ManifestTable, TagTable } from '~/components/ImageTables'
import { ErrorState, RepositoryOfflineState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import {
  Chip,
  Code,
  CodeBlock,
  Columns,
  CommandSnippet,
  FactList,
  Notice,
  Panel,
  SelectField,
  Skeleton,
  StatusBadge,
} from '~/components/ui'

/**
 * The image page of a Helm chart pushed as an OCI artifact (`helm push`):
 * the `helm install` / `helm pull` commands of a version (the selected one,
 * else the newest release), the version's `Chart.yaml` facts, README and
 * default values, then the versions and manifests of the image. With the
 * delete callbacks (administrators, hosted repositories), each version and
 * manifest has a Delete button.
 */
export function ChartView({
  detail,
  selectedTag,
  onSelectTag,
  onDeleteVersion,
  onDeleteManifest,
  deletePending,
}: {
  detail: ImageDetail
  selectedTag: string | undefined
  onSelectTag: (tag: string) => void
  onDeleteVersion?: (tag: ImageTag) => void
  onDeleteManifest?: (manifest: ImageManifest) => void
  deletePending?: boolean
}) {
  const versions = chartVersions(detail.tags, detail.manifests)
  const current =
    versions.find((t) => t.tag === selectedTag) ?? defaultChartVersion(versions)
  const chart = useChart(detail.repo, detail.image, current?.digest)

  let body: ReactNode
  if (!current) {
    body = null
  } else if (chart.isLoading) {
    body = <Skeleton variant="table" label="Loading chart…" />
  } else if (chart.isError) {
    body = isRepositoryOffline(chart.error) ? (
      <RepositoryOfflineState onRetry={() => void chart.refetch()} />
    ) : (
      <ErrorState
        title="Could not load the chart"
        message={chart.error?.message}
        onRetry={() => void chart.refetch()}
      />
    )
  } else if (chart.data) {
    body = <ChartFiles chart={chart.data} />
  }

  return (
    <Columns
      aside={
        <>
          <InstallPanel
            detail={detail}
            versions={versions.map((t) => t.tag)}
            current={current?.tag}
            onSelectTag={onSelectTag}
          />
          {chart.data?.metadata && (
            <Panel title="Chart">
              <ChartFacts metadata={chart.data.metadata} />
            </Panel>
          )}
        </>
      }
      asideLabel="Install and chart details"
    >
      {chart.data?.metadata?.deprecated && (
        <Notice tone="warn" title="Deprecated">
          The chart&apos;s maintainers marked this version deprecated.
        </Notice>
      )}
      {body}
      <Panel
        title="Versions"
        count={versions.length}
        flush
        description={cappedNote(detail.tags.length, detail.tags_total, 'versions')}
      >
        {detail.tags.length === 0 ? (
          <EmptyState title="No versions" icon="Wheel" bordered={false}>
            This chart has only untagged manifests; Helm installs charts by
            version.
          </EmptyState>
        ) : (
          <TagTable
            tags={detail.tags}
            noun="version"
            onDelete={onDeleteVersion}
            deletePending={deletePending}
          />
        )}
      </Panel>
      <Panel
        title="Manifests"
        count={detail.manifests_total ?? detail.manifests.length}
        flush
        description={[
          cappedNote(detail.manifests.length, detail.manifests_total, 'manifests'),
          "The chart's manifests, and referrers such as signatures.",
        ]
          .filter(Boolean)
          .join(' ')}
      >
        <ManifestTable
          manifests={detail.manifests}
          repoKind={detail.repo_kind}
          onDelete={onDeleteManifest}
          deletePending={deletePending}
        />
      </Panel>
    </Columns>
  )
}

/**
 * `helm install` and `helm pull` of the selected version, with the login
 * hint. Helm needs a version: a chart without tags gets no commands.
 */
function InstallPanel({
  detail,
  versions,
  current,
  onSelectTag,
}: {
  detail: ImageDetail
  versions: string[]
  current: string | undefined
  onSelectTag: (tag: string) => void
}) {
  const ref = `oci://${detail.pull_name}`
  const version = current ? chartVersion(current) : undefined
  return (
    <Panel
      title="Install"
      description={
        <>
          Log in first with{' '}
          <Code>helm registry login {detail.registry} --username &lt;username&gt;</Code>,
          using an API token from{' '}
          <Link to="/tokens" className="fg-link">
            Your tokens
          </Link>{' '}
          as the password.
        </>
      }
    >
      {versions.length > 1 && current && (
        <SelectField
          label="Version"
          value={current}
          onChange={(e) => onSelectTag(e.target.value)}
        >
          {versions.map((tag) => (
            <option key={tag} value={tag}>
              {chartVersion(tag)}
            </option>
          ))}
        </SelectField>
      )}
      {version ? (
        <>
          <CommandSnippet
            label="Install"
            command={`helm install <release> ${ref} --version ${version}`}
            copyLabel="Copy install command"
          />
          <CommandSnippet
            label="Pull"
            command={`helm pull ${ref} --version ${version}`}
            copyLabel="Copy pull command"
          />
        </>
      ) : (
        <p className="fg-field-desc">
          No version of this chart is tagged; push one with{' '}
          <Code>helm push</Code>.
        </p>
      )}
    </Panel>
  )
}

/** A link when `url` is an http(s) URL, else the text. */
function MaybeLink({ url }: { url: string }) {
  const href = httpUrl(url)
  return href ? (
    <a href={href} className="fg-link" target="_blank" rel="noopener noreferrer nofollow">
      {url}
    </a>
  ) : (
    <span>{url}</span>
  )
}

/** The `Chart.yaml` facts of a version, the ones it declares. */
function ChartFacts({ metadata }: { metadata: ChartMetadata }) {
  const items: { term: ReactNode; value: ReactNode; mono?: boolean }[] = []
  const add = (term: string, value: ReactNode, mono = false) => {
    if (value !== undefined && value !== null && value !== '') items.push({ term, value, mono })
  }
  add('Name', metadata.name, true)
  add('Version', metadata.version, true)
  add('App version', metadata.appVersion, true)
  add('Description', metadata.description)
  add('Type', metadata.type)
  add('Kubernetes', metadata.kubeVersion, true)
  if (metadata.home) add('Home', <MaybeLink url={metadata.home} />)
  if (metadata.sources?.length) {
    add(
      'Sources',
      <span className="grid gap-1">
        {metadata.sources.map((s) => (
          <MaybeLink key={s} url={s} />
        ))}
      </span>,
    )
  }
  if (metadata.maintainers?.length) {
    add(
      'Maintainers',
      <span className="grid gap-1">
        {metadata.maintainers.map((m, i) => (
          <span key={i}>
            {m.name}
            {m.email && <span className="text-ink-muted"> &lt;{m.email}&gt;</span>}
          </span>
        ))}
      </span>,
    )
  }
  if (metadata.keywords?.length) {
    add(
      'Keywords',
      <span className="fg-cell-badges">
        {metadata.keywords.map((k) => (
          <Chip key={k}>{k}</Chip>
        ))}
      </span>,
    )
  }
  if (metadata.dependencies?.length) {
    add(
      'Dependencies',
      <span className="grid gap-1">
        {metadata.dependencies.map((d, i) => (
          <span key={i}>
            <span className="font-mono">
              {d.alias ?? d.name}
              {d.version && ` ${d.version}`}
            </span>
            {d.repository && <span className="text-ink-muted"> from {d.repository}</span>}
          </span>
        ))}
      </span>,
    )
  }
  if (metadata.deprecated) add('Status', <StatusBadge tone="warn">deprecated</StatusBadge>)
  return <FactList items={items} />
}

/** The README and default values of a version. */
function ChartFiles({ chart }: { chart: ChartDetail }) {
  const cut = (
    <p className="fg-field-desc">
      Cut at 512 KiB; <Code>helm show</Code> prints all of it.
    </p>
  )
  return (
    <>
      {!chart.archive_stored && (
        <Notice tone="info" title="Not stored yet">
          This repository has not stored the chart yet: its README and default
          values show once it is pulled through Forge.
        </Notice>
      )}
      {chart.archive_stored && (
        <Panel title="README">
          {chart.readme ? (
            <>
              <pre className="fg-readme" aria-label={chart.readme.name}>
                {chart.readme.text}
              </pre>
              {chart.readme.truncated && cut}
            </>
          ) : (
            <EmptyState title="No README" icon="File" bordered={false}>
              The chart has no README.
            </EmptyState>
          )}
        </Panel>
      )}
      {chart.archive_stored && (
        <Panel title="Default values">
          {chart.values ? (
            <>
              <CodeBlock
                className="fg-chart-values"
                title={chart.values.name}
                code={chart.values.text}
                copyLabel="Copy values"
                placeholders={[]}
              />
              {chart.values.truncated && cut}
            </>
          ) : (
            <EmptyState title="No default values" icon="File" bordered={false}>
              The chart has no <Code>values.yaml</Code>.
            </EmptyState>
          )}
        </Panel>
      )}
    </>
  )
}
