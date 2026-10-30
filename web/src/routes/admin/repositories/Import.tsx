import { Fragment, useState } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import {
  IMPORT_FORMATS,
  isActive,
  type CreateImport,
  type ImportState,
  type ImportView,
  type ItemState,
  type OnConflict,
} from '~/api/imports'
import { useRepository } from '~/queries/useRepositories'
import {
  useCancelImport,
  useCreateImport,
  useDeleteImport,
  useImportItems,
  useImports,
  useResumeImport,
} from '~/queries/useImports'
import {
  Button,
  CellStack,
  Checkbox,
  Code,
  Notice,
  Page,
  PageHeader,
  Panel,
  ProgressBar,
  SelectField,
  Skeleton,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TextField,
  TextareaField,
  type Tone,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { formatBytes, formatDateTime } from '~/lib/oci'

export const Route = createFileRoute('/_app/manage/repositories/$repo/import')(
  {
    component: ImportRepository,
  },
)

const STATE_TONES: Record<ImportState, Tone> = {
  queued: 'neutral',
  running: 'heat',
  completed: 'ok',
  failed: 'danger',
  cancelled: 'neutral',
}

const ITEM_TONES: Record<ItemState, Tone> = {
  imported: 'ok',
  replaced: 'ok',
  identical: 'neutral',
  planned: 'neutral',
  conflict: 'warn',
  failed: 'danger',
  pending: 'neutral',
}

/**
 * Import a repository from another server into this hosted repository (the
 * admin API under `/admin/repositories/{name}/imports`): a NuGet feed or a
 * registry, read through the format's own protocol, so Nexus, Artifactory,
 * ProGet, BaGet, Harbor, a `distribution` registry or another Forge alike.
 * The form starts an import (or a dry run); the server checks the source
 * before it accepts one and says what is wrong. Below, the repository's imports with their progress,
 * re-read every two seconds while one runs: cancel, resume, retry the failed
 * items, delete, and the conflicts and failures of each.
 */
function ImportRepository() {
  const { repo: name } = Route.useParams()
  const repo = useRepository(name)
  const imports = useImports(name)

  const crumbs = [
    { label: 'Repositories', to: '/manage/repositories' },
    { label: name, to: '/manage/repositories/$repo', params: { repo: name } },
    { label: 'Import' },
  ]

  if (repo.isError) {
    return (
      <Page>
        <PageHeader title={`Import into ${name}`} icon="Download" crumbs={crumbs} />
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
        <PageHeader title={`Import into ${name}`} icon="Download" crumbs={crumbs} />
        <Skeleton lines={4} label="Loading repository…" />
      </Page>
    )
  }
  const supported =
    repo.data.kind === 'hosted' && IMPORT_FORMATS.includes(repo.data.format)
  const active = (imports.data ?? []).find(isActive)
  const all = imports.data ?? []

  return (
    <Page>
      <PageHeader
        title={`Import into ${name}`}
        icon="Download"
        crumbs={crumbs}
        kind={repo.data.kind}
        format={repo.data.format}
        description="Copy the packages of a NuGet feed, or the images of a registry, into this repository, read through the format's own protocol: from Nexus, Artifactory, ProGet, BaGet, Harbor, a distribution registry or another Forge. Versions Forge already has with the same bytes are skipped, so running an import again copies only what is new: import once, then again just before clients switch to Forge."
      />

      {!supported ? (
        <Notice tone="info">
          Imports go to a hosted NuGet or Docker repository; this is a{' '}
          {repo.data.format} {repo.data.kind} repository.
        </Notice>
      ) : active ? (
        <Notice tone="info">
          An import is {active.state}; a repository runs one import at a time.
        </Notice>
      ) : imports.isSuccess ? (
        <StartImportForm
          key={imports.data[0]?.id ?? 'first'}
          repo={name}
          docker={repo.data.format === 'docker'}
          previous={imports.data[0]}
        />
      ) : null}

      <Panel title="Imports" count={imports.isSuccess ? all.length : undefined}>
        {imports.isError ? (
          <ErrorState
            title="Could not load the imports"
            message={imports.error?.message}
            onRetry={() => void imports.refetch()}
          />
        ) : imports.isLoading ? (
          <Skeleton lines={3} label="Loading imports…" />
        ) : all.length === 0 ? (
          <EmptyState title="No imports yet" icon="Download" bordered={false}>
            The imports of this repository show here, with their progress.
          </EmptyState>
        ) : (
          all.map((i, n) => (
            <Fragment key={i.id}>
              {n > 0 && <hr className="fg-divider" />}
              <ImportCard repo={name} imp={i} />
            </Fragment>
          ))
        )}
      </Panel>
    </Page>
  )
}

/**
 * Start an import. The fields start from the repository's last import (all
 * but the password), so the final run before a cutover is one click.
 */
function StartImportForm({
  repo,
  docker,
  previous,
}: {
  repo: string
  docker: boolean
  previous?: ImportView
}) {
  const create = useCreateImport(repo)
  const [url, setUrl] = useState(previous?.url ?? '')
  const [names, setNames] = useState((previous?.names ?? []).join('\n'))
  const [username, setUsername] = useState(previous?.username ?? '')
  const [password, setPassword] = useState('')
  const [onConflict, setOnConflict] = useState<OnConflict>(
    previous?.on_conflict ?? 'skip',
  )
  const [concurrency, setConcurrency] = useState(
    String(previous?.concurrency ?? 4),
  )
  // A first import starts as a dry run; after a dry run, the real one.
  const [dryRun, setDryRun] = useState(previous === undefined)
  const [formError, setFormError] = useState<string | null>(null)
  const what = docker ? 'images' : 'packages'

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setFormError(null)
    if (!url.trim()) {
      setFormError(
        docker
          ? 'Enter the URL of the registry to import from.'
          : 'Enter the URL of the feed to import from.',
      )
      return
    }
    if (username.trim() !== '' && password === '') {
      setFormError('Enter the password of the user.')
      return
    }
    const n = Number(concurrency)
    if (!Number.isInteger(n) || n < 1 || n > 16) {
      setFormError('Concurrency must be a whole number from 1 to 16.')
      return
    }
    const body: CreateImport = {
      url: url.trim(),
      on_conflict: onConflict,
      concurrency: n,
      dry_run: dryRun,
    }
    const named = parseNames(names)
    if (named.length > 0) {
      body.names = named
    }
    if (username.trim() !== '') {
      body.username = username.trim()
      body.password = password
    }
    create.mutate(body, { onSuccess: () => setPassword('') })
  }

  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      title="Start an import"
      footer={
        <Button
          type="submit"
          variant="primary"
          icon="Download"
          disabled={create.isPending}
        >
          {create.isPending
            ? 'Checking the source…'
            : dryRun
              ? 'Start dry run'
              : 'Start import'}
        </Button>
      }
    >
      <div className="fg-form">
        <TextField
          label={docker ? 'Registry URL' : 'Feed URL'}
          mono
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder={
            docker
              ? 'https://registry.example.com'
              : 'https://nexus.example.com/repository/nuget-hosted/index.json'
          }
          description={
            docker ? (
              <>
                The registry API. Nexus: the repository&rsquo;s connector, e.g.{' '}
                <Code>http://nexus.example.com:8082</Code>, or its path route,{' '}
                <Code>&lt;Nexus URL&gt;/repository/&lt;name&gt;</Code>.
              </>
            ) : (
              <>
                A NuGet v3 feed&rsquo;s service index. Nexus:{' '}
                <Code>&lt;Nexus URL&gt;/repository/&lt;name&gt;/index.json</Code>. Point it
                at a hosted repository: a group or a proxy lists its upstream&rsquo;s
                packages too.
              </>
            )
          }
        />
        <TextareaField
          label={docker ? 'Images' : 'Package IDs'}
          optional
          mono
          rows={3}
          value={names}
          onChange={(e) => setNames(e.target.value)}
          description={
            docker
              ? 'One per line. Empty: every image the registry’s catalog lists. Name them for a registry without a catalog (Docker Hub, GHCR, ECR).'
              : 'One per line. Empty: every package the feed’s search finds. Name them for a feed without a search, or for packages a search misses (Nexus stops at 10,000; a package whose versions are all unlisted is in no search result).'
          }
        />
        <div className="fg-fieldrow">
          <TextField
            label="Username"
            optional
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="off"
            description="Leave empty to read anonymously."
          />
          <TextField
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            description="Sealed with the secret encryption, and deleted when the import completes."
          />
        </div>
        <div className="fg-fieldrow">
          <SelectField
            label="A version Forge has with other bytes"
            value={onConflict}
            onChange={(e) => setOnConflict(e.target.value as OnConflict)}
          >
            <option value="skip">Skip it and report it</option>
            <option value="overwrite">Overwrite it with the source&rsquo;s bytes</option>
            <option value="fail">Fail the import</option>
          </SelectField>
          <TextField
            label="Concurrency"
            type="number"
            mono
            value={concurrency}
            onChange={(e) => setConcurrency(e.target.value)}
            description="Items copied at a time (1–16)."
          />
        </div>
        <Checkbox
          label="Dry run"
          checked={dryRun}
          onChange={setDryRun}
          description={`Count the ${what} that would be copied and the conflicts, without writing anything.`}
        />
        {formError && <Notice tone="danger">{formError}</Notice>}
        {create.isError && (
          <Notice tone="danger" title="The import was refused">
            {create.error.body || create.error.message}
          </Notice>
        )}
      </div>
    </Panel>
  )
}

/** The names of a names field: one per line (or separated by commas or spaces). */
function parseNames(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((name) => name.trim())
    .filter((name) => name !== '')
}

/** One import of the repository: its state, progress, counts and actions. */
function ImportCard({ repo, imp }: { repo: string; imp: ImportView }) {
  const cancel = useCancelImport(repo)
  const resume = useResumeImport(repo)
  const remove = useDeleteImport(repo)
  const [password, setPassword] = useState('')
  const [showItems, setShowItems] = useState<ItemState | null>(null)
  const p = imp.progress
  const active = isActive(imp)
  const done = p.found - p.pending
  const needsPassword = imp.username !== null && !imp.has_password
  const error = cancel.error ?? resume.error ?? remove.error

  function doResume(retry: boolean) {
    resume.mutate(
      {
        id: imp.id,
        body: {
          retry_failed: retry,
          ...(needsPassword ? { password } : {}),
        },
      },
      { onSuccess: () => setPassword('') },
    )
  }

  return (
    <article aria-label={`Import ${imp.id}`} className="grid min-w-0 gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge tone={STATE_TONES[imp.state]}>{imp.state}</StatusBadge>
        {imp.dry_run && (
          <StatusBadge tone="neutral" dot={false}>
            dry run
          </StatusBadge>
        )}
        {active && imp.cancel_requested && (
          <StatusBadge tone="warn">cancelling</StatusBadge>
        )}
        <span className="fg-mono min-w-0 text-ink [overflow-wrap:anywhere]">
          {imp.url}
        </span>
        {imp.names && (
          <StatusBadge tone="neutral" dot={false}>
            {`${imp.names.length} named`}
          </StatusBadge>
        )}
      </div>
      <p className="fg-text">
        {imp.state === 'queued'
          ? 'Waiting for a worker.'
          : imp.phase === 'scan' && active
            ? `Scanning the source: ${p.found} found so far.`
            : `${done} of ${p.found} done.`}{' '}
        {imp.source_total !== null &&
          `The feed's search found ${imp.source_total} packages. `}
        Started {formatDateTime(imp.started_at ?? imp.created_at)}
        {imp.finished_at && `, ended ${formatDateTime(imp.finished_at)}`}.
        {imp.source_server && ` ${imp.source_server}.`}
      </p>
      {p.found > 0 && (
        <ProgressBar
          value={done}
          max={p.found}
          valueText={`${done} of ${p.found}`}
          tone={
            imp.state === 'completed'
              ? 'ok'
              : imp.state === 'failed'
                ? 'danger'
                : undefined
          }
        />
      )}
      <ul className="m-0 flex list-none flex-wrap gap-2 p-0" aria-label="Items">
        {(
          [
            ['imported', p.imported],
            ['replaced', p.replaced],
            ['identical', p.identical],
            ['planned', p.planned],
            ['conflict', p.conflict],
            ['failed', p.failed],
            ['pending', p.pending],
          ] as const
        )
          .filter(([, n]) => n > 0)
          .map(([state, n]) => (
            <li key={state}>
              <StatusBadge tone={ITEM_TONES[state]}>{`${n} ${state}`}</StatusBadge>
            </li>
          ))}
        <li>
          <StatusBadge dot={false}>{`${formatBytes(p.bytes_copied)} copied`}</StatusBadge>
        </li>
        {imp.dry_run && p.planned_size > 0 && (
          <li>
            <StatusBadge dot={false}>
              {`would copy ${formatBytes(p.planned_size)}`}
            </StatusBadge>
          </li>
        )}
      </ul>
      {imp.last_error && (
        <Notice tone="danger" title="The import stopped">
          {imp.last_error}
        </Notice>
      )}

      <div className="flex flex-wrap items-end gap-3">
        {active && !imp.cancel_requested && (
          <Button disabled={cancel.isPending} onClick={() => cancel.mutate(imp.id)}>
            Cancel
          </Button>
        )}
        {!active && needsPassword && (p.failed > 0 || imp.state !== 'completed') && (
          <TextField
            label="Password"
            type="password"
            className="min-w-56"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
          />
        )}
        {(imp.state === 'cancelled' || imp.state === 'failed') && (
          <Button
            icon="Refresh"
            disabled={resume.isPending || (needsPassword && password === '')}
            onClick={() => doResume(false)}
          >
            Resume
          </Button>
        )}
        {!active && p.failed > 0 && (
          <Button
            icon="Refresh"
            disabled={resume.isPending || (needsPassword && password === '')}
            onClick={() => doResume(true)}
          >
            Retry failed items
          </Button>
        )}
        {!active && (
          <Button
            variant="ghost"
            icon="Trash"
            disabled={remove.isPending}
            onClick={() => remove.mutate(imp.id)}
          >
            Delete
          </Button>
        )}
        {(['conflict', 'failed', 'planned'] as const)
          .filter((s) => p[s] > 0)
          .map((s) => (
            <Button
              key={s}
              variant="ghost"
              iconEnd={showItems === s ? 'ArrowUp' : 'ArrowDown'}
              aria-expanded={showItems === s}
              onClick={() => setShowItems(showItems === s ? null : s)}
            >
              {showItems === s ? `Hide ${s}` : `Show ${s}`}
            </Button>
          ))}
      </div>
      {error && (
        <Notice tone="danger">{error.body || error.message}</Notice>
      )}
      {showItems && <ItemList repo={repo} id={imp.id} state={showItems} />}
    </article>
  )
}

/** The items of an import in one state (its conflicts, its failures). */
function ItemList({
  repo,
  id,
  state,
}: {
  repo: string
  id: number
  state: ItemState
}) {
  const items = useImportItems(repo, id, state, true)
  if (items.isLoading) return <Skeleton variant="table" rows={3} columns={2} label="Loading…" />
  if (items.isError) {
    return <Notice tone="danger">{items.error.message}</Notice>
  }
  return (
    <Table caption={`Items: ${state}`} dense>
      <TableHead>
        <TableHeader>Item</TableHeader>
        <TableHeader width="120px" align="right">
          Size
        </TableHeader>
      </TableHead>
      <TableBody>
        {(items.data ?? []).map((item) => (
          <TableRow key={item.id}>
            <TableCell lead>
              <CellStack sub={item.detail ?? undefined}>
                <span className="font-mono">
                  {item.version ? `${item.name} ${item.version}` : item.name}
                </span>
              </CellStack>
            </TableCell>
            <TableCell align="right" nowrap>
              {item.size != null ? formatBytes(item.size) : ''}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
