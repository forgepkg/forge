import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import {
  IMPORT_FORMATS,
  isActive,
  type CreateImport,
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
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
import { Checkbox, CheckboxField } from '~/components/catalyst/checkbox'
import { Description, Field, Label } from '~/components/catalyst/fieldset'
import { Heading, Subheading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
import { Select } from '~/components/catalyst/select'
import { Text } from '~/components/catalyst/text'
import { ErrorState } from '~/components/ErrorState'
import { formatBytes, formatDateTime } from '~/lib/oci'

export const Route = createFileRoute('/_app/manage/repositories/$repo/import')(
  {
    component: ImportRepository,
  },
)

const STATE_COLORS = {
  queued: 'zinc',
  running: 'sky',
  completed: 'green',
  failed: 'red',
  cancelled: 'amber',
} as const

/**
 * Import a Nexus hosted repository into this hosted repository (the admin
 * API under `/admin/repositories/{name}/imports`). The form starts an import
 * (or a dry run); the server checks the source before it accepts one and
 * says what is wrong. Below, the repository's imports with their progress,
 * re-read every two seconds while one runs: cancel, resume, retry the failed
 * items, delete, and the conflicts and failures of each.
 */
function ImportRepository() {
  const { repo: name } = Route.useParams()
  const repo = useRepository(name)
  const imports = useImports(name)

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
  const supported =
    repo.data.kind === 'hosted' && IMPORT_FORMATS.includes(repo.data.format)
  const active = (imports.data ?? []).find(isActive)

  return (
    <section className="space-y-6">
      <div>
        <Link
          to="/manage/repositories/$repo"
          params={{ repo: name }}
          className="text-sm/6 text-sky-600 hover:underline dark:text-sky-400"
        >
          ← Back to {name}
        </Link>
        <Heading className="mt-1">
          Import into <span className="font-mono">{name}</span>
        </Heading>
        <Text className="mt-1">
          Copy the packages of a Nexus 3 hosted repository of the same format
          into this repository, with their publish dates, last downloads and
          uploaders. Versions Forge already has with the same bytes are
          skipped, so running an import again copies only what is new: import
          once, then again just before clients switch to Forge.
        </Text>
      </div>

      {!supported ? (
        <Text>
          Imports go to a hosted NuGet, Helm or Docker repository; this is a{' '}
          {repo.data.format} {repo.data.kind} repository.
        </Text>
      ) : active ? (
        <Text>
          An import is {active.state}; a repository runs one import at a time.
        </Text>
      ) : imports.isSuccess ? (
        <StartImportForm
          key={imports.data[0]?.id ?? 'first'}
          repo={name}
          docker={repo.data.format === 'docker'}
          previous={imports.data[0]}
        />
      ) : null}

      <div className="space-y-4">
        <Subheading>Imports</Subheading>
        {imports.isError ? (
          <ErrorState
            title="Could not load the imports"
            message={imports.error?.message}
            onRetry={() => void imports.refetch()}
          />
        ) : imports.isLoading ? (
          <Text>Loading imports…</Text>
        ) : (imports.data ?? []).length === 0 ? (
          <Text>No imports yet.</Text>
        ) : (
          (imports.data ?? []).map((i) => (
            <ImportCard key={i.id} repo={name} imp={i} />
          ))
        )}
      </div>
    </section>
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
  const [source, setSource] = useState(previous?.source_repository ?? '')
  const [username, setUsername] = useState(previous?.username ?? '')
  const [password, setPassword] = useState('')
  const [registryUrl, setRegistryUrl] = useState(previous?.registry_url ?? '')
  const [onConflict, setOnConflict] = useState<OnConflict>(
    previous?.on_conflict ?? 'skip',
  )
  const [concurrency, setConcurrency] = useState(
    String(previous?.concurrency ?? 4),
  )
  // A first import starts as a dry run; after a dry run, the real one.
  const [dryRun, setDryRun] = useState(previous === undefined)
  const [formError, setFormError] = useState<string | null>(null)

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setFormError(null)
    if (!url.trim() || !source.trim()) {
      setFormError('Enter the Nexus URL and the repository to import.')
      return
    }
    if (username.trim() !== '' && password === '') {
      setFormError('Enter the password of the Nexus user.')
      return
    }
    const n = Number(concurrency)
    if (!Number.isInteger(n) || n < 1 || n > 16) {
      setFormError('Concurrency must be a whole number from 1 to 16.')
      return
    }
    const body: CreateImport = {
      url: url.trim(),
      repository: source.trim(),
      on_conflict: onConflict,
      concurrency: n,
      dry_run: dryRun,
    }
    if (username.trim() !== '') {
      body.username = username.trim()
      body.password = password
    }
    if (docker && registryUrl.trim() !== '') {
      body.registry_url = registryUrl.trim()
    }
    create.mutate(body, { onSuccess: () => setPassword('') })
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="space-y-4 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <Subheading>Import from Nexus</Subheading>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field>
          <Label>Nexus URL</Label>
          <Description>With its context path, if it has one.</Description>
          <Input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://nexus.example.com"
          />
        </Field>
        <Field>
          <Label>Nexus repository</Label>
          <Description>A hosted repository of the same format.</Description>
          <Input
            value={source}
            onChange={(e) => setSource(e.target.value)}
            placeholder={docker ? 'docker-hosted' : 'nuget-hosted'}
          />
        </Field>
        <Field>
          <Label>Username</Label>
          <Description>Leave empty to read anonymously.</Description>
          <Input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="off"
          />
        </Field>
        <Field>
          <Label>Password</Label>
          <Description>
            Sealed with the secret encryption, and deleted when the import
            completes.
          </Description>
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
          />
        </Field>
        {docker && (
          <Field className="sm:col-span-2">
            <Label>Registry URL</Label>
            <Description>
              The Nexus repository&rsquo;s registry API. Empty: its path route,{' '}
              <span className="font-mono">
                &lt;Nexus URL&gt;/repository/&lt;name&gt;
              </span>
              ; otherwise its connector, e.g.{' '}
              <span className="font-mono">http://nexus.example.com:8082</span>.
            </Description>
            <Input
              value={registryUrl}
              onChange={(e) => setRegistryUrl(e.target.value)}
            />
          </Field>
        )}
        <Field>
          <Label>A version Forge has with other bytes</Label>
          <Select
            value={onConflict}
            onChange={(e) => setOnConflict(e.target.value as OnConflict)}
          >
            <option value="skip">Skip it and report it</option>
            <option value="overwrite">Overwrite it with Nexus&rsquo; bytes</option>
            <option value="fail">Fail the import</option>
          </Select>
        </Field>
        <Field>
          <Label>Concurrency</Label>
          <Description>Items copied at a time (1–16).</Description>
          <Input
            type="number"
            value={concurrency}
            onChange={(e) => setConcurrency(e.target.value)}
          />
        </Field>
      </div>
      <CheckboxField>
        <Checkbox checked={dryRun} onChange={setDryRun} />
        <Label>Dry run</Label>
        <Description>
          Count what would be copied, its size and the conflicts, without
          writing anything.
        </Description>
      </CheckboxField>
      <div className="flex items-center gap-3">
        <Button type="submit" disabled={create.isPending}>
          {create.isPending
            ? 'Checking Nexus…'
            : dryRun
              ? 'Start dry run'
              : 'Start import'}
        </Button>
      </div>
      {formError && (
        <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
          {formError}
        </p>
      )}
      {create.isError && (
        <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
          {create.error.body || create.error.message}
        </p>
      )}
    </form>
  )
}

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
    <article
      aria-label={`Import ${imp.id}`}
      className="space-y-3 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <div className="flex flex-wrap items-center gap-2">
        <Badge color={STATE_COLORS[imp.state]}>{imp.state}</Badge>
        {imp.dry_run && <Badge color="violet">dry run</Badge>}
        {active && imp.cancel_requested && <Badge>cancelling</Badge>}
        <span className="font-mono text-sm/6">
          {imp.url} · {imp.source_repository}
        </span>
      </div>
      <Text>
        {imp.state === 'queued'
          ? 'Waiting for a worker.'
          : imp.phase === 'scan' && active
            ? `Scanning Nexus: ${p.found} found so far.`
            : `${done} of ${p.found} done.`}{' '}
        {p.assets > 0 &&
          `The Nexus repository holds ${p.assets} assets, ${formatBytes(p.size)}. `}
        Started {formatDateTime(imp.started_at ?? imp.created_at)}
        {imp.finished_at && `, ended ${formatDateTime(imp.finished_at)}`}.
        {imp.nexus_version && ` ${imp.nexus_version}.`}
      </Text>
      {p.found > 0 && (
        <div
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={p.found}
          aria-valuenow={done}
          className="h-1.5 overflow-hidden rounded-full bg-zinc-950/5 dark:bg-white/10"
        >
          <div
            className="h-full bg-sky-500"
            style={{ width: `${(done / p.found) * 100}%` }}
          />
        </div>
      )}
      <dl className="flex flex-wrap gap-x-6 gap-y-1 text-sm/6">
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
            <div key={state} className="flex gap-1">
              <dt className="text-zinc-500 dark:text-zinc-400">{state}</dt>
              <dd className="font-medium">{n}</dd>
            </div>
          ))}
        <div className="flex gap-1">
          <dt className="text-zinc-500 dark:text-zinc-400">copied</dt>
          <dd className="font-medium">{formatBytes(p.bytes_copied)}</dd>
        </div>
        {imp.dry_run && p.planned > 0 && (
          <div className="flex gap-1">
            <dt className="text-zinc-500 dark:text-zinc-400">would copy</dt>
            <dd className="font-medium">{formatBytes(p.planned_size)}</dd>
          </div>
        )}
      </dl>
      {imp.last_error && (
        <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
          {imp.last_error}
        </p>
      )}

      <div className="flex flex-wrap items-end gap-3">
        {active && !imp.cancel_requested && (
          <Button
            outline
            disabled={cancel.isPending}
            onClick={() => cancel.mutate(imp.id)}
          >
            Cancel
          </Button>
        )}
        {!active && needsPassword && (p.failed > 0 || imp.state !== 'completed') && (
          <Field className="min-w-56">
            <Label>Nexus password</Label>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
            />
          </Field>
        )}
        {(imp.state === 'cancelled' || imp.state === 'failed') && (
          <Button
            outline
            disabled={resume.isPending || (needsPassword && password === '')}
            onClick={() => doResume(false)}
          >
            Resume
          </Button>
        )}
        {!active && p.failed > 0 && (
          <Button
            outline
            disabled={resume.isPending || (needsPassword && password === '')}
            onClick={() => doResume(true)}
          >
            Retry failed items
          </Button>
        )}
        {!active && (
          <Button
            plain
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
              plain
              onClick={() => setShowItems(showItems === s ? null : s)}
            >
              {showItems === s ? `Hide ${s}` : `Show ${s}`}
            </Button>
          ))}
      </div>
      {error && (
        <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
          {error.body || error.message}
        </p>
      )}
      {showItems && <ItemList repo={repo} id={imp.id} state={showItems} />}
    </article>
  )
}

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
  if (items.isLoading) return <Text>Loading…</Text>
  if (items.isError) {
    return (
      <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
        {items.error.message}
      </p>
    )
  }
  return (
    <ul className="divide-y divide-zinc-950/5 text-sm/6 dark:divide-white/5">
      {(items.data ?? []).map((item) => (
        <li key={item.id} className="py-1.5">
          <span className="font-mono">
            {item.name} {item.version}
          </span>
          {item.size != null && (
            <span className="text-zinc-500 dark:text-zinc-400">
              {' '}
              · {formatBytes(item.size)}
            </span>
          )}
          {item.detail && (
            <span className="block text-zinc-600 dark:text-zinc-400">
              {item.detail}
            </span>
          )}
        </li>
      ))}
    </ul>
  )
}
