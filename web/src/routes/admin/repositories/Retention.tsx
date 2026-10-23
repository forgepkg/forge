import { useEffect, useRef, useState } from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { useQueryClient } from '@tanstack/react-query'

import type { RepoView } from '~/api/repositories'
import {
  retentionKeys,
  type AuditRecord,
  type PreviewView,
  type RetentionPolicy,
  type RetentionView,
} from '~/api/retention'
import { useRepository } from '~/queries/useRepositories'
import {
  useDeleteRetention,
  usePreviewRetention,
  useRetention,
  useRetentionAudit,
  useRunRetention,
  useSaveRetention,
} from '~/queries/useRetention'
import {
  RetentionPolicyForm,
  buildPolicy,
  describeReason,
  draftFromPolicy,
  policyDeletes,
  policyShape,
  summarizePreview,
  validateDraft,
  type DraftErrors,
  type PolicyDraft,
  type PolicyShape,
} from '~/components/RetentionPolicyForm'
import {
  Button,
  CodeBlock,
  Columns,
  Dialog,
  EmptyState,
  FactList,
  Notice,
  Page,
  PageHeader,
  Panel,
  Skeleton,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Toolbar,
  useToast,
  type Tone,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'
import { formatDateTime, shortDigest } from '~/lib/oci'

export const Route = createFileRoute(
  '/_app/manage/repositories/$repo/retention',
)({
  component: RepositoryRetention,
})

/** Rows of a preview table shown before "Show all". */
const PREVIEW_ROWS = 100

/** Audit rows per page. */
const AUDIT_PAGE = 50

/** How long the screen waits for a requested run before it stops polling. */
const RUN_WATCH_MS = 5 * 60 * 1000

/**
 * A repository's retention (`/admin/repositories/{name}/retention`): the
 * policy editor, a preview of what the policy in the form would remove
 * (before it is saved), the run state with Run now, and the audit log of
 * every run. Saving a policy whose runs delete, without "dry run only", and
 * removing the policy both ask first. Group repositories hold nothing of
 * their own and take no policy.
 */
function RepositoryRetention() {
  const { repo: name } = Route.useParams()
  const repo = useRepository(name)

  const crumbs = [
    { label: 'Repositories', to: '/manage/repositories' },
    { label: name, to: '/manage/repositories/$repo', params: { repo: name } },
    { label: 'Retention' },
  ]
  const title = `Retention of ${name}`

  if (repo.isError) {
    return (
      <Page>
        <PageHeader title={title} icon="Clock" crumbs={crumbs} />
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
        <PageHeader title={title} icon="Clock" crumbs={crumbs} />
        <Skeleton lines={4} label="Loading repository…" />
      </Page>
    )
  }
  const shape = policyShape(repo.data)

  return (
    <Page>
      <PageHeader
        title={title}
        icon="Clock"
        crumbs={crumbs}
        kind={repo.data.kind}
        format={repo.data.format}
        description={DESCRIPTIONS[shape ?? 'group']}
      />
      {shape ? (
        <RetentionScreen key={name} repo={repo.data} shape={shape} />
      ) : (
        <Notice tone="info">
          A group repository holds nothing of its own; set retention on its
          members.
        </Notice>
      )}
    </Page>
  )
}

const DESCRIPTIONS: Record<PolicyShape | 'group', string> = {
  package:
    'Rules that unlist or delete versions of this repository’s packages once they are old or unused. The worker runs the policy in the background; every run is recorded in the audit log.',
  proxy:
    'Rules that evict cached versions nobody pulled for a while, to free their space. An evicted version stays listed, and its next pull fetches it from the upstream again.',
  file: 'Rules that delete files once they are old or unused, keeping the newest of each directory. On a proxy, a deleted file is fetched from the upstream again on its next download.',
  image:
    'Rules that delete old or unused tags, and manifests left without a tag. A layer is removed only once no manifest of the repository uses it.',
  group: 'Group repositories take no retention policy.',
}

function RetentionScreen({ repo, shape }: { repo: RepoView; shape: PolicyShape }) {
  const name = repo.name
  const queryClient = useQueryClient()
  // The ledger's last finish when Run now was pressed: the run asked for is
  // pending until the ledger shows another one.
  const [asked, setAsked] = useState<{ finished: string | null } | null>(null)
  // Bumped after a save or a removal: the form starts again from the server.
  const [seed, setSeed] = useState(0)
  const finishedOf = (v: RetentionView | undefined) => v?.last_run?.finished_at ?? null
  // Polled while the run is pending (and, by the hook, while one runs).
  const view = useRetention(name, (v) => asked !== null && finishedOf(v) === asked.finished)
  const lastFinished = finishedOf(view.data)
  const runPending = asked !== null && lastFinished === asked.finished

  // Without a worker the run never starts: stop waiting after a while.
  useEffect(() => {
    if (!runPending) return
    const t = setTimeout(() => setAsked(null), RUN_WATCH_MS)
    return () => clearTimeout(t)
  }, [runPending])

  // A run that finished (asked for or scheduled) adds audit rows.
  const loaded = view.data !== undefined
  const seen = useRef<string | null | undefined>(undefined)
  useEffect(() => {
    if (!loaded) return
    if (seen.current !== undefined && seen.current !== lastFinished) {
      void queryClient.invalidateQueries({ queryKey: retentionKeys.audits(name) })
    }
    seen.current = lastFinished
  }, [loaded, lastFinished, name, queryClient])

  if (view.isError) {
    return (
      <ErrorState
        title="Could not load the retention policy"
        message={view.error?.message}
        onRetry={() => void view.refetch()}
      />
    )
  }
  if (view.isLoading || !view.data) {
    return <Skeleton lines={6} label="Loading the retention policy…" />
  }

  return (
    <Columns
      asideLabel="Runs"
      aside={
        <RunPanel
          repo={name}
          view={view.data}
          runPending={runPending}
          onRun={() => setAsked({ finished: lastFinished })}
        />
      }
    >
      <PolicyPanel
        key={seed}
        repo={name}
        shape={shape}
        stored={view.data.policy}
        onReset={() => setSeed((n) => n + 1)}
      />
      <AuditPanel repo={name} />
    </Columns>
  )
}

/**
 * The policy form, its preview and the save and remove confirmations. The
 * form starts from the stored policy, or from an example dry-run policy.
 */
function PolicyPanel({
  repo,
  shape,
  stored,
  onReset,
}: {
  repo: string
  shape: PolicyShape
  stored: RetentionPolicy | null
  onReset: () => void
}) {
  const toast = useToast()
  const save = useSaveRetention(repo)
  const remove = useDeleteRetention(repo)
  const preview = usePreviewRetention(repo)
  const [draft, setDraft] = useState<PolicyDraft>(() => draftFromPolicy(shape, stored))
  const [errors, setErrors] = useState<DraftErrors | null>(null)
  const [refused, setRefused] = useState<string | null>(null)
  const [previewed, setPreviewed] = useState<{
    json: string
    policy: RetentionPolicy
    result: PreviewView
  } | null>(null)
  const [confirming, setConfirming] = useState<RetentionPolicy | null>(null)
  const [removing, setRemoving] = useState(false)
  const [showJson, setShowJson] = useState(false)

  const valid = validateDraft(shape, draft) === null
  const current = valid ? buildPolicy(shape, draft) : null
  const currentJson = current ? JSON.stringify(current) : null
  const busy = save.isPending || preview.isPending || remove.isPending

  function change(next: PolicyDraft) {
    setDraft(next)
    if (errors) setErrors(validateDraft(shape, next))
  }

  /** The form's policy, or `null` with the errors shown. */
  function checked(): RetentionPolicy | null {
    const errs = validateDraft(shape, draft)
    setErrors(errs)
    setRefused(null)
    return errs ? null : buildPolicy(shape, draft)
  }

  function runPreview(policy: RetentionPolicy, then?: (p: PreviewView) => void) {
    preview.mutate(policy, {
      onSuccess: (result) => {
        setPreviewed({ json: JSON.stringify(policy), policy, result })
        then?.(result)
      },
      onError: (e) => setRefused(e.body || e.message),
    })
  }

  function store(policy: RetentionPolicy) {
    save.mutate(policy, {
      onSuccess: () => {
        setConfirming(null)
        toast({ tone: 'ok', title: `Saved the retention policy of ${repo}` })
        onReset()
      },
      onError: (e) => {
        setConfirming(null)
        setRefused(e.body || e.message)
      },
    })
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const policy = checked()
    if (!policy) return
    if (!policyDeletes(shape, policy)) {
      store(policy)
      return
    }
    // The confirmation states what the policy would delete now.
    if (previewed?.json === JSON.stringify(policy)) setConfirming(policy)
    else runPreview(policy, () => setConfirming(policy))
  }

  return (
    <>
      <Panel
        as="form"
        onSubmit={handleSubmit}
        noValidate
        title="Policy"
        description={
          stored
            ? undefined
            : 'This repository has no policy. The form starts with an example, as a dry run; nothing is stored until you save it.'
        }
        actions={
          stored && (
            <Button
              size="sm"
              variant="danger"
              icon="Trash"
              onClick={() => setRemoving(true)}
            >
              Remove policy
            </Button>
          )
        }
        footer={
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Button
              variant="ghost"
              aria-expanded={showJson}
              iconEnd={showJson ? 'ArrowUp' : 'ArrowDown'}
              onClick={() => setShowJson((v) => !v)}
            >
              {showJson ? 'Hide JSON' : 'Show JSON'}
            </Button>
            <div className="fg-actions">
              <Button
                icon="Eye"
                disabled={busy}
                onClick={() => {
                  const policy = checked()
                  if (policy) runPreview(policy)
                }}
              >
                {preview.isPending && !confirming ? 'Previewing…' : 'Preview'}
              </Button>
              <Button type="submit" variant="primary" disabled={busy}>
                {save.isPending ? 'Saving…' : 'Save policy'}
              </Button>
            </div>
          </div>
        }
      >
        <RetentionPolicyForm
          shape={shape}
          draft={draft}
          errors={errors}
          onChange={change}
        />
        {errors && (
          <Notice tone="danger" className="mt-4">
            Fix the fields marked above.
          </Notice>
        )}
        {refused && (
          <Notice tone="danger" title="The policy was refused" className="mt-4">
            {refused}
          </Notice>
        )}
        {showJson && (
          <div className="mt-4">
            {currentJson ? (
              <CodeBlock
                title="Policy JSON"
                copyLabel="Copy the policy"
                placeholders={[]}
                code={JSON.stringify(current, null, 2)}
              />
            ) : (
              <p className="fg-text">Fix the fields marked above to see the JSON.</p>
            )}
          </div>
        )}
      </Panel>

      <PreviewPanel
        shape={shape}
        previewed={previewed}
        stale={previewed !== null && previewed.json !== currentJson}
      />

      <Dialog
        open={confirming !== null}
        onClose={() => setConfirming(null)}
        title="Save a policy that removes content?"
        icon="Alert"
        tone="danger"
        description={
          <>
            {previewed && `${summarizePreview(shape, previewed.result)} `}
            Its runs are not dry runs: the worker can start one as soon as the
            policy is saved, and each run removes what is eligible then. To
            stage the policy first, cancel and turn on “Dry run only”.
          </>
        }
        confirmLabel={save.isPending ? 'Saving…' : 'Save policy'}
        confirmVariant="danger-solid"
        confirmDisabled={save.isPending}
        onConfirm={() => confirming && store(confirming)}
      />

      <Dialog
        open={removing}
        onClose={() => setRemoving(false)}
        title={`Remove the retention policy of ${repo}?`}
        icon="Trash"
        tone="danger"
        description="Forge stops running retention on this repository. What earlier runs removed stays removed, and the audit log is kept."
        confirmLabel={remove.isPending ? 'Removing…' : 'Remove policy'}
        confirmVariant="danger-solid"
        confirmDisabled={remove.isPending}
        onConfirm={() =>
          remove.mutate(undefined, {
            onSuccess: () => {
              setRemoving(false)
              toast({ tone: 'ok', title: `Removed the retention policy of ${repo}` })
              onReset()
            },
            onError: (e) => {
              setRemoving(false)
              setRefused(e.body || e.message)
            },
          })
        }
      />
    </>
  )
}

interface PreviewRow {
  key: string
  name: string
  detail?: string
  action?: string
  rule: string
  why: string
}

interface PreviewSection {
  title: string
  nameHeader: string
  detailHeader?: string
  rows: PreviewRow[]
}

/** The tables of a preview, by the repository's shape. */
function previewSections(shape: PolicyShape, p: PreviewView): PreviewSection[] {
  switch (shape) {
    case 'package':
      return [
        {
          title: 'Versions',
          nameHeader: 'Package',
          detailHeader: 'Version',
          rows: p.decisions.map((d) => ({
            key: `c${d.component_id}`,
            name: d.package_name,
            detail: d.version,
            action: d.action === 'unlist' ? 'unlist' : 'delete',
            rule: d.rule_id,
            why: describeReason(d.reason),
          })),
        },
      ]
    case 'proxy':
      return [
        {
          title: 'Cached versions',
          nameHeader: 'Package',
          detailHeader: 'Version',
          rows: p.proxy_decisions.map((d) => ({
            key: `p${d.cached_version_id}`,
            name: d.package_name,
            detail: d.version,
            rule: d.rule_id,
            why: describeReason(d.reason),
          })),
        },
      ]
    case 'file':
      return [
        {
          title: 'Files',
          nameHeader: 'Path',
          rows: (p.file_decisions ?? []).map((d) => ({
            key: `f${d.file_id}`,
            name: d.path,
            rule: d.rule_id,
            why: describeReason(d.reason),
          })),
        },
      ]
    case 'image':
      return [
        {
          title: 'Tags',
          nameHeader: 'Image',
          detailHeader: 'Tag',
          rows: (p.image_decisions?.tags ?? []).map((d) => ({
            key: `t${d.image}:${d.tag}`,
            name: d.image,
            detail: d.tag,
            rule: d.rule_id,
            why: describeReason(d.reason),
          })),
        },
        {
          title: 'Manifests',
          nameHeader: 'Image',
          detailHeader: 'Digest',
          rows: (p.image_decisions?.manifests ?? []).map((d) => ({
            key: `m${d.manifest_id}`,
            name: d.image,
            detail: shortDigest(d.digest),
            rule: d.rule_id,
            why: describeReason(d.reason),
          })),
        },
      ]
  }
}

/** What the previewed policy would remove now, with the rule behind each. */
function PreviewPanel({
  shape,
  previewed,
  stale,
}: {
  shape: PolicyShape
  previewed: { policy: RetentionPolicy; result: PreviewView } | null
  stale: boolean
}) {
  return (
    <Panel
      title="Preview"
      description="What the policy in the form would remove if it ran now. A preview changes nothing."
    >
      {!previewed ? (
        <EmptyState title="Not previewed yet" icon="Eye" bordered={false}>
          Preview the policy to see each item it would remove and the rule
          that selects it.
        </EmptyState>
      ) : (
        <div className="grid gap-4">
          {stale && (
            <Notice tone="warn">
              The form changed since this preview; preview it again.
            </Notice>
          )}
          <p className="fg-text">{summarizePreview(shape, previewed.result)}</p>
          {previewed.policy.enabled === false && (
            <Notice tone="info">
              The policy is disabled: this is what it would do once enabled.
            </Notice>
          )}
          {previewed.policy.dry_run_only && previewed.policy.enabled !== false && (
            <Notice tone="info">
              Dry run only: its runs record these in the audit log and remove
              nothing.
            </Notice>
          )}
          {previewSections(shape, previewed.result)
            .filter((s) => s.rows.length > 0)
            .map((s) => (
              <PreviewTable key={s.title} section={s} />
            ))}
        </div>
      )}
    </Panel>
  )
}

function PreviewTable({ section }: { section: PreviewSection }) {
  const [all, setAll] = useState(false)
  const rows = all ? section.rows : section.rows.slice(0, PREVIEW_ROWS)
  const hasAction = section.rows.some((r) => r.action)
  return (
    <div className="grid gap-2">
      <h3 className="fg-subtitle">
        {section.title} <span className="fg-muted">{section.rows.length}</span>
      </h3>
      <Table caption={`${section.title} the policy would remove`} dense>
        <TableHead>
          <TableHeader>{section.nameHeader}</TableHeader>
          {section.detailHeader && <TableHeader>{section.detailHeader}</TableHeader>}
          {hasAction && <TableHeader>Action</TableHeader>}
          <TableHeader>Rule</TableHeader>
          <TableHeader>Why</TableHeader>
        </TableHead>
        <TableBody>
          {rows.map((r) => (
            <TableRow key={r.key}>
              <TableCell lead className="font-mono [overflow-wrap:anywhere]">
                {r.name}
              </TableCell>
              {section.detailHeader && (
                <TableCell className="font-mono" nowrap>
                  {r.detail}
                </TableCell>
              )}
              {hasAction && (
                <TableCell nowrap>
                  <StatusBadge tone={r.action === 'delete' ? 'danger' : 'neutral'}>
                    {r.action}
                  </StatusBadge>
                </TableCell>
              )}
              <TableCell className="font-mono" nowrap>
                {r.rule}
              </TableCell>
              <TableCell>{r.why}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {!all && section.rows.length > PREVIEW_ROWS && (
        <div>
          <Button variant="ghost" onClick={() => setAll(true)}>
            {`Show all ${section.rows.length}`}
          </Button>
        </div>
      )}
    </div>
  )
}

/** The run ledger: state, last and next run, its summary, and Run now. */
function RunPanel({
  repo,
  view,
  runPending,
  onRun,
}: {
  repo: string
  view: RetentionView
  runPending: boolean
  onRun: () => void
}) {
  const run = useRunRetention(repo)
  const ledger = view.last_run
  const policy = view.policy
  const running = ledger?.state === 'running'
  const summary = ledger?.last_run_summary

  const nextRun = !policy
    ? 'not scheduled: no policy'
    : policy.enabled === false
      ? 'not scheduled: disabled'
      : formatDateTime(ledger?.next_run_at)

  return (
    <Panel title="Runs">
      <div className="grid gap-4">
        {ledger ? (
          <FactList
            items={[
              {
                term: 'State',
                value: (
                  <StatusBadge tone={running ? 'heat' : 'neutral'}>
                    {ledger.state}
                  </StatusBadge>
                ),
              },
              { term: 'Next run', value: nextRun },
              { term: 'Last started', value: formatDateTime(ledger.started_at) },
              { term: 'Last finished', value: formatDateTime(ledger.finished_at) },
              ...(summary
                ? [
                    {
                      term: 'Last run',
                      value: `${summary.deleted ?? 0} deleted, ${summary.unlisted ?? 0} unlisted, ${summary.skipped ?? 0} skipped, of ${summary.evaluated ?? 0}`,
                    },
                    {
                      term: 'Blobs queued for deletion',
                      value: String(summary.blobs_enqueued ?? 0),
                    },
                  ]
                : []),
            ]}
          />
        ) : (
          <p className="fg-text">
            {policy ? 'Not run yet.' : 'No policy is stored, so nothing runs.'}
          </p>
        )}
        {ledger?.last_error && (
          <Notice tone="danger" title="The last run failed">
            {ledger.last_error}
          </Notice>
        )}
        {runPending && !running && (
          <Notice tone="info">
            Run requested. The retention worker starts it on its next poll,
            within about half a minute.
          </Notice>
        )}
        {run.isError && <Notice tone="danger">{run.error.body || run.error.message}</Notice>}
        <div>
          <Button
            icon="Refresh"
            disabled={!policy || running || runPending || run.isPending}
            onClick={() => run.mutate(undefined, { onSuccess: onRun })}
          >
            Run now
          </Button>
          <p className="fg-field-desc mt-2">
            {policy
              ? 'Runs the stored policy without waiting for the minimum time between runs.'
              : 'Save a policy to run it.'}
          </p>
        </div>
      </div>
    </Panel>
  )
}

const AUDIT_ACTIONS: Record<string, { label: string; tone: Tone }> = {
  hard_delete: { label: 'deleted', tone: 'danger' },
  delete_tag: { label: 'deleted', tone: 'danger' },
  delete_manifest: { label: 'deleted', tone: 'danger' },
  unlist: { label: 'unlisted', tone: 'neutral' },
  skipped: { label: 'skipped', tone: 'warn' },
}

/** An audit row's target: what was removed, and its version, tag or digest. */
function auditTarget(r: AuditRecord): { name: string; detail: string } {
  switch (r.target_kind) {
    case 'oci_manifest':
      return { name: r.package_name, detail: shortDigest(r.version) }
    case 'raw_file':
      return { name: r.package_name, detail: '' }
    default:
      return { name: r.package_name, detail: r.version }
  }
}

function auditAction(r: AuditRecord): { label: string; tone: Tone } {
  if (r.target_kind === 'proxy_cached_version' && r.action === 'hard_delete') {
    return { label: 'evicted', tone: 'neutral' }
  }
  return AUDIT_ACTIONS[r.action] ?? { label: r.action.replace(/_/g, ' '), tone: 'neutral' }
}

/** Every run's decisions, newest first; filtered to one run, paged back. */
function AuditPanel({ repo }: { repo: string }) {
  const [runId, setRunId] = useState<string | undefined>(undefined)
  // The `before` cursors of the pages above the current one.
  const [cursors, setCursors] = useState<number[]>([])
  const audit = useRetentionAudit(repo, {
    run_id: runId,
    before: cursors[cursors.length - 1],
    limit: AUDIT_PAGE,
  })
  const items = audit.data?.items ?? []

  function filter(id: string | undefined) {
    setRunId(id)
    setCursors([])
  }

  return (
    <Panel title="Audit log" flush>
      {runId && (
        <Toolbar>
          <span className="fg-text">
            Run <span className="font-mono">{runId}</span>
          </span>
          <Button size="sm" variant="ghost" icon="X" onClick={() => filter(undefined)}>
            Show every run
          </Button>
        </Toolbar>
      )}
      {audit.isError ? (
        <ErrorState
          title="Could not load the audit log"
          message={audit.error?.message}
          onRetry={() => void audit.refetch()}
        />
      ) : audit.isLoading ? (
        <Skeleton variant="table" rows={3} columns={5} label="Loading the audit log…" />
      ) : items.length === 0 ? (
        <EmptyState title="No audit rows" icon="Clock" bordered={false}>
          {cursors.length > 0
            ? 'There are no older rows.'
            : 'Each run records here what it unlisted, deleted or skipped, dry runs included.'}
        </EmptyState>
      ) : (
        <Table caption="Retention audit log">
          <TableHead>
            <TableHeader width="170px">Time</TableHeader>
            <TableHeader>Target</TableHeader>
            <TableHeader>Action</TableHeader>
            <TableHeader>Rule</TableHeader>
            <TableHeader>Run</TableHeader>
          </TableHead>
          <TableBody>
            {items.map((r) => {
              const target = auditTarget(r)
              const action = auditAction(r)
              return (
                <TableRow key={r.id}>
                  <TableCell nowrap>{formatDateTime(r.created_at)}</TableCell>
                  <TableCell lead>
                    <span className="font-mono [overflow-wrap:anywhere]">
                      {target.name}
                      {target.detail && ` ${target.detail}`}
                    </span>
                  </TableCell>
                  <TableCell nowrap>
                    <span className="inline-flex flex-wrap gap-1">
                      <StatusBadge tone={action.tone}>{action.label}</StatusBadge>
                      {r.dry_run && (
                        <StatusBadge dot={false} title="Recorded, not applied">
                          dry run
                        </StatusBadge>
                      )}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono" nowrap>
                    {r.rule_id}
                  </TableCell>
                  <TableCell nowrap>
                    {runId ? (
                      <span className="font-mono">{r.run_id.slice(0, 8)}</span>
                    ) : (
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`Show only run ${r.run_id}`}
                        title="Show only this run"
                        onClick={() => filter(r.run_id)}
                      >
                        <span className="font-mono">{r.run_id.slice(0, 8)}</span>
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      )}
      {(cursors.length > 0 || items.length === AUDIT_PAGE) && (
        <div className="fg-actions fg-actions--end border-t border-line px-5 py-3">
          <Button
            size="sm"
            icon="ChevronLeft"
            disabled={cursors.length === 0}
            onClick={() => setCursors((c) => c.slice(0, -1))}
          >
            Newer
          </Button>
          <Button
            size="sm"
            iconEnd="ChevronRight"
            disabled={items.length < AUDIT_PAGE}
            onClick={() => setCursors((c) => [...c, items[items.length - 1].id])}
          >
            Older
          </Button>
        </div>
      )}
    </Panel>
  )
}
