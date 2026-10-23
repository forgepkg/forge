import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { makeQueryClient } from '~/lib/queryClient'
import { clearSession, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { RepoView } from '~/api/repositories'
import type {
  AuditRecord,
  PreviewView,
  RetentionPolicy,
  RetentionView,
} from '~/api/retention'
import { routeTree } from '~/routeTree.gen'

/**
 * The retention screen (`/manage/repositories/$repo/retention`), driven
 * against the real route tree and query hooks:
 *  - the edit screen of a hosted or proxy repository links to it, a group's
 *    does not, and a group's screen says it takes no policy;
 *  - a repository without a policy starts from an example dry-run policy;
 *    the preview sends the draft and lists what it removes, with the rule;
 *  - saving a policy that deletes asks first, stating the preview's counts;
 *    a refused policy shows the server's reason at the form;
 *  - a stored policy seeds the form (docker and proxy fields, intervals);
 *    removing it asks first;
 *  - Run now, the run state, and the audit log filtered to a run and paged.
 */

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

function repo(over: Partial<RepoView>): RepoView {
  return {
    id: 1,
    name: 'nuget-internal',
    format: 'nuget',
    kind: 'hosted',
    anonymous_read: false,
    online: true,
    remote_url: null,
    package_delay_seconds: 0,
    upstream_username: null,
    has_upstream_password: false,
    metadata_ttl_seconds: null,
    not_found_ttl_seconds: null,
    allow_redeploy: false,
    prefer_hosted: false,
    reserved_prefixes: [],
    host: null,
    immutable_tags: false,
    latest_mutable: false,
    writable_member: null,
    max_upload_bytes: null,
    ...over,
  }
}

const storedPolicy: RetentionPolicy = {
  version: 1,
  enabled: true,
  dry_run_only: false,
  min_run_interval_seconds: 86400,
  rules: [
    {
      id: 'stale-releases',
      action: 'hard_delete',
      scope: 'hosted',
      release_type: 'releases',
      package_name_prefix: 'acme.',
      criteria: { keep_last_n: 5, older_than_days: 180 },
    },
  ],
}

const ledger: RetentionView['last_run'] = {
  state: 'idle',
  next_run_at: '2026-10-24T03:00:00Z',
  started_at: '2026-10-23T03:00:00Z',
  finished_at: '2026-10-23T03:00:05Z',
  locked_until: null,
  last_error: null,
  last_run_summary: {
    evaluated: 120,
    unlisted: 0,
    deleted: 3,
    blobs_enqueued: 2,
    skipped: 1,
  },
}

function preview(over: Partial<PreviewView>): PreviewView {
  return {
    decisions: [
      {
        component_id: 11,
        package_name: 'acme.core',
        version: '1.0.0',
        action: 'hard_delete',
        rule_id: 'keep-recent',
        reason: { not_downloaded_for_days: 90 },
      },
      {
        component_id: 12,
        package_name: 'acme.core',
        version: '1.1.0',
        action: 'unlist',
        rule_id: 'keep-recent',
        reason: { older_than_days: 30 },
      },
    ],
    proxy_decisions: [],
    counts: { evaluated: 12, unlisted: 1, deleted: 1 },
    ...over,
  }
}

function auditRow(over: Partial<AuditRecord>): AuditRecord {
  return {
    id: 100,
    run_id: '11111111-2222-3333-4444-555555555555',
    rule_id: 'stale-releases',
    action: 'hard_delete',
    target_kind: 'component',
    package_name: 'acme.core',
    version: '1.0.0',
    component_id: 11,
    blob_sha256: null,
    ref_count_after: 0,
    blob_delete_enqueued: true,
    dry_run: false,
    reason: { older_than_days: 180 },
    created_at: '2026-10-23T03:00:04Z',
    ...over,
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

interface Handlers {
  repositories: RepoView[]
  view?: RetentionView
  audit?: (query: URLSearchParams) => AuditRecord[]
  onPreview?: (body: { policy?: RetentionPolicy }) => Response
  onPut?: (body: { policy: RetentionPolicy }) => Response
}

function mockApi(h: Handlers) {
  let view: RetentionView = h.view ?? { policy: null, last_run: null }
  fetchMock.mockImplementation(
    (input: RequestInfo | URL, init?: RequestInit) => {
      const raw = typeof input === 'string' ? input : input.toString()
      const url = new URL(raw, 'http://localhost')
      const method = (init?.method ?? 'GET').toUpperCase()
      const path = url.pathname
      const body = init?.body ? JSON.parse(init.body as string) : {}

      if (path.endsWith('/admin/me')) return Promise.resolve(json(adminMe))
      if (path.endsWith('/retention/preview') && method === 'POST') {
        return Promise.resolve(h.onPreview ? h.onPreview(body) : json(preview({})))
      }
      if (path.endsWith('/retention/run') && method === 'POST') {
        return Promise.resolve(json({ scheduled: true }, 202))
      }
      if (path.endsWith('/retention/audit')) {
        return Promise.resolve(json({ items: h.audit?.(url.searchParams) ?? [] }))
      }
      if (path.endsWith('/retention')) {
        if (method === 'GET') return Promise.resolve(json(view))
        if (method === 'PUT') {
          if (h.onPut) {
            const resp = h.onPut(body)
            if (!resp.ok) return Promise.resolve(resp)
          }
          view = { policy: body.policy, last_run: view.last_run ?? ledger }
          return Promise.resolve(json(view))
        }
        if (method === 'DELETE') {
          view = { ...view, policy: null }
          return Promise.resolve(new Response(null, { status: 204 }))
        }
      }
      const m = path.match(/\/admin\/repositories\/([^/]+)$/)
      if (m && method === 'GET') {
        const found = h.repositories.find(
          (r) => r.name === decodeURIComponent(m[1]),
        )
        return Promise.resolve(found ? json(found) : json('nope', 404))
      }
      if (path.endsWith('/admin/repositories')) {
        return Promise.resolve(json(h.repositories))
      }
      return Promise.resolve(new Response('not found', { status: 404 }))
    },
  )
}

async function renderAt(initialPath: string) {
  const queryClient = makeQueryClient()
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: [initialPath] }),
  })
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await waitFor(() => expect(router.state.status).toBe('idle'))
  return router
}

function requests(method: string, suffix: string) {
  return fetchMock.mock.calls.filter(([input, init]) => {
    const raw = typeof input === 'string' ? input : input.toString()
    return (
      (init?.method ?? 'GET').toUpperCase() === method &&
      new URL(raw, 'http://localhost').pathname.endsWith(suffix)
    )
  })
}

function bodyOf(call: unknown[]): unknown {
  const init = call[1] as RequestInit | undefined
  return init?.body ? JSON.parse(init.body as string) : undefined
}

function rule(n: number) {
  return within(screen.getByRole('group', { name: `Rule ${n}` }))
}

describe('retention screen', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('is linked from hosted and proxy repositories, not from a group', async () => {
    mockApi({
      repositories: [
        repo({}),
        repo({ id: 2, name: 'nuget-all', kind: 'group' }),
      ],
    })
    const router = await renderAt('/manage/repositories/nuget-internal')
    await userEvent.click(await screen.findByRole('link', { name: 'Retention' }))
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        '/manage/repositories/nuget-internal/retention',
      ),
    )
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Retention of nuget-internal' }),
    ).toBeInTheDocument()

    await router.navigate({
      to: '/manage/repositories/$repo',
      params: { repo: 'nuget-all' },
    })
    await screen.findByRole('heading', { level: 1, name: 'Edit nuget-all' })
    expect(screen.queryByRole('link', { name: 'Retention' })).not.toBeInTheDocument()

    await router.navigate({
      to: '/manage/repositories/$repo/retention',
      params: { repo: 'nuget-all' },
    })
    expect(
      await screen.findByText(/set retention on its members/),
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save policy' })).not.toBeInTheDocument()
  })

  it('previews the draft and stores a dry-run policy without asking', async () => {
    let previewed: unknown
    let stored: unknown
    mockApi({
      repositories: [repo({})],
      onPreview: (body) => {
        previewed = body
        return json(preview({}))
      },
      onPut: (body) => {
        stored = body
        return json({})
      },
    })
    await renderAt('/manage/repositories/nuget-internal/retention')
    expect(await screen.findByText(/This repository has no policy/)).toBeInTheDocument()
    expect(screen.getByText('No policy is stored, so nothing runs.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run now' })).toBeDisabled()
    // The example is a dry run.
    expect(screen.getByRole('switch', { name: 'Dry run only' })).toBeChecked()
    expect(rule(1).getByLabelText(/^Rule id/)).toHaveValue('keep-recent')

    await userEvent.clear(rule(1).getByLabelText(/^Newest versions/))
    await userEvent.type(rule(1).getByLabelText(/^Newest versions/), '3')
    await userEvent.click(screen.getByRole('button', { name: 'Preview' }))

    expect(
      await screen.findByText('Of 12 versions, 1 would be deleted and 1 unlisted.'),
    ).toBeInTheDocument()
    const table = within(screen.getByRole('table', { name: /Versions the policy would remove/ }))
    expect(table.getAllByRole('row')).toHaveLength(3)
    expect(table.getByText('not downloaded for 90 days')).toBeInTheDocument()
    expect(table.getByText('older than 30 days')).toBeInTheDocument()
    expect(previewed).toEqual({
      policy: {
        version: 1,
        enabled: true,
        dry_run_only: true,
        min_run_interval_seconds: 3600,
        rules: [
          {
            id: 'keep-recent',
            action: 'hard_delete',
            scope: 'hosted',
            release_type: 'any',
            criteria: { keep_last_n: 3, not_downloaded_for_days: 90 },
          },
        ],
      },
    })

    // Editing the form makes the preview stale.
    await userEvent.type(rule(1).getByLabelText(/^Package id prefix/), 'acme.')
    expect(screen.getByText(/The form changed since this preview/)).toBeInTheDocument()

    // A dry run removes nothing: stored without a confirmation.
    await userEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    await waitFor(() => expect(stored).toBeDefined())
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(stored).toMatchObject({
      policy: {
        dry_run_only: true,
        rules: [{ package_name_prefix: 'acme.' }],
      },
    })
    // The screen now shows the stored policy and its ledger.
    expect(await screen.findByRole('button', { name: 'Remove policy' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run now' })).toBeEnabled()
  })

  it('asks before saving a policy that deletes, with the preview counts', async () => {
    mockApi({ repositories: [repo({})] })
    await renderAt('/manage/repositories/nuget-internal/retention')
    await userEvent.click(await screen.findByRole('switch', { name: 'Dry run only' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save policy' }))

    const dialog = within(await screen.findByRole('dialog'))
    expect(dialog.getByText(/Of 12 versions, 1 would be deleted and 1 unlisted/)).toBeInTheDocument()
    expect(requests('POST', '/retention/preview')).toHaveLength(1)
    await userEvent.click(dialog.getByRole('button', { name: 'Cancel' }))
    expect(requests('PUT', '/retention')).toHaveLength(0)

    // The preview of the unchanged form is reused for the confirmation.
    await userEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: 'Save policy' }),
    )
    await waitFor(() => expect(requests('PUT', '/retention')).toHaveLength(1))
    expect(requests('POST', '/retention/preview')).toHaveLength(1)
    expect(bodyOf(requests('PUT', '/retention')[0])).toMatchObject({
      policy: { dry_run_only: false },
    })
  })

  it('shows the fields the browser refuses, and the reason the server refuses a policy', async () => {
    mockApi({
      repositories: [repo({})],
      onPut: () =>
        new Response(
          'invalid retention policy: rule "keep-recent" has no trigger criterion (older_than_days / not_downloaded_for_days / not_pulled_for_days)',
          { status: 400 },
        ),
    })
    await renderAt('/manage/repositories/nuget-internal/retention')
    await userEvent.clear(await screen.findByRole('textbox', { name: /^Rule id/ }))
    await userEvent.type(rule(1).getByLabelText(/^Newest versions/), 'x')
    await userEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    expect(rule(1).getByText('Enter a rule id.')).toBeInTheDocument()
    expect(
      rule(1).getByText('Enter a whole number of at least 1, or leave it empty.'),
    ).toBeInTheDocument()
    expect(requests('PUT', '/retention')).toHaveLength(0)

    await userEvent.type(rule(1).getByLabelText(/^Rule id/), 'keep-recent')
    await userEvent.clear(rule(1).getByLabelText(/^Newest versions/))
    await userEvent.clear(rule(1).getByLabelText(/^Not downloaded for/))
    await userEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    expect(await screen.findByText('The policy was refused')).toBeInTheDocument()
    expect(screen.getByText(/has no trigger criterion/)).toBeInTheDocument()
  })

  it('edits a stored policy, removes it after asking, and shows its runs', async () => {
    mockApi({
      repositories: [repo({})],
      view: { policy: storedPolicy, last_run: ledger },
    })
    await renderAt('/manage/repositories/nuget-internal/retention')
    expect(await screen.findByRole('switch', { name: 'Dry run only' })).not.toBeChecked()
    expect(screen.getByLabelText('Minimum time between runs')).toHaveValue('1')
    expect(screen.getByLabelText('Unit')).toHaveValue('days')
    expect(rule(1).getByLabelText(/^Rule id/)).toHaveValue('stale-releases')
    expect(rule(1).getByLabelText(/^Versions/)).toHaveValue('releases')
    expect(rule(1).getByLabelText(/^Package id prefix/)).toHaveValue('acme.')
    expect(rule(1).getByLabelText(/^Published more than/)).toHaveValue('180')

    const runs = within(screen.getByRole('complementary', { name: 'Runs' }))
    expect(runs.getByText('3 deleted, 0 unlisted, 1 skipped, of 120')).toBeInTheDocument()

    // A second rule, moved first.
    await userEvent.click(screen.getByRole('button', { name: 'Add rule' }))
    expect(rule(2).getByLabelText(/^Rule id/)).toHaveValue('rule-2')
    await userEvent.click(screen.getByRole('button', { name: 'Move rule 2 up' }))
    expect(rule(1).getByLabelText(/^Rule id/)).toHaveValue('rule-2')
    await userEvent.click(screen.getByRole('button', { name: 'Remove rule 1' }))
    expect(screen.queryByRole('group', { name: 'Rule 2' })).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Remove policy' }))
    const dialog = within(await screen.findByRole('dialog'))
    expect(dialog.getByText(/audit log is kept/)).toBeInTheDocument()
    await userEvent.click(dialog.getByRole('button', { name: 'Remove policy' }))
    await waitFor(() => expect(requests('DELETE', '/retention')).toHaveLength(1))
    // The form starts again from the example.
    expect(await screen.findByText(/This repository has no policy/)).toBeInTheDocument()
    expect(runs.getByRole('button', { name: 'Run now' })).toBeDisabled()
  })

  it('runs now, and filters and pages the audit log', async () => {
    const older = Array.from({ length: 50 }, (_, i) =>
      auditRow({ id: 200 - i, version: `2.${i}.0` }),
    )
    mockApi({
      repositories: [repo({})],
      view: { policy: storedPolicy, last_run: ledger },
      audit: (q) => {
        if (q.get('run_id')) return [auditRow({ id: 7, run_id: q.get('run_id')! })]
        if (q.get('before') === '151') {
          return [auditRow({ id: 150, action: 'skipped', dry_run: true })]
        }
        return older
      },
    })
    await renderAt('/manage/repositories/nuget-internal/retention')
    const runs = within(await screen.findByRole('complementary', { name: 'Runs' }))
    await userEvent.click(runs.getByRole('button', { name: 'Run now' }))
    expect(await runs.findByText(/Run requested/)).toBeInTheDocument()
    expect(requests('POST', '/retention/run')).toHaveLength(1)
    expect(runs.getByRole('button', { name: 'Run now' })).toBeDisabled()

    const log = within(screen.getByRole('region', { name: 'Audit log' }))
    expect(await log.findByText('acme.core 2.0.0')).toBeInTheDocument()
    await userEvent.click(log.getByRole('button', { name: 'Older' }))
    expect(await log.findByText('skipped')).toBeInTheDocument()
    expect(log.getByText('dry run')).toBeInTheDocument()
    expect(log.getByRole('button', { name: 'Older' })).toBeDisabled()
    await userEvent.click(log.getByRole('button', { name: 'Newer' }))
    expect(await log.findByText('acme.core 2.0.0')).toBeInTheDocument()

    await userEvent.click(
      log.getAllByRole('button', {
        name: 'Show only run 11111111-2222-3333-4444-555555555555',
      })[0],
    )
    expect(await log.findByRole('button', { name: 'Show every run' })).toBeInTheDocument()
    await waitFor(() =>
      expect(
        requests('GET', '/retention/audit').some(([input]) =>
          String(input).includes('run_id=11111111-2222-3333-4444-555555555555'),
        ),
      ).toBe(true),
    )
  })

  it('edits image rules on a docker repository', async () => {
    mockApi({
      repositories: [repo({ name: 'docker-hosted', format: 'docker' })],
      onPreview: () =>
        json({
          decisions: [],
          proxy_decisions: [],
          image_decisions: {
            tags: [
              {
                image: 'team/api',
                tag: 'pr-17',
                manifest_id: 3,
                digest: 'sha256:0123456789abcdef0123456789abcdef',
                rule_id: 'cleanup',
                reason: { keep_last_n_tags: 10, tag_not_pulled_for_days: 90 },
              },
            ],
            manifests: [
              {
                image: 'team/api',
                manifest_id: 4,
                digest: 'sha256:fedcba9876543210fedcba9876543210',
                rule_id: 'cleanup',
                reason: { delete_untagged_after_days: 7 },
              },
            ],
          },
          counts: { evaluated: 40, unlisted: 0, deleted: 2 },
        }),
    })
    await renderAt('/manage/repositories/docker-hosted/retention')
    const tags = await screen.findByRole('textbox', { name: /^Protected tags/ })
    expect(tags).toHaveValue('latest')
    await userEvent.type(tags, ', stable  main')
    await userEvent.click(screen.getByRole('button', { name: 'Preview' }))

    expect(
      await screen.findByText('Of 40 tags and manifests, 1 tag and 1 manifest would be deleted.'),
    ).toBeInTheDocument()
    expect(screen.getByText('not among the 10 newest tags, not pulled for 90 days')).toBeInTheDocument()
    expect(screen.getByText('untagged for 7 days')).toBeInTheDocument()
    expect(screen.getByText('fedcba987654')).toBeInTheDocument()
    expect(bodyOf(requests('POST', '/retention/preview')[0])).toEqual({
      policy: {
        version: 1,
        enabled: true,
        dry_run_only: true,
        min_run_interval_seconds: 3600,
        rules: [
          {
            id: 'cleanup',
            keep_last_n_tags: 10,
            protected_tags: ['latest', 'stable', 'main'],
            tag_not_pulled_for_days: 90,
            delete_untagged_after_days: 7,
          },
        ],
      },
    })
  })

  it('edits eviction rules on a proxy', async () => {
    let stored: unknown
    mockApi({
      repositories: [repo({ name: 'nuget-proxy', kind: 'proxy' })],
      onPut: (body) => {
        stored = body
        return json({})
      },
    })
    await renderAt('/manage/repositories/nuget-proxy/retention')
    expect(await screen.findByText(/An evicted version stays listed/)).toBeInTheDocument()
    expect(rule(1).queryByLabelText(/^Action/)).not.toBeInTheDocument()
    expect(rule(1).queryByLabelText(/^Newest versions/)).not.toBeInTheDocument()
    await userEvent.clear(rule(1).getByLabelText(/^Not pulled for/))
    await userEvent.type(rule(1).getByLabelText(/^Not pulled for/), '30')
    await userEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    await waitFor(() =>
      expect(stored).toEqual({
        policy: {
          version: 1,
          enabled: true,
          dry_run_only: true,
          min_run_interval_seconds: 3600,
          rules: [
            {
              id: 'evict-cold',
              action: 'hard_delete',
              scope: 'proxy_cached',
              release_type: 'any',
              criteria: { not_pulled_for_days: 30 },
            },
          ],
        },
      }),
    )
  })
})
