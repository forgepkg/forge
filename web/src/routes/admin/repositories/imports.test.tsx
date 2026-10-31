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
import type { ImportItem, ImportView } from '~/api/imports'
import { routeTree } from '~/routeTree.gen'
import { searchOptions } from '~/lib/search'

/**
 * The import screen (`/manage/repositories/$repo/import`), driven against
 * the real route tree and query hooks:
 *  - a hosted repository's edit screen links to it, a proxy's does not;
 *  - the form posts the import (a dry run by default) from a feed's URL, with
 *    the package ids it names, and shows the server's preflight refusal;
 *  - an import shows its progress, its conflicts on demand, and a completed
 *    import's failed items are retried with the password it no longer holds;
 *    the form starts from the last import;
 *  - an npm hosted repository offers the import of a registry, with named
 *    packages and scopes, and shows its dist-tag conflicts.
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

function imp(over: Partial<ImportView>): ImportView {
  return {
    id: 7,
    repository: 'nuget-internal',
    url: 'https://nexus.example.com/repository/nuget-hosted/index.json',
    names: null,
    username: 'migrator',
    has_password: false,
    on_conflict: 'skip',
    concurrency: 4,
    dry_run: false,
    state: 'completed',
    phase: 'copy',
    cancel_requested: false,
    source_server: 'Nexus/3.70.1-02 (OSS)',
    source_total: 10,
    listing: 'search',
    last_error: null,
    created_by: 1,
    created_at: '2026-10-22T10:00:00Z',
    started_at: '2026-10-22T10:00:01Z',
    finished_at: '2026-10-22T10:05:00Z',
    updated_at: '2026-10-22T10:05:00Z',
    progress: {
      found: 10,
      pending: 0,
      imported: 7,
      replaced: 0,
      identical: 0,
      conflict: 2,
      failed: 1,
      planned: 0,
      planned_size: 0,
      bytes_copied: 4096,
    },
    ...over,
  }
}

function item(over: Partial<ImportItem>): ImportItem {
  return {
    id: 1,
    kind: 'component',
    name: 'Acme.Core',
    version: '1.0.0',
    state: 'conflict',
    detail: 'Forge has other bytes for this version',
    size: 1024,
    bytes_copied: 0,
    published_at: null,
    downloaded_at: null,
    uploader: null,
    attempts: 1,
    updated_at: '2026-10-22T10:05:00Z',
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
  imports?: ImportView[]
  items?: ImportItem[]
  onCreate?: (body: unknown) => Response
  onResume?: (id: string, body: unknown) => Response
}

function mockApi(h: Handlers) {
  fetchMock.mockImplementation(
    (input: RequestInfo | URL, init?: RequestInit) => {
      const raw = typeof input === 'string' ? input : input.toString()
      const url = new URL(raw, 'http://localhost')
      const method = (init?.method ?? 'GET').toUpperCase()
      const path = url.pathname
      const body = init?.body ? JSON.parse(init.body as string) : {}

      if (path.endsWith('/admin/me')) return Promise.resolve(json(adminMe))
      if (path.endsWith('/items')) {
        const state = url.searchParams.get('state')
        return Promise.resolve(
          json((h.items ?? []).filter((i) => !state || i.state === state)),
        )
      }
      const resume = path.match(/\/imports\/(\d+)\/resume$/)
      if (resume && method === 'POST') {
        return Promise.resolve(
          h.onResume ? h.onResume(resume[1], body) : json(imp({})),
        )
      }
      if (path.endsWith('/imports') && method === 'GET') {
        return Promise.resolve(json(h.imports ?? []))
      }
      if (path.endsWith('/imports') && method === 'POST') {
        return Promise.resolve(
          h.onCreate ? h.onCreate(body) : json(imp({ state: 'queued' }), 201),
        )
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
    ...searchOptions,
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

describe('import', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('is linked from a hosted repository, not from a proxy', async () => {
    mockApi({
      repositories: [
        repo({}),
        repo({ id: 2, name: 'nuget-proxy', kind: 'proxy' }),
      ],
    })
    const router = await renderAt('/manage/repositories/nuget-internal')
    const link = await screen.findByRole('link', { name: 'Import' })
    await userEvent.click(link)
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        '/manage/repositories/nuget-internal/import',
      ),
    )

    await router.navigate({
      to: '/manage/repositories/$repo',
      params: { repo: 'nuget-proxy' },
    })
    await screen.findByText(/Edit/)
    expect(
      screen.queryByRole('link', { name: 'Import' }),
    ).not.toBeInTheDocument()
  })

  it('starts a dry run and shows a preflight refusal', async () => {
    let created: unknown
    mockApi({
      repositories: [repo({})],
      onCreate: (body) => {
        created = body
        return new Response(
          'the NuGet feed at https://feed.example.com/v3/index.json: the source answered 404',
          { status: 400 },
        )
      },
    })
    await renderAt('/manage/repositories/nuget-internal/import')
    await screen.findByText('No imports yet')

    await userEvent.type(
      screen.getByLabelText('Feed URL'),
      'https://feed.example.com/v3/index.json',
    )
    await userEvent.type(
      screen.getByLabelText(/Package IDs/),
      'Acme.Core\nAcme.Web, Acme.Cli',
    )
    await userEvent.click(screen.getByRole('button', { name: 'Start dry run' }))

    expect(await screen.findByText(/answered 404/)).toBeInTheDocument()
    expect(created).toEqual({
      url: 'https://feed.example.com/v3/index.json',
      names: ['Acme.Core', 'Acme.Web', 'Acme.Cli'],
      on_conflict: 'skip',
      concurrency: 4,
      dry_run: true,
    })
  })

  it('shows progress and conflicts, and retries failed items with the password again', async () => {
    let resumed: unknown
    mockApi({
      repositories: [repo({})],
      imports: [imp({})],
      items: [item({}), item({ id: 2, name: 'Acme.Web' })],
      onResume: (_, body) => {
        resumed = body
        return json(imp({ state: 'queued' }))
      },
    })
    await renderAt('/manage/repositories/nuget-internal/import')
    const card = await screen.findByRole('article', { name: 'Import 7' })
    // The form starts from the last import, for the run before a cutover.
    expect(screen.getByLabelText('Feed URL')).toHaveValue(
      'https://nexus.example.com/repository/nuget-hosted/index.json',
    )
    expect(screen.getByRole('button', { name: 'Start import' })).toBeEnabled()
    expect(within(card).getByText('10 of 10 done.', { exact: false })).toBeInTheDocument()
    expect(
      within(card).getByText(/search found 10 packages/, { exact: false }),
    ).toBeInTheDocument()
    expect(within(card).getByRole('progressbar')).toHaveAttribute(
      'aria-valuenow',
      '10',
    )

    await userEvent.click(within(card).getByRole('button', { name: 'Show conflict' }))
    expect(await within(card).findByText('Acme.Web 1.0.0')).toBeInTheDocument()
    expect(within(card).getAllByText('Forge has other bytes for this version')).toHaveLength(2)

    // The completed import's password was deleted: retrying needs it again.
    const retry = within(card).getByRole('button', { name: 'Retry failed items' })
    expect(retry).toBeDisabled()
    await userEvent.type(within(card).getByLabelText('Password'), 's3cret')
    await userEvent.click(retry)
    await waitFor(() => expect(resumed).toEqual({ retry_failed: true, password: 's3cret' }))
    expect(requests('POST', '/imports/7/resume')).toHaveLength(1)
  })

  it('offers the import on an npm hosted repository, with packages and scopes', async () => {
    let created: unknown
    mockApi({
      repositories: [repo({ name: 'npm-internal', format: 'npm' })],
      imports: [
        imp({
          repository: 'npm-internal',
          url: 'https://nexus.example.com/repository/npm-hosted',
          username: null,
          listing: 'all',
          source_total: 3,
          progress: {
            found: 5,
            pending: 0,
            imported: 4,
            replaced: 0,
            identical: 0,
            conflict: 1,
            failed: 0,
            planned: 0,
            planned_size: 0,
            bytes_copied: 2048,
          },
        }),
      ],
      items: [
        item({
          kind: 'tag',
          name: '@acme/ui',
          version: 'latest',
          detail: 'Forge points it at 1.0.0; the source at 1.1.0',
        }),
      ],
      onCreate: (body) => {
        created = body
        return json(imp({ state: 'queued' }), 201)
      },
    })
    const router = await renderAt('/manage/repositories/npm-internal')
    await userEvent.click(await screen.findByRole('link', { name: 'Import' }))
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        '/manage/repositories/npm-internal/import',
      ),
    )
    const card = await screen.findByRole('article', { name: 'Import 7' })
    expect(
      within(card).getByText(/\/-\/all lists 3 packages/, { exact: false }),
    ).toBeInTheDocument()
    await userEvent.click(within(card).getByRole('button', { name: 'Show conflict' }))
    expect(
      await within(card).findByText('@acme/ui dist-tag latest'),
    ).toBeInTheDocument()
    expect(
      within(card).getByText('Forge points it at 1.0.0; the source at 1.1.0'),
    ).toBeInTheDocument()

    const url = screen.getByLabelText('Registry URL')
    expect(url).toHaveValue('https://nexus.example.com/repository/npm-hosted')
    await userEvent.type(
      screen.getByLabelText(/Packages or scopes/),
      '@acme\nleft-pad',
    )
    await userEvent.click(screen.getByRole('button', { name: 'Start import' }))
    await waitFor(() =>
      expect(created).toEqual({
        url: 'https://nexus.example.com/repository/npm-hosted',
        names: ['@acme', 'left-pad'],
        on_conflict: 'skip',
        concurrency: 4,
        dry_run: false,
      }),
    )
  })

  it('imports the named images of a registry without a catalog', async () => {
    let created: unknown
    mockApi({
      repositories: [repo({ name: 'images', format: 'docker' })],
      imports: [
        imp({
          repository: 'images',
          url: 'https://registry.example.com',
          names: ['team/app'],
          source_total: null,
          progress: {
            found: 1,
            pending: 0,
            imported: 0,
            replaced: 0,
            identical: 0,
            conflict: 0,
            failed: 1,
            planned: 0,
            planned_size: 0,
            bytes_copied: 0,
          },
        }),
      ],
      items: [
        item({
          name: 'team/gone',
          version: '',
          state: 'failed',
          detail: 'the source has no tag of this image',
        }),
      ],
      onCreate: (body) => {
        created = body
        return json(imp({ state: 'queued' }), 201)
      },
    })
    await renderAt('/manage/repositories/images/import')
    const card = await screen.findByRole('article', { name: 'Import 7' })
    expect(within(card).getByText('1 named')).toBeInTheDocument()
    await userEvent.click(within(card).getByRole('button', { name: 'Show failed' }))
    expect(await within(card).findByText('team/gone')).toBeInTheDocument()

    expect(screen.getByLabelText('Registry URL')).toHaveValue(
      'https://registry.example.com',
    )
    expect(screen.getByLabelText(/Images/)).toHaveValue('team/app')
    // The password is never prefilled.
    const form = screen.getByRole('button', { name: 'Start import' }).closest('form')!
    await userEvent.type(within(form).getByLabelText('Password'), 's3cret')
    await userEvent.click(screen.getByRole('button', { name: 'Start import' }))
    await waitFor(() =>
      expect(created).toEqual({
        url: 'https://registry.example.com',
        names: ['team/app'],
        username: 'migrator',
        password: 's3cret',
        on_conflict: 'skip',
        concurrency: 4,
        dry_run: false,
      }),
    )
  })
})
