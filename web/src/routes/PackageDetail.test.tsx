import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { clearSession } from '~/lib/auth'
import { makeQueryClient } from '~/lib/queryClient'
import type { Me } from '~/api/me'
import type { PackageDetail } from '~/api/packages'
import { routeTree } from '~/routeTree.gen'

/**
 * Package-detail screen: renders versions + dependency groups; a delayed proxy
 * version shows the delay badge; a proxy labels the time column "Cached" (when
 * Forge downloaded it), a hosted repository "Published"; a 404 renders the
 * not-found empty state; an offline repository's 503 says so (without
 * retrying). Drives the real route tree + `usePackageDetail`.
 */

const anonMe: Me = {
  user: { id: 0, username: 'anonymous', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

const proxyDetail: PackageDetail = {
  repo: 'proxy',
  repo_kind: 'proxy',
  id: 'newtonsoft.json',
  original_id: 'Newtonsoft.Json',
  versions: [
    {
      version: '13.0.3',
      version_original: '13.0.3',
      listed: true,
      size: 700_416,
      published_at: '2024-01-01T00:00:00Z',
      delay_status: 'available',
      delayed_until: null,
      retention_status: null,
    },
    {
      version: '14.0.0-beta',
      version_original: '14.0.0-beta',
      listed: true,
      size: null,
      published_at: '2026-06-01T00:00:00Z',
      delay_status: 'delayed_until',
      delayed_until: '2999-01-01T00:00:00Z',
      retention_status: null,
    },
  ],
  dependency_groups_by_version: {
    '13.0.3': [
      {
        target_framework: 'net8.0',
        dependencies: [{ id: 'System.Text.Json', range: '[8.0.0, )' }],
      },
    ],
  },
}

const fetchMock = vi.fn()

function mockApi(detail: (repo: string, id: string) => Response) {
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const url = new URL(raw, 'http://localhost')
    if (url.pathname.endsWith('/admin/me')) {
      return Promise.resolve(
        new Response(JSON.stringify(anonMe), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      )
    }
    const m = url.pathname.match(/\/browse\/packages\/([^/]+)\/([^/]+)$/)
    if (m) return Promise.resolve(detail(m[1], m[2]))
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

/** Test query client with retries off so error/empty states resolve promptly. */
function testQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
}

async function renderDetail(path: string, queryClient = testQueryClient()) {
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: [path] }),
  })
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await waitFor(() => expect(router.state.status).toBe('idle'))
  return router
}

describe('PackageDetail', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('renders versions and dependency groups', async () => {
    mockApi(() => jsonResponse(proxyDetail))

    await renderDetail('/packages/proxy/newtonsoft.json')

    expect(
      await screen.findByRole('heading', { name: 'Newtonsoft.Json' }),
    ).toBeInTheDocument()
    // Both versions appear in the versions table.
    const versionsTable = screen.getByRole('table')
    expect(within(versionsTable).getByText('13.0.3')).toBeInTheDocument()
    expect(within(versionsTable).getByText('14.0.0-beta')).toBeInTheDocument()
    // The dependency links to the same-repo package.
    const dep = screen.getByRole('link', { name: 'System.Text.Json' })
    expect(dep).toBeInTheDocument()
    expect(screen.getByText('[8.0.0, )')).toBeInTheDocument()
    expect(screen.getByText('net8.0')).toBeInTheDocument()
  })

  it('shows a delay badge for a still-delayed proxy version', async () => {
    mockApi(() => jsonResponse(proxyDetail))

    await renderDetail('/packages/proxy/newtonsoft.json')

    await screen.findByRole('heading', { name: 'Newtonsoft.Json' })
    const table = screen.getByRole('table')
    const betaRow = within(table).getByText('14.0.0-beta').closest('tr')
    expect(betaRow).not.toBeNull()
    expect(within(betaRow as HTMLElement).getByText(/delayed/)).toBeInTheDocument()

    // The available version shows the available badge, not delayed.
    const stableRow = within(table).getByText('13.0.3').closest('tr') as HTMLElement
    expect(within(stableRow).getByText('available')).toBeInTheDocument()
  })

  it('labels the time column "Cached" on a proxy', async () => {
    mockApi(() => jsonResponse(proxyDetail))

    await renderDetail('/packages/proxy/newtonsoft.json')

    await screen.findByRole('heading', { name: 'Newtonsoft.Json' })
    const cached = screen.getByRole('columnheader', { name: 'Cached' })
    expect(cached).toHaveAttribute(
      'title',
      'When Forge first downloaded this version from the upstream',
    )
    expect(screen.queryByRole('columnheader', { name: 'Published' })).toBeNull()
  })

  it('labels the time column "Published" on a hosted repository', async () => {
    mockApi(() =>
      jsonResponse({
        ...proxyDetail,
        repo: 'internal',
        repo_kind: 'hosted',
        versions: proxyDetail.versions.map((v) => ({ ...v, delay_status: null })),
      }),
    )

    await renderDetail('/packages/internal/newtonsoft.json')

    await screen.findByRole('heading', { name: 'Newtonsoft.Json' })
    expect(
      screen.getByRole('columnheader', { name: 'Published' }),
    ).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: 'Cached' })).toBeNull()
  })

  it('renders a not-found empty state on 404', async () => {
    mockApi(() => new Response('package not found', { status: 404 }))

    await renderDetail('/packages/nuget/missing')

    expect(await screen.findByText('Package not found')).toBeInTheDocument()
  })

  it('says the repository is offline on its 503, without retrying', async () => {
    mockApi(
      () =>
        new Response('repository is offline', {
          status: 503,
          headers: { 'retry-after': '60' },
        }),
    )

    // The app's query client, so its retry policy applies.
    await renderDetail('/packages/internal/acme.core', makeQueryClient())

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Repository offline')).toBeInTheDocument()
    expect(alert).toHaveTextContent(
      'This repository is offline for maintenance. Try again later.',
    )
    expect(alert).not.toHaveTextContent('503')
    const detailCalls = fetchMock.mock.calls.filter(([input]) =>
      String(input).includes('/browse/packages/'),
    )
    expect(detailCalls).toHaveLength(1)
  })

  it('keeps the generic error for another 503', async () => {
    mockApi(() => new Response('temporarily unavailable', { status: 503 }))

    await renderDetail('/packages/internal/acme.core')

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Could not load package')).toBeInTheDocument()
    expect(alert).not.toHaveTextContent('offline')
  })

  it('renders an error state on a server error', async () => {
    mockApi(() => new Response('boom', { status: 500 }))

    await renderDetail('/packages/nuget/whatever')

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Could not load package')).toBeInTheDocument()
  })
})
