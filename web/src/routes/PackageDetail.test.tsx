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
import { textContent } from '~/test/text'
import { searchOptions } from '~/lib/search'

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

/** A scoped npm package of a hosted repository. */
const npmDetail: PackageDetail = {
  repo: 'npm-hosted',
  repo_kind: 'hosted',
  id: '@acme/ui',
  original_id: '@acme/ui',
  versions: ['1.0.0', '1.1.0', '2.0.0-rc.1'].map((version) => ({
    version,
    version_original: version,
    listed: true,
    size: 2048,
    published_at: '2026-06-01T00:00:00Z',
    delay_status: null,
    delayed_until: null,
    retention_status: null,
  })),
  dependency_groups_by_version: {
    '1.1.0': [
      { target_framework: 'dependencies', dependencies: [{ id: '@acme/core', range: '^2.0.0' }] },
      { target_framework: 'peerDependencies', dependencies: [{ id: 'react', range: '>=18' }] },
    ],
  },
  tags: { latest: '1.1.0', next: '2.0.0-rc.1' },
  deprecated: { '1.0.0': 'use 1.1.0' },
  readme: '# @acme/ui\n\nButtons.',
  description: 'Acme UI components',
}

const fetchMock = vi.fn()

function mockApi(
  detail: (repo: string, id: string) => Response,
  repos: { name: string; format: string }[] = [],
) {
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
    if (url.pathname.endsWith('/browse/repos')) {
      return Promise.resolve(
        jsonResponse(
          repos.map((r, i) => ({ id: i + 1, kind: 'hosted', online: true, ...r })),
        ),
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
    ...searchOptions,
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
    const versionsTable = screen.getByRole('table', { name: 'Versions of Newtonsoft.Json' })
    expect(within(versionsTable).getByText('13.0.3')).toBeInTheDocument()
    expect(within(versionsTable).getByText(textContent('14.0.0-beta'))).toBeInTheDocument()
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
    const table = screen.getByRole('table', { name: 'Versions of Newtonsoft.Json' })
    const betaRow = within(table).getByText(textContent('14.0.0-beta')).closest('tr')
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

  it('shows an npm package\'s dist-tags, deprecations, README and install commands', async () => {
    mockApi(() => jsonResponse(npmDetail), [{ name: 'npm-hosted', format: 'npm' }])

    await renderDetail('/packages/npm-hosted/%40acme%2Fui')

    await screen.findByRole('heading', { name: '@acme/ui' })
    const detailCalls = fetchMock.mock.calls.map(([input]) => String(input))
    expect(detailCalls.some((u) => u.endsWith('/browse/packages/npm-hosted/%40acme%2Fui'))).toBe(
      true,
    )
    const table = screen.getByRole('table', { name: 'Versions of @acme/ui' })
    const row = (v: string) => within(table).getByText(textContent(v)).closest('tr') as HTMLElement
    expect(within(row('1.1.0')).getByText('latest')).toBeInTheDocument()
    expect(within(row('2.0.0-rc.1')).getByText('next')).toBeInTheDocument()
    expect(within(row('1.0.0')).getByText('deprecated')).toHaveAttribute('title', 'use 1.1.0')

    // The README, as text.
    expect(screen.getByLabelText('README of @acme/ui')).toHaveTextContent('# @acme/ui Buttons.')
    // Dependency kinds stand where target frameworks do; names stay exact.
    expect(screen.getByRole('columnheader', { name: 'Kind' })).toBeInTheDocument()
    expect(screen.getByText('peerDependencies')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '@acme/core' })).toHaveAttribute(
      'href',
      '/packages/npm-hosted/%40acme%2Fcore',
    )
    // Install commands start at `latest`, not the newest prerelease.
    expect(await screen.findByText(textContent('npm install @acme/ui@1.1.0'))).toBeInTheDocument()
    expect(screen.getByText(textContent('pnpm add @acme/ui@1.1.0'))).toBeInTheDocument()
    // The dist-tags, and the latest version's description.
    expect(screen.getByRole('heading', { name: 'Dist-tags' })).toBeInTheDocument()
    expect(screen.getByText('Acme UI components')).toBeInTheDocument()
  })
})
