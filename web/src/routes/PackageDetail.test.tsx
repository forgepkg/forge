import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import userEvent from '@testing-library/user-event'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { clearSession } from '~/lib/auth'
import { makeQueryClient } from '~/lib/queryClient'
import type { Me } from '~/api/me'
import { pkgKeys, type PackageDetail } from '~/api/packages'
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

const fetchMock = vi.fn()
const adminMe: Me = {
  ...anonMe,
  user: { ...anonMe.user, id: 1, username: 'admin', is_admin: true },
  is_admin: true,
}
const hostedDetail: PackageDetail = {
  ...proxyDetail,
  repo: 'internal',
  repo_kind: 'hosted',
  versions: proxyDetail.versions.map((v) => ({ ...v, delay_status: null })),
}

function mockApi(
  detail: (repo: string, id: string) => Response,
  {
    me = anonMe,
    format = 'nuget',
    deleteVersion,
  }: {
    me?: Me
    format?: string
    deleteVersion?: () => Response | Promise<Response>
  } = {},
) {
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const url = new URL(raw, 'http://localhost')
    if (url.pathname.endsWith('/admin/me')) {
      return Promise.resolve(
        new Response(JSON.stringify(me), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      )
    }
    if (url.pathname.endsWith('/browse/repos')) {
      return Promise.resolve(jsonResponse([
        { id: 1, name: 'internal', kind: 'hosted', online: true, format },
      ]))
    }
    if (init?.method === 'DELETE' && deleteVersion) {
      return Promise.resolve(deleteVersion())
    }
    if (url.pathname.endsWith('/browse/packages')) {
      return Promise.resolve(jsonResponse({ total: 0, items: [] }))
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

  it.each(['nuget', 'helm'])('confirms and deletes a hosted %s version, refreshing package queries', async (format) => {
    const user = userEvent.setup()
    const version = { ...hostedDetail.versions[0], version_original: '13.0.3+build.1' }
    let current = { ...hostedDetail, versions: [version, hostedDetail.versions[1]] }
    const deleteVersion = vi.fn(() => {
      current = { ...current, versions: [hostedDetail.versions[1]], dependency_groups_by_version: {} }
      return new Response(null, { status: 204 })
    })
    mockApi(() => jsonResponse(current), { me: adminMe, format, deleteVersion })
    const client = testQueryClient()
    const repoListKey = pkgKeys.search({ repo: 'internal' })
    const searchKey = pkgKeys.search({ q: 'newtonsoft' })
    client.setQueryData(repoListKey, { total: 1, items: [] })
    client.setQueryData(searchKey, { total: 1, items: [] })
    const router = await renderDetail('/packages/internal/newtonsoft.json', client)
    const table = await screen.findByRole('table', { name: 'Versions of Newtonsoft.Json' })
    expect(within(table).getAllByRole('button', { name: 'Delete' })).toHaveLength(2)
    await user.click(within(table).getAllByRole('button', { name: 'Delete' })[0])
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('internal')
    expect(dialog).toHaveTextContent('Newtonsoft.Json')
    expect(dialog).toHaveTextContent('13.0.3+build.1')
    expect(dialog).toHaveTextContent('This cannot be undone')
    expect(dialog).toHaveTextContent('Clients that already downloaded this version keep their copy')
    expect(deleteVersion).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(deleteVersion).not.toHaveBeenCalled()
    await user.click(within(table).getAllByRole('button', { name: 'Delete' })[0])
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete version' }))
    await waitFor(() => expect(within(table).queryByText('13.0.3+build.1')).not.toBeInTheDocument())
    expect(deleteVersion).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith(
      '/admin/repositories/internal/packages/newtonsoft.json/13.0.3%2Bbuild.1',
      expect.objectContaining({ method: 'DELETE', credentials: 'same-origin' }),
    )
    expect(client.getQueryState(repoListKey)?.isInvalidated).toBe(true)
    expect(client.getQueryState(searchKey)?.isInvalidated).toBe(true)
    expect(router.state.location.pathname).toBe('/packages/internal/newtonsoft.json')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByText('System.Text.Json')).not.toBeInTheDocument()
    if (format === 'nuget') {
      expect(screen.getByText('dotnet add package Newtonsoft.Json --version 14.0.0-beta')).toBeInTheDocument()
    }
  })

  it.each(['404', 'empty'])('returns to the repository after deleting the last version (%s)', async (result) => {
    const user = userEvent.setup()
    let deleted = false
    mockApi(
      () => deleted
        ? result === '404'
          ? new Response('package not found', { status: 404 })
          : jsonResponse({ ...hostedDetail, versions: [] })
        : jsonResponse({ ...hostedDetail, versions: [hostedDetail.versions[0]] }),
      {
        me: adminMe,
        deleteVersion: () => {
          deleted = true
          return new Response(null, { status: 204 })
        },
      },
    )
    const router = await renderDetail('/packages/internal/newtonsoft.json')
    await user.click(await screen.findByRole('button', { name: 'Delete' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete version' }))
    await waitFor(() => expect(router.state.location.pathname).toBe('/repos/internal'))
  })

  it('clears a pending deletion when browser navigation changes packages', async () => {
    const user = userEvent.setup()
    mockApi(
      (_repo, id) => {
        const version = id === 'other' ? '42.0.0' : '13.0.3'
        return jsonResponse({
          ...hostedDetail,
          id,
          original_id: id === 'other' ? 'Other.Package' : 'Newtonsoft.Json',
          versions: [{ ...hostedDetail.versions[0], version, version_original: version }],
        })
      },
      { me: adminMe, deleteVersion: () => new Response(null, { status: 204 }) },
    )
    const router = await renderDetail('/packages/internal/newtonsoft.json')
    await router.navigate({
      to: '/packages/$repo/$id',
      params: { repo: 'internal', id: 'other' },
    })
    await screen.findByRole('heading', { name: 'Other.Package' })
    await user.click(await screen.findByRole('button', { name: 'Delete' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('42.0.0')

    router.history.back()

    await screen.findByRole('heading', { name: 'Newtonsoft.Json' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: 'Delete' }))
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('13.0.3')
    expect(dialog).not.toHaveTextContent('42.0.0')
    await user.click(within(dialog).getByRole('button', { name: 'Delete version' }))
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        '/admin/repositories/internal/packages/newtonsoft.json/13.0.3',
        expect.objectContaining({ method: 'DELETE' }),
      ),
    )
  })

  it('keeps the version and reports a failed deletion, allowing a retry', async () => {
    const user = userEvent.setup()
    const deleteVersion = vi.fn()
      .mockReturnValueOnce(new Response('deletion failed', { status: 500 }))
      .mockReturnValue(new Response(null, { status: 204 }))
    mockApi(() => jsonResponse(hostedDetail), { me: adminMe, deleteVersion })
    await renderDetail('/packages/internal/newtonsoft.json')
    await user.click((await screen.findAllByRole('button', { name: 'Delete' }))[0])
    const dialog = screen.getByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Delete version' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('deletion failed')
    expect(within(screen.getByRole('table', { name: 'Versions of Newtonsoft.Json' })).getByText('13.0.3')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Delete version' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(deleteVersion).toHaveBeenCalledTimes(2)
  })

  it('disables duplicate deletion while a request is pending', async () => {
    const user = userEvent.setup()
    let finish!: (response: Response) => void
    const deleteVersion = vi.fn(() => new Promise<Response>((resolve) => { finish = resolve }))
    mockApi(() => jsonResponse(hostedDetail), { me: adminMe, deleteVersion })
    await renderDetail('/packages/internal/newtonsoft.json')
    await user.click((await screen.findAllByRole('button', { name: 'Delete' }))[0])
    const dialog = screen.getByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Delete version' }))
    expect(within(dialog).getByRole('button', { name: 'Deleting…' })).toBeDisabled()
    for (const button of screen.getAllByRole('button', { name: 'Delete' })) {
      expect(button).toBeDisabled()
    }
    await user.keyboard('{Escape}')
    expect(dialog).toBeInTheDocument()
    expect(deleteVersion).toHaveBeenCalledTimes(1)
    finish(new Response(null, { status: 204 }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it.each([
    { me: anonMe, kind: 'hosted', format: 'nuget' },
    { me: adminMe, kind: 'proxy', format: 'nuget' },
    { me: adminMe, kind: 'group', format: 'nuget' },
    { me: adminMe, kind: 'hosted', format: 'docker' },
  ])('hides deletion for is_admin=$me.is_admin, $kind, $format', async ({ me, kind, format }) => {
    mockApi(() => jsonResponse({ ...hostedDetail, repo_kind: kind }), { me, format })
    await renderDetail('/packages/internal/newtonsoft.json')
    await screen.findByRole('table', { name: 'Versions of Newtonsoft.Json' })
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: 'Actions' })).not.toBeInTheDocument()
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
})
