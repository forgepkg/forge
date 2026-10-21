import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { clearSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { BrowseRepo, BrowseResult } from '~/api/packages'
import { routeTree } from '~/routeTree.gen'

/**
 * Folder-view browse: the root lists the readable repositories (an offline
 * one badged); a repository screen searches + paginates that repo's packages
 * and says when the repository is offline. Drives the real route tree +
 * `useBrowseRepos` / `usePackageSearch`, so URL-search-param wiring is
 * exercised too.
 */

const readerMe: Me = {
  user: { id: 2, username: 'alice', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

const repos: BrowseRepo[] = [
  { name: 'nuget', kind: 'proxy', online: true },
  { name: 'internal', kind: 'hosted', online: true },
  { name: 'releases', kind: 'hosted', online: false },
]

function page(total: number, ids: string[]): BrowseResult {
  return {
    total,
    items: ids.map((id) => ({
      repo: 'nuget',
      repo_kind: 'hosted',
      id: id.toLowerCase(),
      original_id: id,
      latest_version: '1.0.0',
      listed: true,
    })),
  }
}

const fetchMock = vi.fn()

/**
 * Route the mock by URL: `/admin/me` -> identity, `/browse/repos` -> repo list,
 * `/browse/packages` -> handler.
 */
function mockApi(browse: (url: URL) => Response) {
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const url = new URL(raw, 'http://localhost')
    if (url.pathname.endsWith('/admin/me')) {
      return Promise.resolve(jsonResponse(readerMe))
    }
    if (url.pathname.endsWith('/browse/repos')) {
      return Promise.resolve(jsonResponse(repos))
    }
    if (url.pathname.endsWith('/browse/packages')) {
      return Promise.resolve(browse(url))
    }
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

/** Mount the app at `initialPath`, or with a history stack (last = current). */
async function renderBrowse(initialPath: string | string[] = '/') {
  const queryClient = testQueryClient()
  const entries = Array.isArray(initialPath) ? initialPath : [initialPath]
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({
      initialEntries: entries,
      initialIndex: entries.length - 1,
    }),
  })
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await waitFor(() => expect(router.state.status).toBe('idle'))
  return router
}

describe('Browse root (repository folders)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('lists the readable repositories as folder links', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/')

    const nugetLink = await screen.findByRole('link', { name: /nuget/ })
    expect(nugetLink).toHaveAttribute('href', '/repos/nuget')
    expect(screen.getByRole('link', { name: /internal/ })).toBeInTheDocument()
  })

  it('badges an offline repository', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/')

    const releases = await screen.findByRole('link', { name: /releases/ })
    expect(within(releases).getByText('offline')).toHaveAttribute(
      'title',
      'Offline for maintenance',
    )
    expect(
      within(screen.getByRole('link', { name: /internal/ })).queryByText('offline'),
    ).toBeNull()
  })

  it('navigates into a repository when its folder is clicked', async () => {
    mockApi(() => jsonResponse(page(1, ['Alpha'])))

    const user = userEvent.setup()
    const router = await renderBrowse('/')

    await user.click(await screen.findByRole('link', { name: /nuget/ }))

    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/repos/nuget'),
    )
    expect(await screen.findByRole('link', { name: /Alpha/ })).toBeInTheDocument()
  })
})

describe('RepoBrowse (per-repo search)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('scopes the search to the repository from the URL', async () => {
    mockApi(() => jsonResponse(page(2, ['Alpha', 'Beta'])))

    await renderBrowse('/repos/nuget')

    expect(await screen.findByRole('link', { name: /Alpha/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Beta/ })).toBeInTheDocument()
    expect(screen.getByText(/Page 1 of 1 · 2 total/)).toBeInTheDocument()

    // Every package request carried the repo filter.
    const pkgCalls = fetchMock.mock.calls
      .map(([input]) =>
        new URL(String(input), 'http://localhost'),
      )
      .filter((u) => u.pathname.endsWith('/browse/packages'))
    expect(pkgCalls.length).toBeGreaterThan(0)
    for (const u of pkgCalls) {
      expect(u.searchParams.get('repo')).toBe('nuget')
    }
  })

  it('paginates: Next requests the next page and updates skip', async () => {
    // 25 total over a page size of 20 => two pages.
    mockApi((url) => {
      const skip = Number(url.searchParams.get('skip') ?? '0')
      if (skip === 0) return jsonResponse(page(25, ['Alpha']))
      return jsonResponse(page(25, ['Omega']))
    })

    const user = userEvent.setup()
    const router = await renderBrowse('/repos/nuget')

    expect(await screen.findByRole('link', { name: /Alpha/ })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Next' }))

    expect(await screen.findByRole('link', { name: /Omega/ })).toBeInTheDocument()
    expect(router.state.location.search).toMatchObject({ skip: 20 })
  })

  it('shows an empty state when there are no results', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/repos/nuget')

    expect(await screen.findByText('No packages found')).toBeInTheDocument()
  })

  it('a page past the last result offers a way back instead of looking empty', async () => {
    // An old bookmark: 25 packages, but skip=40 is past the last page.
    mockApi((url) => {
      const skip = Number(url.searchParams.get('skip') ?? '0')
      return jsonResponse(skip === 0 ? page(25, ['Alpha']) : page(25, []))
    })

    const user = userEvent.setup()
    const router = await renderBrowse('/repos/nuget?q=a&skip=40')

    expect(await screen.findByText('No packages on this page')).toBeInTheDocument()
    expect(
      screen.queryByText('This repository does not contain any packages yet.'),
    ).toBeNull()

    await user.click(screen.getByRole('link', { name: 'Back to page 1' }))

    expect(await screen.findByRole('link', { name: /Alpha/ })).toBeInTheDocument()
    expect(router.state.location.search).toEqual({ q: 'a' })
  })

  it('shows an error state with a retry on failure', async () => {
    mockApi(() => new Response('boom', { status: 500 }))

    await renderBrowse('/repos/nuget')

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Could not load packages')).toBeInTheDocument()
    expect(within(alert).getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('says the repository is offline on its 503', async () => {
    mockApi(
      () =>
        new Response('repository is offline', {
          status: 503,
          headers: { 'retry-after': '60' },
        }),
    )

    await renderBrowse('/repos/releases')

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Repository offline')).toBeInTheDocument()
    expect(alert).toHaveTextContent(
      'This repository is offline for maintenance. Try again later.',
    )
    expect(within(alert).queryByText('Could not load packages')).toBeNull()
    expect(screen.queryByText('No packages found')).toBeNull()
  })

  it('debounces a typed query into the URL search param', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    const user = userEvent.setup()
    const router = await renderBrowse('/repos/nuget')

    await user.type(screen.getByLabelText('Search packages'), 'json')

    await waitFor(() =>
      expect(router.state.location.search).toMatchObject({ q: 'json' }),
    )
  })

  it('Back after typing a query leaves the search instead of getting stuck', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    const user = userEvent.setup()
    const router = await renderBrowse(['/', '/repos/nuget'])

    await user.type(await screen.findByLabelText('Search packages'), 'json')
    await waitFor(() =>
      expect(router.state.location.search).toMatchObject({ q: 'json' }),
    )

    // The debounced query replaced the entry, so one Back leaves the repo.
    router.history.back()
    await waitFor(() => expect(router.state.location.pathname).toBe('/'))
    await new Promise((r) => setTimeout(r, 500))
    expect(router.state.location.pathname).toBe('/')
  })

  it('Back to an earlier search shows that query and stays there', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    const router = await renderBrowse([
      '/repos/nuget?q=alpha',
      '/repos/nuget?q=beta',
    ])
    const box = await screen.findByLabelText('Search packages')
    expect(box).toHaveValue('beta')

    router.history.back()

    await waitFor(() => expect(box).toHaveValue('alpha'))
    // The input no longer drags the URL back to the newer query.
    await new Promise((r) => setTimeout(r, 500))
    expect(router.state.location.search).toMatchObject({ q: 'alpha' })
    expect(box).toHaveValue('alpha')
  })
})
