import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { clearToken } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { BrowseResult } from '~/api/packages'
import { routeTree } from '~/routeTree.gen'

/**
 * Browse screen (plan §Phase 3 testing): search renders results + paginates;
 * the empty and error states render; a new query resets paging. Drives the real
 * route tree + `usePackageSearch`, so URL-search-param wiring is exercised too.
 */

const anonMe: Me = {
  user: { id: 0, username: 'anonymous', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

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

/** Route the mock by URL: `/admin/me` -> identity, `/browse/packages` -> handler. */
function mockApi(browse: (url: URL) => Response) {
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

async function renderBrowse(initialPath = '/') {
  const queryClient = testQueryClient()
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

describe('Browse', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearToken()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearToken()
  })

  it('renders search results in the table', async () => {
    mockApi(() => jsonResponse(page(2, ['Alpha', 'Beta'])))

    await renderBrowse()

    expect(await screen.findByRole('link', { name: 'Alpha' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Beta' })).toBeInTheDocument()
    expect(screen.getByText(/Page 1 of 1 · 2 total/)).toBeInTheDocument()
  })

  it('paginates: Next requests the next page and updates skip', async () => {
    // 25 total over a page size of 20 => two pages.
    mockApi((url) => {
      const skip = Number(url.searchParams.get('skip') ?? '0')
      if (skip === 0) return jsonResponse(page(25, ['Alpha']))
      return jsonResponse(page(25, ['Omega']))
    })

    const user = userEvent.setup()
    const router = await renderBrowse()

    expect(await screen.findByRole('link', { name: 'Alpha' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Next' }))

    expect(await screen.findByRole('link', { name: 'Omega' })).toBeInTheDocument()
    expect(router.state.location.search).toMatchObject({ skip: 20 })
  })

  it('shows an empty state when there are no results', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse()

    expect(await screen.findByText('No packages found')).toBeInTheDocument()
  })

  it('shows an error state with a retry on failure', async () => {
    mockApi(() => new Response('boom', { status: 500 }))

    await renderBrowse()

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Could not load packages')).toBeInTheDocument()
    expect(within(alert).getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('debounces a typed query into the URL search param', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    const user = userEvent.setup()
    const router = await renderBrowse()

    await user.type(screen.getByLabelText('Search packages'), 'json')

    await waitFor(() =>
      expect(router.state.location.search).toMatchObject({ q: 'json' }),
    )
  })
})
