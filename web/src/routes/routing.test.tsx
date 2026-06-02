import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { makeQueryClient } from '~/lib/queryClient'
import { clearToken, setToken } from '~/lib/auth'
import type { Me } from '~/api/me'
import { routeTree } from '~/routeTree.gen'

/**
 * Router-integration tests against the **real** route tree (plan §2 testing):
 *   - the Admin nav link is hidden for a reader and shown for an admin;
 *   - the `_app/admin` guard redirects a non-admin to Browse and an
 *     unauthenticated visitor to /login;
 *   - an admin reaches the admin landing.
 *
 * These drive the genuine `beforeLoad` guard + `AppLayout` nav, so they catch
 * regressions a shallow component render would miss.
 */

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin', 'user.admin', 'token.admin'],
}

const readerMe: Me = {
  user: { id: 2, username: 'alice', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

const fetchMock = vi.fn()

/** Mock `GET /admin/me` to return the given identity, or 401 when null. */
function mockMe(me: Me | null) {
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.endsWith('/admin/me')) {
      if (me === null) {
        return Promise.resolve(new Response('unauthorized', { status: 401 }))
      }
      return Promise.resolve(
        new Response(JSON.stringify(me), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      )
    }
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

/** Mount the real app at `initialPath` and wait for the router to settle. */
async function renderApp(initialPath: string) {
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

describe('app routing + admin gating', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearToken()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearToken()
  })

  it('hides the Admin nav link for a reader', async () => {
    setToken('reader-token')
    mockMe(readerMe)

    await renderApp('/')

    const header = await screen.findByRole('banner')
    // Wait for the identity to resolve so the current-user widget has rendered:
    // the username plus a "reader" role badge and a Sign out button.
    expect(await within(header).findByText('alice')).toBeInTheDocument()
    expect(within(header).getByText('reader')).toBeInTheDocument()
    expect(
      within(header).getByRole('button', { name: 'Sign out' }),
    ).toBeInTheDocument()

    const nav = within(header).getByRole('navigation')
    expect(within(nav).getByRole('link', { name: 'Browse' })).toBeInTheDocument()
    expect(
      within(nav).queryByRole('link', { name: 'Admin' }),
    ).not.toBeInTheDocument()
  })

  it('shows the Admin nav link for an admin', async () => {
    setToken('admin-token')
    mockMe(adminMe)

    await renderApp('/')

    const nav = await screen.findByRole('navigation')
    await waitFor(() =>
      expect(within(nav).getByRole('link', { name: 'Admin' })).toBeInTheDocument(),
    )
  })

  it('redirects a non-admin away from /admin to Browse', async () => {
    setToken('reader-token')
    mockMe(readerMe)

    const router = await renderApp('/admin')

    expect(router.state.location.pathname).toBe('/')
    // Did not render the admin landing.
    expect(screen.queryByText('Administration')).not.toBeInTheDocument()
  })

  it('lets an admin reach the admin landing at /admin', async () => {
    setToken('admin-token')
    mockMe(adminMe)

    const router = await renderApp('/admin')

    expect(router.state.location.pathname).toBe('/admin')
    expect(await screen.findByText('Administration')).toBeInTheDocument()
  })

  it('redirects an unauthenticated visitor from /admin to /login', async () => {
    mockMe(null)

    const router = await renderApp('/admin')

    expect(router.state.location.pathname).toBe('/login')
    // The guard flags the expired/redirect search so login can return the user.
    expect(router.state.location.search).toMatchObject({ expired: true })
  })
})
