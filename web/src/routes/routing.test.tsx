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
import { clearSession, getCsrfToken, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import { routeTree } from '~/routeTree.gen'
import { searchOptions } from '~/lib/search'

/**
 * Router-integration tests against the **real** route tree:
 *   - the Admin nav link is hidden for a reader and shown for an admin;
 *   - the `_app/manage` guard redirects a non-admin to Browse and an
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

/**
 * Mock `GET /admin/me` to return the given identity, or 401 when null. Extra
 * `routes` (URL suffix → response factory) answer other endpoints such as
 * `/auth/me` / `/auth/logout`; everything else is a 404.
 */
function mockMe(me: Me | null, routes: Record<string, () => Response> = {}) {
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString()
    for (const [suffix, respond] of Object.entries(routes)) {
      if (url.endsWith(suffix)) return Promise.resolve(respond())
    }
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

describe('app routing + admin gating', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('hides the Administration links for a reader', async () => {
    setSession('reader-csrf')
    mockMe(readerMe)

    await renderApp('/')

    const rail = await screen.findByRole('navigation', { name: 'Main' })
    // Wait for the identity to resolve so the current-user widget has rendered:
    // the username, its role and a Sign out button.
    expect(await within(rail).findByText('alice')).toBeInTheDocument()
    expect(within(rail).getByText('User')).toBeInTheDocument()
    expect(
      within(rail).getByRole('button', { name: 'Sign out' }),
    ).toBeInTheDocument()

    expect(within(rail).getByRole('link', { name: 'Browse' })).toBeInTheDocument()
    expect(within(rail).getByRole('link', { name: 'Your tokens' })).toBeInTheDocument()
    expect(within(rail).queryByText('Administration')).not.toBeInTheDocument()
    expect(
      within(rail).queryByRole('link', { name: 'Overview' }),
    ).not.toBeInTheDocument()
  })

  it('shows the Administration links for an admin', async () => {
    setSession('admin-csrf')
    mockMe(adminMe)

    await renderApp('/')

    const rail = await screen.findByRole('navigation', { name: 'Main' })
    await waitFor(() =>
      expect(within(rail).getByRole('link', { name: 'Overview' })).toHaveAttribute(
        'href',
        '/manage',
      ),
    )
    expect(within(rail).getByText('Administrator')).toBeInTheDocument()
    expect(within(rail).getByRole('link', { name: 'Authentication' })).toHaveAttribute(
      'href',
      '/manage/realms',
    )
  })

  it('redirects a non-admin away from /manage to Browse', async () => {
    setSession('reader-csrf')
    mockMe(readerMe)

    const router = await renderApp('/manage')

    expect(router.state.location.pathname).toBe('/')
    // Did not render the admin landing.
    expect(screen.queryByText('Administration')).not.toBeInTheDocument()
  })

  it('lets an admin reach the admin landing at /manage', async () => {
    setSession('admin-csrf')
    mockMe(adminMe)

    const router = await renderApp('/manage')

    expect(router.state.location.pathname).toBe('/manage')
    const main = within(screen.getByRole('main'))
    expect(await main.findByRole('heading', { level: 1, name: 'Administration' })).toBeInTheDocument()
    // Only what the UI can manage; the rest is named as API-only, and RBAC
    // is no longer part of that rest.
    expect(main.queryByText(/admin flags|with retention/)).toBeNull()
    expect(
      main.getByText(/User deactivation has no screen/),
    ).toBeInTheDocument()
    expect(main.queryByText(/RBAC/)).toBeNull()
    expect(main.getByRole('link', { name: /^Roles/ })).toHaveAttribute(
      'href',
      '/manage/roles',
    )
    expect(
      main.getByRole('link', { name: /^Content selectors/ }),
    ).toHaveAttribute('href', '/manage/content-selectors')
    expect(main.getByRole('link', { name: /^System/ })).toHaveAttribute('href', '/manage/system')
  })

  it('refreshes the stored CSRF token from the live session on load', async () => {
    // e.g. after an OIDC redirect: the cookie is fresh, the stored token stale.
    setSession('stale-csrf')
    mockMe(readerMe, {
      '/auth/me': () =>
        new Response(
          JSON.stringify({
            user_id: 2,
            username: 'alice',
            is_admin: false,
            csrf_token: 'fresh-csrf',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    })

    await renderApp('/')

    await waitFor(() => expect(getCsrfToken()).toBe('fresh-csrf'))
  })

  it('surfaces a failed sign-out and still clears local state', async () => {
    setSession('reader-csrf')
    mockMe(readerMe, {
      '/auth/logout': () => new Response('session error', { status: 500 }),
    })
    const router = await renderApp('/')

    const rail = await screen.findByRole('navigation', { name: 'Main' })
    await within(rail).findByText('alice')
    await userEvent.click(within(rail).getByRole('button', { name: 'Sign out' }))

    await waitFor(() => expect(router.state.location.pathname).toBe('/login'))
    expect(
      await screen.findByText(/sign-out could not be confirmed/i),
    ).toBeInTheDocument()
    expect(getCsrfToken()).toBeNull()
    // The logout request carried the CSRF header.
    const logoutCall = fetchMock.mock.calls.find(([u]) =>
      String(u).endsWith('/auth/logout'),
    )
    expect(logoutCall?.[1]?.headers).toMatchObject({ 'X-CSRF-Token': 'reader-csrf' })
  })

  it('signs out cleanly without a warning when the server confirms', async () => {
    setSession('reader-csrf')
    mockMe(readerMe, {
      '/auth/logout': () =>
        new Response(JSON.stringify({ revoked: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    })
    const router = await renderApp('/')

    const rail = await screen.findByRole('navigation', { name: 'Main' })
    await within(rail).findByText('alice')
    await userEvent.click(within(rail).getByRole('button', { name: 'Sign out' }))

    await waitFor(() => expect(router.state.location.pathname).toBe('/login'))
    expect(screen.queryByText(/sign-out could not be confirmed/i)).toBeNull()
    expect(getCsrfToken()).toBeNull()
  })

  it('redirects an unauthenticated visitor from /manage to /login', async () => {
    mockMe(null)

    const router = await renderApp('/manage')

    expect(router.state.location.pathname).toBe('/login')
    // The app-level login gate records the attempted URL so login can return
    // the user there after signing in.
    expect(router.state.location.search).toMatchObject({ redirect: '/manage' })
  })
})
