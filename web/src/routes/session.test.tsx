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
import { meKeys, type Me } from '~/api/me'
import { routeTree } from '~/routeTree.gen'
import { searchOptions } from '~/lib/search'

/**
 * Session expiry + sign-out against the real route tree, query client and
 * app shell (H4, L11b):
 *  - once the server starts answering 401 (idle timeout, revoked session),
 *    the app makes a *bounded* number of requests and lands on /login with a
 *    return-to and the "expired" notice — it used to refetch `/admin/me` in an
 *    endless loop while the route guards kept resolving the stale identity;
 *  - signing out drops every cached query, not just the identity.
 */

const readerMe: Me = {
  user: { id: 2, username: 'alice', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

/**
 * A fake server whose session can be expired mid-test: while alive it answers
 * the identity and data endpoints; once expired every endpoint is a 401.
 * Counts `GET /admin/me` calls. Responses take a couple of milliseconds (a
 * real round-trip), so a request loop shows up as a high count instead of
 * starving the event loop.
 */
function fakeServer(me: Me) {
  const state = { alive: true, meCalls: 0, calls: [] as string[] }
  const respond = (path: string): Response => {
    if (!state.alive) {
      return new Response('authentication required', { status: 401 })
    }
    if (path.endsWith('/admin/me')) return json(me)
    if (path.endsWith('/auth/me')) {
      return json({
        user_id: me.user.id,
        username: me.user.username,
        is_admin: me.is_admin,
        csrf_token: 'live-csrf',
      })
    }
    if (path.endsWith('/browse/repos')) {
      return json([{ name: 'nuget', kind: 'proxy' }])
    }
    if (path.endsWith('/admin/repositories')) return json([])
    if (path.endsWith('/auth/logout')) {
      state.alive = false // the server revokes the session
      return json({ revoked: true })
    }
    return new Response('not found', { status: 404 })
  }
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const path = new URL(raw, 'http://localhost').pathname
    state.calls.push(path)
    if (path.endsWith('/admin/me')) state.meCalls++
    return new Promise<Response>((resolve) =>
      setTimeout(() => resolve(respond(path)), 2),
    )
  })
  return state
}

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
  return { router, queryClient }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

describe('session expiry', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('a 401 on the identity refetch makes a bounded number of requests and routes to login', async () => {
    setSession('live-csrf')
    const server = fakeServer(readerMe)
    const { router, queryClient } = await renderApp('/')
    const header = await screen.findByRole('navigation', { name: 'Main' })
    expect(await within(header).findByText('alice')).toBeInTheDocument()

    // The session expires server-side; the next identity refetch (window
    // focus, an auth-change notification, ...) gets a 401.
    server.alive = false
    server.meCalls = 0
    server.calls = []
    void queryClient.invalidateQueries({ queryKey: meKeys.self() })
    await sleep(500)

    // Bounded: the old notify -> invalidate -> 401 -> notify cycle made ~100
    // calls in this window.
    expect(server.meCalls).toBeGreaterThanOrEqual(1)
    expect(server.meCalls).toBeLessThanOrEqual(3)
    expect(server.calls.length).toBeLessThanOrEqual(5)

    // ...and the user is on the login screen, told why, with a way back.
    expect(router.state.location.pathname).toBe('/login')
    expect(router.state.location.search).toMatchObject({
      redirect: '/',
      expired: 'true',
    })
    expect(
      await screen.findByText(/your session expired/i),
    ).toBeInTheDocument()
    // The stale identity is gone (not merely invalidated), so no route
    // guard can resolve it again.
    expect(queryClient.getQueryData(meKeys.self())).toBeUndefined()
    expect(getCsrfToken()).toBeNull()

    // And it stays quiet afterwards.
    const settled = server.calls.length
    await sleep(300)
    expect(server.calls.length).toBe(settled)
  })

  it('a 401 from a page query returns to that page after sign-in', async () => {
    setSession('live-csrf')
    const server = fakeServer(adminMe)
    const { router, queryClient } = await renderApp('/')
    await within(await screen.findByRole('navigation', { name: 'Main' })).findByText('root')

    // Expire, then navigate in-app: the guards resolve the cached identity,
    // the page's own data query is the first to see the 401.
    server.alive = false
    server.calls = []
    void router.navigate({ to: '/manage/repositories' })

    await waitFor(() => expect(router.state.location.pathname).toBe('/login'))
    expect(router.state.location.search).toMatchObject({
      redirect: '/manage/repositories',
      expired: 'true',
    })
    expect(queryClient.getQueryData(meKeys.self())).toBeUndefined()
    await sleep(300)
    expect(server.calls.length).toBeLessThanOrEqual(5)
  })
})

describe('sign-out', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('drops every cached query, not only the identity', async () => {
    setSession('live-csrf')
    fakeServer(readerMe)
    const { router, queryClient } = await renderApp('/')
    const header = await screen.findByRole('navigation', { name: 'Main' })
    await within(header).findByText('alice')
    // The Browse screen cached this user's repository list.
    await within(screen.getByRole('main')).findByRole('link', { name: /nuget/ })
    expect(queryClient.getQueryCache().getAll().length).toBeGreaterThan(1)

    await userEvent.click(within(header).getByRole('button', { name: 'Sign out' }))

    await waitFor(() => expect(router.state.location.pathname).toBe('/login'))
    await sleep(100)
    // No query holds the previous user's data any more (only the login
    // screen's own public options may be cached).
    const withData = queryClient
      .getQueryCache()
      .getAll()
      .filter((q) => q.state.data !== undefined && q.queryKey[0] !== 'auth')
      .map((q) => q.queryKey)
    expect(withData).toEqual([])
    expect(queryClient.getQueryData(meKeys.self())).toBeUndefined()
    // A deliberate sign-out is not reported as an expired session.
    expect(router.state.location.search).not.toHaveProperty('expired', true)
    expect(screen.queryByText(/your session expired/i)).toBeNull()
  })
})
