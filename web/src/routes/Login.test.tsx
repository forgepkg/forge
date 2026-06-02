import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { makeQueryClient } from '~/lib/queryClient'
import { clearToken, getToken } from '~/lib/auth'
import type { Me } from '~/api/me'
import { routeTree } from '~/routeTree.gen'

/**
 * Login behavior (plan §3, §Testing): pasting a *valid* token verifies it via
 * `GET /admin/me`, persists it, and lands on the requested page; an *invalid*
 * token is never left in storage and surfaces an inline error.
 */

const readerMe: Me = {
  user: { id: 2, username: 'reader', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

const fetchMock = vi.fn()

function meEndpoint(handler: () => Response) {
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.endsWith('/admin/me')) return Promise.resolve(handler())
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

async function renderLogin() {
  const queryClient = makeQueryClient()
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: ['/login'] }),
  })
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await waitFor(() => expect(router.state.status).toBe('idle'))
  return router
}

describe('Login', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearToken()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearToken()
  })

  it('stores a valid token and navigates to Browse', async () => {
    const user = userEvent.setup()
    meEndpoint(
      () =>
        new Response(JSON.stringify(readerMe), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    )

    const router = await renderLogin()

    await user.type(screen.getByLabelText('Registry token'), 'good-token')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))

    await waitFor(() => expect(router.state.location.pathname).toBe('/'))
    expect(getToken()).toBe('good-token')
  })

  it('rejects an invalid token: clears storage and shows an error', async () => {
    const user = userEvent.setup()
    meEndpoint(() => new Response('unauthorized', { status: 401 }))

    const router = await renderLogin()

    await user.type(screen.getByLabelText('Registry token'), 'bad-token')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/not accepted/i)
    expect(getToken()).toBeNull()
    expect(router.state.location.pathname).toBe('/login')
  })
})
