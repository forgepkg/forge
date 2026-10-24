import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider, createMemoryHistory, createRouter } from '@tanstack/react-router'

import { clearSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { CliLoginRequest } from '~/api/cliLogin'
import { routeTree } from '~/routeTree.gen'

/**
 * The page `npm login` opens: it shows who asks, signs the client in as the
 * current user or refuses it (`POST /auth/cli-login/{secret}`), and says so
 * when the request is no longer pending (404).
 */

const me: Me = {
  user: { id: 4, username: 'dev@example.com', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

const pending: CliLoginRequest = {
  client: 'npm',
  repository: 'npm-all',
  hostname: 'laptop-42',
  client_ip: '192.0.2.7',
  created_at: '2026-10-23T10:00:00Z',
  expires_at: '2026-10-23T10:10:00Z',
}

const fetchMock = vi.fn()

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function mockApi(login: () => Response, decide: () => Response = () => new Response(null, { status: 204 })) {
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input.toString(), 'http://localhost')
    if (url.pathname.endsWith('/admin/me')) return Promise.resolve(json(me))
    if (url.pathname === '/auth/me') {
      return Promise.resolve(json({ username: me.user.username, csrf_token: 'csrf' }))
    }
    if (url.pathname === '/auth/cli-login/s3cret') {
      return Promise.resolve((init?.method ?? 'GET') === 'POST' ? decide() : login())
    }
    if (url.pathname.endsWith('/browse/repos')) return Promise.resolve(json([]))
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

async function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: ['/cli-login/s3cret'] }),
  })
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await waitFor(() => expect(router.state.status).toBe('idle'))
}

function decisions() {
  return fetchMock.mock.calls
    .filter(([input, init]) => String(input).includes('/auth/cli-login/') && init?.method === 'POST')
    .map(([, init]) => JSON.parse(String(init?.body)))
}

describe('CliLogin', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('shows the request and signs the client in on approval', async () => {
    const user = userEvent.setup()
    mockApi(() => json(pending))
    await renderPage()

    expect(await screen.findByText('npm asks to sign in')).toBeInTheDocument()
    expect(screen.getByText('npm-all')).toBeInTheDocument()
    expect(screen.getByText('laptop-42')).toBeInTheDocument()
    expect(screen.getByText('192.0.2.7')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText('Signed in')).toBeInTheDocument()
    expect(decisions()).toEqual([{ approve: true }])
  })

  it('refuses the client', async () => {
    const user = userEvent.setup()
    mockApi(() => json(pending))
    await renderPage()

    await user.click(await screen.findByRole('button', { name: 'Refuse' }))
    expect(await screen.findByText('Refused')).toBeInTheDocument()
    expect(decisions()).toEqual([{ approve: false }])
  })

  it('says when the request is no longer pending', async () => {
    mockApi(() => new Response('no such login request', { status: 404 }))
    await renderPage()

    expect(await screen.findByText('This login request is no longer pending')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Sign in' })).toBeNull()
  })
})
