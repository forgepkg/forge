import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider, createMemoryHistory, createRouter } from '@tanstack/react-router'

import { makeQueryClient } from '~/lib/queryClient'
import { clearSession } from '~/lib/auth'
import { searchOptions } from '~/lib/search'
import type { LoginOptions } from '~/api/auth'
import type { Me } from '~/api/me'
import type { DeviceRequest } from '~/api/device'
import { normalizeUserCode } from '~/api/device'
import { routeTree } from '~/routeTree.gen'
import { describeScope } from './Device'

/**
 * The device login's page (`/device`, RFC 8628): a signed-in user enters the
 * code a command-line client shows (or arrives with it filled in from the
 * client's link), sees which client asks for what, and approves or denies it
 * (`POST /auth/device/lookup`, `POST /auth/device/decide`). A filled-in code
 * is looked up but never approved without the click; a visitor is sent
 * through the sign-in and back with the code; a code no request waits for
 * (mistyped, expired, answered) and too many wrong codes are said so.
 */

const me: Me = {
  user: { id: 4, username: 'dev@example.com', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

const pending: DeviceRequest = {
  user_code: 'BCDF-GHJK',
  client_id: 'docker-credential-forge',
  client_name: 'Docker credential helper',
  scope: { level: 'write', repositories: ['docker-hosted'] },
  client_ip: '192.0.2.7',
  created_at: '2026-10-31T10:00:00Z',
  expires_at: '2026-10-31T10:10:00Z',
}

const combined: LoginOptions = {
  mode: 'combined',
  password: true,
  oidc: [],
  remember_accounts: false,
}

const fetchMock = vi.fn()

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  })
}

interface Handlers {
  /** Whether a session is signed in (a visitor otherwise, until it signs in). */
  signedIn?: boolean
  lookup?: (body: { user_code: string }) => Response
  decide?: (body: { user_code: string; approve: boolean }) => Response
}

/** A fake server: the identity, the login and the device endpoints. */
function mockApi(h: Handlers) {
  const state = { signedIn: h.signedIn ?? true }
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input.toString(), 'http://localhost')
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = () => JSON.parse(String(init?.body))
    const path = url.pathname
    if (path === '/auth/login-options') return Promise.resolve(json(combined))
    if (path === '/auth/login' && method === 'POST') {
      state.signedIn = true
      return Promise.resolve(
        json({ user_id: 4, username: me.user.username, is_admin: false, csrf_token: 'csrf' }),
      )
    }
    if (!state.signedIn) {
      return Promise.resolve(new Response('authentication required', { status: 401 }))
    }
    if (path === '/admin/me') return Promise.resolve(json(me))
    if (path === '/auth/me') {
      return Promise.resolve(json({ username: me.user.username, csrf_token: 'csrf' }))
    }
    if (path === '/auth/device/lookup' && method === 'POST') {
      return Promise.resolve(h.lookup ? h.lookup(body()) : json(pending))
    }
    if (path === '/auth/device/decide' && method === 'POST') {
      return Promise.resolve(h.decide ? h.decide(body()) : new Response(null, { status: 204 }))
    }
    if (path === '/browse/repos') return Promise.resolve(json([]))
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

async function renderPage(initialPath: string) {
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

/** The bodies sent to `path`. */
function sent(path: string): unknown[] {
  return fetchMock.mock.calls
    .filter(([input, init]) => String(input).endsWith(path) && init?.method === 'POST')
    .map(([, init]) => JSON.parse(String(init?.body)))
}

describe('Device', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
    localStorage.clear()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
    localStorage.clear()
  })

  it('looks up a typed code and signs the client in on approval', async () => {
    const user = userEvent.setup()
    mockApi({})
    await renderPage('/device')

    await user.type(await screen.findByRole('textbox', { name: 'Code' }), 'bcdf ghjk')
    await user.click(screen.getByRole('button', { name: 'Continue' }))

    expect(await screen.findByText('Docker credential helper asks to sign in')).toBeInTheDocument()
    expect(sent('/auth/device/lookup')).toEqual([{ user_code: 'BCDF-GHJK' }])
    expect(screen.getAllByText('BCDF-GHJK').length).toBeGreaterThan(0)
    expect(screen.getByText('docker-credential-forge')).toBeInTheDocument()
    expect(screen.getByText('192.0.2.7')).toBeInTheDocument()
    expect(
      screen.getByText('Read and write, on the repository docker-hosted'),
    ).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Approve' }))
    expect(await screen.findByText('Signed in')).toBeInTheDocument()
    expect(sent('/auth/device/decide')).toEqual([{ user_code: 'BCDF-GHJK', approve: true }])
  })

  it('looks up a filled-in code but never approves it without the click, and denies', async () => {
    const user = userEvent.setup()
    mockApi({})
    await renderPage('/device?code=bcdf-ghjk')

    expect(await screen.findByText('Docker credential helper asks to sign in')).toBeInTheDocument()
    expect(sent('/auth/device/lookup')).toEqual([{ user_code: 'BCDF-GHJK' }])
    // Shown, not decided.
    await new Promise((r) => setTimeout(r, 50))
    expect(sent('/auth/device/decide')).toEqual([])

    await user.click(screen.getByRole('button', { name: 'Deny' }))
    expect(await screen.findByText('Denied')).toBeInTheDocument()
    expect(sent('/auth/device/decide')).toEqual([{ user_code: 'BCDF-GHJK', approve: false }])
  })

  it('takes a visitor through the sign-in and back to the filled-in code', async () => {
    const user = userEvent.setup()
    mockApi({ signedIn: false })
    const router = await renderPage('/device?code=bcdf-ghjk')

    await waitFor(() => expect(router.state.location.pathname).toBe('/login'))
    expect(router.state.location.search).toMatchObject({ redirect: '/device?code=bcdf-ghjk' })
    expect(sent('/auth/device/lookup')).toEqual([])

    await user.type(await screen.findByLabelText('Username'), me.user.username)
    await user.type(screen.getByLabelText('Password'), 'secret-password')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))

    await waitFor(() => expect(router.state.location.pathname).toBe('/device'))
    expect(router.state.location.search).toMatchObject({ code: 'bcdf-ghjk' })
    expect(await screen.findByText('Docker credential helper asks to sign in')).toBeInTheDocument()
    expect(sent('/auth/device/lookup')).toEqual([{ user_code: 'BCDF-GHJK' }])
    expect(sent('/auth/device/decide')).toEqual([])
  })

  it('says when no sign-in waits for the code (an expired one), offering no approval', async () => {
    mockApi({
      lookup: () => new Response('no login is waiting for this code', { status: 404 }),
    })
    await renderPage('/device?code=BCDF-GHJK')

    expect(await screen.findByText('No sign-in is waiting for this code')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull()
    // The code stays in the field, to correct it.
    expect(screen.getByRole('textbox', { name: 'Code' })).toHaveValue('BCDF-GHJK')
  })

  it('says when the request expired before the click', async () => {
    const user = userEvent.setup()
    mockApi({
      decide: () => new Response('no login is waiting for this code', { status: 404 }),
    })
    await renderPage('/device?code=BCDF-GHJK')

    await user.click(await screen.findByRole('button', { name: 'Approve' }))
    expect(await screen.findByText('This sign-in is no longer pending')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Approve' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Deny' })).toBeDisabled()
  })

  it('refuses a malformed code before asking, and says when too many codes were wrong', async () => {
    const user = userEvent.setup()
    mockApi({
      lookup: () =>
        new Response('too many wrong codes; try again later', {
          status: 429,
          headers: { 'retry-after': '300' },
        }),
    })
    await renderPage('/device')

    const field = await screen.findByRole('textbox', { name: 'Code' })
    await user.type(field, 'BCDF-GHJ1')
    await user.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Enter the eight letters your terminal shows, such as BCDF-GHJK.',
    )
    expect(sent('/auth/device/lookup')).toEqual([])

    await user.clear(field)
    await user.type(field, 'BCDF-GHJK')
    await user.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText('Too many wrong codes')).toBeInTheDocument()
    expect(screen.getByText('Try again in 5 minutes.')).toBeInTheDocument()
  })
})

describe('device codes and scopes', () => {
  it('reads a code in any spelling', () => {
    expect(normalizeUserCode('bcdfghjk')).toBe('BCDF-GHJK')
    expect(normalizeUserCode(' BCDF-ghjk ')).toBe('BCDF-GHJK')
    for (const bad of ['', 'BCDF-GHJ', 'BCDF-GHJKL', 'ABCD-EFGH', 'BCDF-GHJ0']) {
      expect(normalizeUserCode(bad)).toBeNull()
    }
  })

  it('says what a token may do', () => {
    expect(describeScope(null)).toBe('Everything you may do')
    expect(describeScope({ level: 'read', repositories: [] })).toBe('Read')
    expect(describeScope({ level: null, repositories: ['a', 'b'] })).toBe(
      'Everything you may do, on the repositories a, b',
    )
    expect(describeScope({ level: 'delete', repositories: ['a'] })).toBe(
      'Read, write and delete, on the repository a',
    )
  })
})
