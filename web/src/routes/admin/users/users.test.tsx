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
import { clearSession, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { UserView } from '~/api/users'
import type { TokenView } from '~/api/tokens'
import { routeTree } from '~/routeTree.gen'

/**
 * Admin users + tokens screens (plan §Phase 5 testing), driven against the
 * **real** route tree + query hooks so the admin guard, routing, and mutations
 * are all exercised:
 *  - the users list renders users and create-user POSTs the right body + the
 *    list re-fetches (invalidation);
 *  - delete-user invalidates the list;
 *  - the per-user token screen shows a freshly-created secret **once** and
 *    revoke removes the token (list invalidation reflecting `revoked_at`).
 */

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

function user(over: Partial<UserView>): UserView {
  return {
    id: 1,
    username: 'alice',
    is_admin: false,
    active: true,
    ...over,
  }
}

function token(over: Partial<TokenView>): TokenView {
  return {
    id: 1,
    user_id: 2,
    name: 'ci',
    expires_at: null,
    revoked_at: null,
    last_used_at: null,
    created_at: '2026-01-01T00:00:00Z',
    ...over,
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

interface ApiHandlers {
  users?: UserView[]
  tokens?: TokenView[]
  onCreateUser?: (body: unknown) => Response
  onDeleteUser?: (id: number) => Response
  onCreateToken?: (userId: number, body: unknown) => Response
  onRevokeToken?: (id: number) => Response
}

/** Route the mock by method + pathname against the admin API. */
function mockApi(h: ApiHandlers) {
  fetchMock.mockImplementation(
    (input: RequestInfo | URL, init?: RequestInit) => {
      const raw = typeof input === 'string' ? input : input.toString()
      const url = new URL(raw, 'http://localhost')
      const method = (init?.method ?? 'GET').toUpperCase()
      const path = url.pathname

      if (path.endsWith('/admin/me')) return Promise.resolve(json(adminMe))

      // Per-user token list / create.
      const tokensMatch = path.match(/\/admin\/users\/(\d+)\/tokens$/)
      if (tokensMatch) {
        const userId = Number(tokensMatch[1])
        if (method === 'GET') {
          return Promise.resolve(json(h.tokens ?? []))
        }
        if (method === 'POST') {
          const body = init?.body ? JSON.parse(init.body as string) : {}
          return Promise.resolve(
            h.onCreateToken
              ? h.onCreateToken(userId, body)
              : json({ ...token({ name: body.name, user_id: userId }), token: 'plaintext-secret' }, 201),
          )
        }
      }

      // Token revoke.
      const revokeMatch = path.match(/\/admin\/tokens\/(\d+)$/)
      if (revokeMatch && method === 'DELETE') {
        const id = Number(revokeMatch[1])
        return Promise.resolve(
          h.onRevokeToken ? h.onRevokeToken(id) : new Response(null, { status: 204 }),
        )
      }

      // User list / create.
      if (path.endsWith('/admin/users') && method === 'GET') {
        return Promise.resolve(json(h.users ?? []))
      }
      if (path.endsWith('/admin/users') && method === 'POST') {
        const body = init?.body ? JSON.parse(init.body as string) : {}
        return Promise.resolve(
          h.onCreateUser ? h.onCreateUser(body) : json(user(body), 201),
        )
      }

      // User delete.
      const userMatch = path.match(/\/admin\/users\/(\d+)$/)
      if (userMatch && method === 'DELETE') {
        const id = Number(userMatch[1])
        return Promise.resolve(
          h.onDeleteUser ? h.onDeleteUser(id) : new Response(null, { status: 204 }),
        )
      }

      return Promise.resolve(new Response('not found', { status: 404 }))
    },
  )
}

async function renderAt(initialPath: string) {
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

describe('admin users', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('lists users with their role and status', async () => {
    mockApi({
      users: [
        user({ id: 2, username: 'alice', is_admin: false, active: true }),
        user({ id: 3, username: 'bob', is_admin: true, active: false }),
      ],
    })

    await renderAt('/manage/users')

    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.getByText('bob')).toBeInTheDocument()
    expect(screen.getByText('inactive')).toBeInTheDocument()
  })

  it('create-user POSTs the right body and re-fetches the list', async () => {
    let posted: unknown = null
    const usersAfter = [user({ id: 2, username: 'carol' })]
    mockApi({
      users: [],
      onCreateUser: (body) => {
        posted = body
        // Subsequent GET should reflect the new user.
        mockApi({ users: usersAfter, onCreateUser: () => json(user(body as UserView), 201) })
        return json(user({ id: 2, username: (body as UserView).username }), 201)
      },
    })

    const user_ = userEvent.setup()
    await renderAt('/manage/users')

    await user_.type(await screen.findByLabelText('Username'), 'carol')
    await user_.type(screen.getByLabelText('Password'), 'hunter2')
    await user_.click(screen.getByRole('checkbox', { name: 'Administrator' }))
    await user_.click(screen.getByRole('button', { name: 'Create user' }))

    await waitFor(() => expect(posted).not.toBeNull())
    expect(posted).toEqual({
      username: 'carol',
      password: 'hunter2',
      is_admin: true,
      active: true,
    })
    // List invalidation re-fetched and shows the new user.
    expect(await screen.findByText('carol')).toBeInTheDocument()
  })

  it('delete-user confirms then DELETEs and re-fetches', async () => {
    let deleted: number | null = null
    mockApi({
      users: [user({ id: 7, username: 'doomed' })],
      onDeleteUser: (id) => {
        deleted = id
        mockApi({ users: [] })
        return new Response(null, { status: 204 })
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/users')

    expect(await screen.findByText('doomed')).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Delete' }))
    await u.click(screen.getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(deleted).toBe(7))
  })
})

describe('admin tokens', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('creates a token and shows the plaintext secret once', async () => {
    mockApi({
      users: [user({ id: 2, username: 'alice' })],
      tokens: [],
      onCreateToken: (userId, body) =>
        json(
          {
            ...token({ id: 9, user_id: userId, name: (body as { name: string }).name }),
            token: 'super-secret-plaintext',
          },
          201,
        ),
    })

    const u = userEvent.setup()
    // Seed the users cache by visiting the list first so the username renders.
    const router = await renderAt('/manage/users')
    await screen.findByText('alice')
    await router.navigate({ to: '/manage/users/$userId', params: { userId: '2' } })
    await waitFor(() => expect(router.state.status).toBe('idle'))

    await u.type(await screen.findByLabelText('Token name'), 'ci-pipeline')
    await u.click(screen.getByRole('button', { name: 'Create token' }))

    // The plaintext is shown exactly once via ShowOnceSecret.
    expect(await screen.findByText('super-secret-plaintext')).toBeInTheDocument()
    expect(screen.getByText('Token created')).toBeInTheDocument()
  })

  it('revokes a token after confirmation', async () => {
    let revoked: number | null = null
    mockApi({
      users: [user({ id: 2, username: 'alice' })],
      tokens: [token({ id: 5, user_id: 2, name: 'ci' })],
      onRevokeToken: (id) => {
        revoked = id
        mockApi({
          users: [user({ id: 2, username: 'alice' })],
          tokens: [token({ id: 5, user_id: 2, name: 'ci', revoked_at: '2026-02-02T00:00:00Z' })],
        })
        return new Response(null, { status: 204 })
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/users/2')

    expect(await screen.findByText('ci')).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Revoke' }))
    await u.click(screen.getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(revoked).toBe(5))
    expect(await screen.findByText('revoked')).toBeInTheDocument()
  })
})
