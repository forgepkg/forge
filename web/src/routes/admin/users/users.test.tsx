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
import { clearSession, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { UserView } from '~/api/users'
import type { TokenView } from '~/api/tokens'
import { routeTree } from '~/routeTree.gen'

/**
 * Admin users + tokens screens, driven against the **real** route tree + query
 * hooks so the admin guard, routing, and mutations are all exercised:
 *  - the users list renders users with how each signs in, and create-user
 *    POSTs the right body + the list re-fetches (invalidation; roles are
 *    covered by `userRoles.test.tsx`);
 *  - delete-user invalidates the list, and a refused delete (409 for the last
 *    active admin) shows the server's reason;
 *  - the per-user token screen shows a freshly-created secret **once** and
 *    revoke removes the token (list invalidation reflecting `revoked_at`);
 *    an expired token is not shown as active, and scopes are visible.
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
    auth_source: 'local',
    captured_password_at: null,
    roles: [],
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
  onConvertUser?: (id: number) => Response
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

      // Switch to a local account.
      const convertMatch = path.match(/\/admin\/users\/(\d+)\/convert-to-local$/)
      if (convertMatch && method === 'POST') {
        const id = Number(convertMatch[1])
        return Promise.resolve(
          h.onConvertUser ? h.onConvertUser(id) : json(user({ id, auth_source: 'local' })),
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

  it('shows how each user signs in, telling look-alike accounts apart', async () => {
    mockApi({
      users: [
        user({ id: 2, username: 'alice', auth_source: 'upstream-basic' }),
        user({ id: 3, username: 'alice@corp', auth_source: 'oidc' }),
        user({ id: 4, username: 'root', auth_source: 'local' }),
        user({ id: 5, username: 'svc', auth_source: 'scim' }),
      ],
    })

    await renderAt('/manage/users')

    await screen.findByText('alice@corp')
    expect(screen.getByRole('columnheader', { name: 'Sign-in' })).toBeInTheDocument()
    const signIn = (name: string) =>
      within(screen.getByRole('button', { name }).closest('tr')!).getAllByRole(
        'cell',
      )[1]
    expect(signIn('alice')).toHaveTextContent('Credential forwarding')
    expect(signIn('alice@corp')).toHaveTextContent('Identity provider')
    expect(signIn('root')).toHaveTextContent('Password')
    // An unknown source is shown as sent.
    expect(signIn('svc')).toHaveTextContent('scim')
  })

  it('marks local and identity-provider accounts without a UPN as legacy names', async () => {
    mockApi({
      users: [
        user({ id: 2, username: 'root', auth_source: 'local' }),
        user({ id: 3, username: 'alice@corp.example', auth_source: 'local' }),
        user({ id: 4, username: 'bob', auth_source: 'oidc' }),
        // A forwarded account keeps the name its upstream accepted.
        user({ id: 5, username: 'carol', auth_source: 'upstream-basic' }),
      ],
    })

    await renderAt('/manage/users')

    await screen.findByText('alice@corp.example')
    const row = (name: string) =>
      within(screen.getByRole('button', { name }).closest('tr')!)
    expect(row('root').getByText('legacy name')).toBeInTheDocument()
    expect(row('bob').getByText('legacy name')).toBeInTheDocument()
    expect(row('alice@corp.example').queryByText('legacy name')).toBeNull()
    expect(row('carol').queryByText('legacy name')).toBeNull()
  })

  it('create-user asks for a UPN before it POSTs', async () => {
    let posted = false
    mockApi({
      users: [],
      onCreateUser: () => {
        posted = true
        return json(user({ id: 2, username: 'carol' }), 201)
      },
    })

    const user_ = userEvent.setup()
    await renderAt('/manage/users')

    const username = await screen.findByLabelText('Username')
    expect(username).toHaveAttribute('placeholder', 'alice@example.com')
    await user_.type(username, 'carol')
    await user_.type(screen.getByLabelText('Password'), 'hunter2')

    expect(
      screen.getByText('The username must be a UPN such as alice@example.com.'),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create user' })).toBeDisabled()

    await user_.type(username, '@example')
    expect(screen.getByRole('button', { name: 'Create user' })).toBeDisabled()
    await user_.type(username, '.com')
    expect(
      screen.queryByText('The username must be a UPN such as alice@example.com.'),
    ).toBeNull()
    expect(screen.getByRole('button', { name: 'Create user' })).toBeEnabled()
    expect(posted).toBe(false)
  })

  it('create-user POSTs the right body and re-fetches the list', async () => {
    let posted: unknown = null
    const usersAfter = [user({ id: 2, username: 'carol@example.com' })]
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

    await user_.type(await screen.findByLabelText('Username'), 'carol@example.com')
    // A password manager must not offer the admin's own password here.
    expect(screen.getByLabelText('Password')).toHaveAttribute(
      'autocomplete',
      'new-password',
    )
    await user_.type(screen.getByLabelText('Password'), 'hunter2')
    await user_.click(screen.getByRole('button', { name: 'Create user' }))

    await waitFor(() => expect(posted).not.toBeNull())
    expect(posted).toEqual({
      username: 'carol@example.com',
      password: 'hunter2',
      is_admin: false,
      active: true,
    })
    // List invalidation re-fetched and shows the new user.
    expect(await screen.findByText('carol@example.com')).toBeInTheDocument()
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

  it('shows why a delete was refused and keeps the user', async () => {
    mockApi({
      users: [user({ id: 4, username: 'sole-admin', is_admin: true })],
      onDeleteUser: () =>
        new Response(
          'this would leave no active administrator; make another user an admin first',
          { status: 409 },
        ),
    })

    const u = userEvent.setup()
    await renderAt('/manage/users')

    await u.click(await screen.findByRole('button', { name: 'Delete' }))
    await u.click(screen.getByRole('button', { name: 'Confirm' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'this would leave no active administrator',
    )
    expect(screen.getByText('sole-admin')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument()
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
      users: [user({ id: 2, username: 'alice', auth_source: 'oidc' })],
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

    // The header says how this user signs in.
    expect(await screen.findByText(/^Sign-in:/)).toHaveTextContent(
      'Sign-in: Identity provider',
    )

    await u.type(await screen.findByLabelText('Token name'), 'ci-pipeline')
    await u.click(screen.getByRole('button', { name: 'Create token' }))

    // The plaintext is shown exactly once via ShowOnceSecret.
    expect(await screen.findByText('super-secret-plaintext')).toBeInTheDocument()
    expect(screen.getByText('Token created')).toBeInTheDocument()
  })

  it('switches a forwarded account with a kept password to a local one', async () => {
    let converted: number | null = null
    let users = [
      user({
        id: 2,
        username: 'alice',
        auth_source: 'upstream-basic',
        captured_password_at: '2026-10-01T12:00:00Z',
      }),
    ]
    mockApi({
      get users() {
        return users
      },
      tokens: [],
      onConvertUser: (id) => {
        converted = id
        users = [user({ id, username: 'alice', auth_source: 'local' })]
        return json(users[0])
      },
    })

    const u = userEvent.setup()
    const router = await renderAt('/manage/users')
    await screen.findByText('alice')
    await router.navigate({ to: '/manage/users/$userId', params: { userId: '2' } })
    await waitFor(() => expect(router.state.status).toBe('idle'))

    expect(await screen.findByText(/^Password kept/)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Switch to a local account…' }))
    expect(converted).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Switch to a local account' }))

    await waitFor(() => expect(converted).toBe(2))
    expect(await screen.findByText(/^Sign-in:/)).toHaveTextContent('Sign-in: Password')
    expect(screen.queryByText(/^Password kept/)).not.toBeInTheDocument()
  })

  it('offers no switch for an account without a kept password', async () => {
    mockApi({
      users: [user({ id: 2, username: 'alice', auth_source: 'upstream-basic' })],
      tokens: [],
    })
    const router = await renderAt('/manage/users')
    await screen.findByText('alice')
    await router.navigate({ to: '/manage/users/$userId', params: { userId: '2' } })
    await waitFor(() => expect(router.state.status).toBe('idle'))
    expect(await screen.findByText(/^Sign-in:/)).toHaveTextContent('Credential forwarding')
    expect(screen.queryByRole('button', { name: /local account/ })).not.toBeInTheDocument()
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

  it('marks expired tokens and shows each token scope', async () => {
    mockApi({
      users: [user({ id: 2, username: 'alice' })],
      tokens: [
        token({ id: 5, name: 'old-ci', expires_at: '2000-01-01T00:00:00Z' }),
        token({
          id: 6,
          name: 'ops',
          scope: { actions: ['admin'] },
        }),
        token({
          id: 7,
          name: 'push',
          expires_at: '2999-01-01T00:00:00Z',
          scope: { actions: ['read', 'write'], repositories: [3, 4] },
        }),
      ],
    })

    await renderAt('/manage/users/2')

    const row = async (name: string) =>
      (await screen.findByText(name)).closest('tr')!
    const oldCi = await row('old-ci')
    expect(within(oldCi).getByText('expired')).toBeInTheDocument()
    expect(within(oldCi).queryByText('active')).toBeNull()
    expect(within(oldCi).getByText('unscoped')).toBeInTheDocument()

    const ops = await row('ops')
    expect(within(ops).getByText('admin')).toBeInTheDocument()
    expect(within(ops).getByText('active')).toBeInTheDocument()

    const push = await row('push')
    expect(within(push).getByText('read, write')).toBeInTheDocument()
    expect(within(push).getByText('2 repositories')).toBeInTheDocument()
    expect(within(push).getByText('active')).toBeInTheDocument()
  })
})
