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
import { searchOptions } from '~/lib/search'

/**
 * Admin users + tokens screens, driven against the **real** route tree + query
 * hooks so the admin guard, routing, and mutations are all exercised:
 *  - the users list renders users with how each signs in and their status
 *    (invited, invitation expired, …); the create page (`/manage/users/new`)
 *    POSTs no password, says when no email service is configured and shows
 *    an invitation link once (access levels are covered by
 *    `userRoles.test.tsx`);
 *  - the user page of an invited account resends, copies (shown once) and
 *    revokes its invitation;
 *  - the user page deactivates, reactivates and signs a user out everywhere,
 *    each after a confirmation saying what happens, and the list and the page
 *    show the new status at once; a refused deactivation (409 for the last
 *    active admin) shows the server's reason and changes nothing;
 *  - delete-user invalidates the list, its confirmation suggests deactivating
 *    instead, and a refused delete (409 for the last active admin) shows the
 *    server's reason;
 *  - the per-user token screen shows a freshly-created secret **once** and
 *    revoke (after a dialog) removes the token (list invalidation
 *    reflecting `revoked_at`);
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
    email: null,
    status: 'active',
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
  realms?: unknown[]
  tokens?: TokenView[]
  onCreateUser?: (body: unknown) => Response
  onDeleteUser?: (id: number) => Response
  onCreateToken?: (userId: number, body: unknown) => Response
  onRevokeToken?: (id: number) => Response
  onConvertUser?: (id: number) => Response
  onInvite?: (id: number, body: unknown) => Response
  onRevokeInvitation?: (id: number) => Response
  onSetActive?: (id: number, body: unknown) => Response
  onReauth?: (id: number) => Response
  email?: unknown
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
      if (path.endsWith('/admin/settings/email') && method === 'GET') {
        return Promise.resolve(json(h.email ?? { configured: false }))
      }
      const inviteMatch = path.match(/\/admin\/users\/(\d+)\/invitation$/)
      if (inviteMatch) {
        const id = Number(inviteMatch[1])
        if (method === 'POST') {
          const body = init?.body ? JSON.parse(init.body as string) : {}
          return Promise.resolve(h.onInvite ? h.onInvite(id, body) : json({}))
        }
        if (method === 'DELETE') {
          return Promise.resolve(
            h.onRevokeInvitation ? h.onRevokeInvitation(id) : new Response(null, { status: 204 }),
          )
        }
      }
      if (path.endsWith('/admin/realms') && method === 'GET') {
        return Promise.resolve(json(h.realms ?? []))
      }

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

      // Sign out everywhere.
      const reauthMatch = path.match(/\/admin\/users\/(\d+)\/reauth$/)
      if (reauthMatch && method === 'POST') {
        const id = Number(reauthMatch[1])
        return Promise.resolve(
          h.onReauth ? h.onReauth(id) : new Response(null, { status: 204 }),
        )
      }

      // User delete, deactivate / reactivate.
      const userMatch = path.match(/\/admin\/users\/(\d+)$/)
      if (userMatch && method === 'DELETE') {
        const id = Number(userMatch[1])
        return Promise.resolve(
          h.onDeleteUser ? h.onDeleteUser(id) : new Response(null, { status: 204 }),
        )
      }
      if (userMatch && method === 'PATCH') {
        const id = Number(userMatch[1])
        const body = init?.body ? JSON.parse(init.body as string) : {}
        return Promise.resolve(
          h.onSetActive ? h.onSetActive(id, body) : json(user({ id, ...body })),
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
        user({ id: 3, username: 'bob', is_admin: true, active: false, status: 'inactive' }),
        user({ id: 4, username: 'carol', status: 'invited' }),
        user({ id: 5, username: 'dave', status: 'invitation_expired' }),
      ],
    })

    await renderAt('/manage/users')

    expect(await screen.findByText('alice')).toBeInTheDocument()
    const status = (name: string) =>
      within(screen.getByRole('link', { name }).closest('tr')!).getAllByRole('cell')[4]
    expect(status('alice')).toHaveTextContent('active')
    expect(status('bob')).toHaveTextContent('inactive')
    expect(status('carol')).toHaveTextContent('invited')
    expect(status('dave')).toHaveTextContent('invitation expired')
    // Users are created on a page of their own.
    expect(screen.queryByLabelText('Password')).toBeNull()
    expect(screen.getByRole('link', { name: 'New user' })).toHaveAttribute(
      'href',
      '/manage/users/new',
    )
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
      within(screen.getByRole('link', { name }).closest('tr')!).getAllByRole(
        'cell',
      )[1]
    expect(signIn('alice')).toHaveTextContent('Credential forwarding')
    expect(signIn('alice@corp')).toHaveTextContent('Identity provider')
    expect(signIn('root')).toHaveTextContent('Password')
    // An unknown source is shown as sent.
    expect(signIn('svc')).toHaveTextContent('scim')
  })

  it('creates an account of a credential-forwarding realm, without a password', async () => {
    let posted: unknown = null
    mockApi({
      users: [],
      realms: [
        { id: 3, kind: 'credential_forwarding', name: 'nexus', enabled: true, priority: 20, config: {} },
        { id: 4, kind: 'oidc', name: 'entra', enabled: true, priority: 30, config: {} },
      ],
      onCreateUser: (body) => {
        posted = body
        return json(
          { ...user({ id: 2, username: 'dora@example.com', auth_source: 'upstream-basic' }), invitation: null },
          201,
        )
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/users/new')

    await u.type(await screen.findByLabelText('Username'), 'dora@example.com')
    const signIn = await screen.findByLabelText('Sign-in')
    // Only credential-forwarding realms are offered.
    expect(
      within(signIn).queryByRole('option', { name: /entra/ }),
    ).toBeNull()
    await u.selectOptions(signIn, 'nexus')
    expect(screen.queryByLabelText('Password')).toBeNull()
    expect(
      screen.getByText(/gets the part of the username before the @/),
    ).toBeInTheDocument()
    // No invitation goes to such an account.
    expect(screen.queryByText(/No email service is configured/)).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Create user' }))

    await waitFor(() => expect(posted).not.toBeNull())
    expect(posted).toEqual({
      username: 'dora@example.com',
      role: 'reader',
      realm: 'nexus',
    })
    expect(
      await screen.findByText('Created dora@example.com: it signs in with its upstream password.'),
    ).toBeInTheDocument()
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
    await renderAt('/manage/users/new')

    const username = await screen.findByLabelText('Username')
    expect(username).toHaveAttribute('placeholder', 'alice@example.com')
    expect(screen.queryByLabelText('Password')).toBeNull()
    await user_.type(username, 'carol')
    await user_.click(screen.getByLabelText('Email address'))

    expect(
      screen.getByText('The username must be a UPN such as alice@example.com.'),
    ).toBeInTheDocument()
    const submit = screen.getByRole('button', { name: 'Create and invite' })
    expect(submit).toBeDisabled()

    await user_.type(username, '@example')
    expect(submit).toBeDisabled()
    await user_.type(username, '.com')
    expect(
      screen.queryByText('The username must be a UPN such as alice@example.com.'),
    ).toBeNull()
    expect(submit).toBeEnabled()
    // The address defaults to the username.
    expect(screen.getByLabelText('Email address')).toHaveAttribute(
      'placeholder',
      'carol@example.com',
    )
    expect(posted).toBe(false)
  })

  it('invites a new user without an email service, showing the link once', async () => {
    let posted: unknown = null
    mockApi({
      users: [],
      onCreateUser: (body) => {
        posted = body
        return json(
          {
            ...user({ id: 2, username: 'carol@example.com', status: 'invited' }),
            invitation: {
              email: 'carol.mail@example.org',
              expires_at: '2026-10-26T09:00:00Z',
              email_sent: false,
              error: 'no email service is configured',
              link: 'https://forge.example.com/invite#tok-1',
            },
          },
          201,
        )
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/users/new')

    expect(await screen.findByText(/No email service is configured, so no invitation/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Set up email' })).toHaveAttribute(
      'href',
      '/manage/settings/email',
    )
    await u.type(screen.getByLabelText('Username'), 'carol@example.com')
    await u.type(screen.getByLabelText('Email address'), 'carol.mail@example.org')
    await u.click(screen.getByRole('radio', { name: /^Admin/ }))
    await u.click(screen.getByRole('button', { name: 'Create and invite' }))

    await waitFor(() => expect(posted).not.toBeNull())
    expect(posted).toEqual({
      username: 'carol@example.com',
      email: 'carol.mail@example.org',
      role: 'admin',
    })
    expect(await screen.findByText('https://forge.example.com/invite#tok-1')).toBeInTheDocument()
    expect(screen.getByText(/this is the only time it is shown/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to carol@example.com' })).toHaveAttribute(
      'href',
      '/manage/users/2',
    )

    // Another one: the form again, empty.
    await u.click(screen.getByRole('button', { name: 'Create another' }))
    expect(screen.getByLabelText('Username')).toHaveValue('')
  })

  it('says where the invitation went when it was sent', async () => {
    mockApi({
      users: [],
      email: { configured: true, enabled: true },
      onCreateUser: (body) =>
        json(
          {
            ...user({ id: 3, username: (body as { username: string }).username, status: 'invited' }),
            invitation: {
              email: 'erin@example.com',
              expires_at: '2026-10-26T09:00:00Z',
              email_sent: true,
              error: null,
              link: null,
            },
          },
          201,
        ),
    })

    const u = userEvent.setup()
    await renderAt('/manage/users/new')

    await u.type(await screen.findByLabelText('Username'), 'erin@example.com')
    expect(screen.queryByText(/No email service is configured/)).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Create and invite' }))
    expect(
      await screen.findByText(/Created erin@example.com and sent the invitation to erin@example.com/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/only time it is shown/i)).toBeNull()
  })

  it("resends, copies and revokes an invited user's invitation", async () => {
    const invites: unknown[] = []
    let revoked = 0
    mockApi({
      users: [
        user({
          id: 9,
          username: 'frank@example.com',
          email: 'frank@example.org',
          status: 'invited',
          invitation: {
            email: 'frank@example.org',
            expires_at: '2026-10-26T09:00:00Z',
            created_at: '2026-10-23T09:00:00Z',
            sent_at: '2026-10-23T09:00:01Z',
          },
        }),
      ],
      onInvite: (_id, body) => {
        invites.push(body)
        return (body as { send_email: boolean }).send_email
          ? json({
              email: 'frank@example.org',
              expires_at: '2026-10-27T09:00:00Z',
              email_sent: true,
              error: null,
              link: null,
            })
          : json({
              email: 'frank@example.org',
              expires_at: '2026-10-27T09:00:00Z',
              email_sent: false,
              error: null,
              link: 'https://forge.example.com/invite#copied',
            })
      },
      onRevokeInvitation: () => {
        revoked += 1
        return new Response(null, { status: 204 })
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/users/9')

    expect(await screen.findByText(/went to frank@example.org/)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Resend invitation' }))
    expect(await screen.findByText(/Sent a new invitation to frank@example.org/)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Copy invitation link' }))
    expect(await screen.findByText('https://forge.example.com/invite#copied')).toBeInTheDocument()
    expect(invites).toEqual([{ send_email: true }, { send_email: false }])

    await u.click(screen.getByRole('button', { name: 'Revoke invitation' }))
    await waitFor(() => expect(revoked).toBe(1))
    expect(screen.queryByText('https://forge.example.com/invite#copied')).toBeNull()
  })

  it('deactivates a user after a confirmation, and both screens show it at once', async () => {
    const patches: unknown[] = []
    let users = [user({ id: 2, username: 'alice' })]
    mockApi({
      get users() {
        return users
      },
      tokens: [token({ id: 5, user_id: 2, name: 'ci' })],
      onSetActive: (id, body) => {
        patches.push(body)
        users = [user({ id, username: 'alice', active: false, status: 'inactive' })]
        return json(users[0])
      },
    })

    const u = userEvent.setup()
    const router = await renderAt('/manage/users/2')

    const account = await screen.findByRole('region', { name: 'Account' })
    expect(within(account).getByText('alice is active and can sign in.')).toBeInTheDocument()
    await u.click(within(account).getByRole('button', { name: 'Deactivate…' }))
    const dialog = screen.getByRole('dialog', { name: 'Deactivate alice?' })
    expect(dialog).toHaveTextContent(/Every sign-in is refused/)
    expect(dialog).toHaveTextContent(/browser sessions end now/)
    expect(dialog).toHaveTextContent(/tokens are suspended, not revoked/)
    expect(patches).toEqual([])
    await u.click(within(dialog).getByRole('button', { name: 'Deactivate user' }))

    await waitFor(() => expect(patches).toEqual([{ active: false }]))
    expect(await within(account).findByText(/Deactivated alice/)).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(within(account).getByText(/alice is inactive/)).toBeInTheDocument()
    expect(within(account).getByRole('button', { name: 'Reactivate…' })).toBeInTheDocument()
    expect(within(account).queryByRole('button', { name: 'Deactivate…' })).toBeNull()
    // The header's status and the tokens say so too.
    expect(screen.getByText('inactive')).toBeInTheDocument()
    expect(screen.getByText(/its tokens are refused until it is reactivated/)).toBeInTheDocument()

    await router.navigate({ to: '/manage/users' })
    const row = (await screen.findByRole('link', { name: 'alice' })).closest('tr')!
    expect(within(row).getAllByRole('cell')[4]).toHaveTextContent('inactive')
  })

  it('reactivates a user, naming the tokens that work again', async () => {
    const patches: unknown[] = []
    let users = [user({ id: 2, username: 'alice', active: false, status: 'inactive' })]
    mockApi({
      get users() {
        return users
      },
      tokens: [
        token({ id: 5, user_id: 2, name: 'ci' }),
        token({ id: 6, user_id: 2, name: 'old', revoked_at: '2026-02-02T00:00:00Z' }),
      ],
      onSetActive: (id, body) => {
        patches.push(body)
        users = [user({ id, username: 'alice' })]
        return json(users[0])
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/users/2')

    const account = await screen.findByRole('region', { name: 'Account' })
    // Signing out an inactive user would change nothing.
    expect(within(account).queryByRole('button', { name: /Sign out/ })).toBeNull()
    await screen.findByText('ci')
    await u.click(within(account).getByRole('button', { name: 'Reactivate…' }))
    const dialog = screen.getByRole('dialog', { name: 'Reactivate alice?' })
    expect(dialog).toHaveTextContent(/their 1 unrevoked token works again/)
    expect(dialog).toHaveTextContent(/Revoke any that should not/)
    await u.click(within(dialog).getByRole('button', { name: 'Reactivate user' }))

    await waitFor(() => expect(patches).toEqual([{ active: true }]))
    expect(await within(account).findByText('Reactivated alice.')).toBeInTheDocument()
    expect(within(account).getByText('alice is active and can sign in.')).toBeInTheDocument()
    expect(screen.queryByText(/its tokens are refused/)).toBeNull()
  })

  it('signs a credential-forwarding user out everywhere', async () => {
    let reauthed: number | null = null
    let tokenFetches = 0
    mockApi({
      users: [user({ id: 2, username: 'alice', auth_source: 'upstream-basic' })],
      get tokens() {
        tokenFetches += 1
        return [token({ id: 5, user_id: 2, name: 'ci' })]
      },
      onReauth: (id) => {
        reauthed = id
        return new Response(null, { status: 204 })
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/users/2')

    const account = await screen.findByRole('region', { name: 'Account' })
    await screen.findByText('ci')
    const fetchesBefore = tokenFetches
    await u.click(within(account).getByRole('button', { name: 'Sign out everywhere…' }))
    const dialog = screen.getByRole('dialog', { name: 'Sign alice out everywhere?' })
    expect(dialog).toHaveTextContent(/browser sessions end/)
    expect(dialog).toHaveTextContent(/checked against the upstream again/)
    expect(dialog).toHaveTextContent(/minted from a forwarded sign-in are revoked/)
    expect(reauthed).toBeNull()
    await u.click(within(dialog).getByRole('button', { name: 'Sign out everywhere' }))

    await waitFor(() => expect(reauthed).toBe(2))
    expect(await within(account).findByText('Signed alice out everywhere.')).toBeInTheDocument()
    // The tokens are re-read: those minted from a forwarded sign-in are gone.
    await waitFor(() => expect(tokenFetches).toBeGreaterThan(fetchesBefore))
  })

  it('explains that signing out keeps the tokens of an account that does not forward', async () => {
    mockApi({ users: [user({ id: 2, username: 'alice' })], tokens: [] })

    const u = userEvent.setup()
    await renderAt('/manage/users/2')

    await u.click(await screen.findByRole('button', { name: 'Sign out everywhere…' }))
    const dialog = screen.getByRole('dialog', { name: 'Sign alice out everywhere?' })
    expect(dialog).toHaveTextContent(/API tokens keep working/)
    expect(dialog).not.toHaveTextContent(/upstream/)
  })

  it('shows why deactivating the last administrator was refused and changes nothing', async () => {
    mockApi({
      users: [user({ id: 4, username: 'sole-admin', is_admin: true, roles: ['admin'] })],
      tokens: [],
      onSetActive: () =>
        new Response(
          'this would leave no active administrator; make another user an admin first',
          { status: 409 },
        ),
    })

    const u = userEvent.setup()
    await renderAt('/manage/users/4')

    const account = await screen.findByRole('region', { name: 'Account' })
    await u.click(within(account).getByRole('button', { name: 'Deactivate…' }))
    await u.click(
      within(screen.getByRole('dialog', { name: 'Deactivate sole-admin?' })).getByRole(
        'button',
        { name: 'Deactivate user' },
      ),
    )

    expect(await within(account).findByRole('alert')).toHaveTextContent(
      'this would leave no active administrator',
    )
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(within(account).getByText('sole-admin is active and can sign in.')).toBeInTheDocument()
    expect(within(account).getByRole('button', { name: 'Deactivate…' })).toBeInTheDocument()
  })

  it('deactivating an invited user says its invitation is revoked', async () => {
    mockApi({
      users: [user({ id: 9, username: 'frank@example.com', status: 'invitation_expired' })],
      tokens: [],
    })

    const u = userEvent.setup()
    await renderAt('/manage/users/9')

    const account = await screen.findByRole('region', { name: 'Account' })
    expect(within(account).getByText(/has not chosen a password yet/)).toBeInTheDocument()
    // Nothing to sign out of yet.
    expect(within(account).queryByRole('button', { name: /Sign out/ })).toBeNull()
    await u.click(within(account).getByRole('button', { name: 'Deactivate…' }))
    expect(
      screen.getByRole('dialog', { name: 'Deactivate frank@example.com?' }),
    ).toHaveTextContent(/Their invitation is revoked/)
  })

  it('delete-user suggests deactivating an account that should be kept', async () => {
    mockApi({
      users: [
        user({ id: 7, username: 'doomed' }),
        user({ id: 8, username: 'gone', active: false, status: 'inactive' }),
      ],
    })

    const u = userEvent.setup()
    await renderAt('/manage/users')

    const row = (name: string) =>
      screen.getByRole('link', { name }).closest('tr')!
    await screen.findByText('doomed')
    await u.click(within(row('doomed')).getByRole('button', { name: 'Delete' }))
    let dialog = screen.getByRole('dialog', { name: 'Delete doomed?' })
    expect(dialog).toHaveTextContent(/To keep the account, deactivate it/)
    expect(within(dialog).getByRole('link', { name: 'its page' })).toHaveAttribute(
      'href',
      '/manage/users/7',
    )
    await u.click(within(dialog).getByRole('button', { name: 'Cancel' }))

    // An inactive account is deactivated already.
    await u.click(within(row('gone')).getByRole('button', { name: 'Delete' }))
    dialog = screen.getByRole('dialog', { name: 'Delete gone?' })
    expect(dialog).not.toHaveTextContent(/deactivate it/)
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
    const dialog = screen.getByRole('dialog', { name: 'Delete doomed?' })
    expect(deleted).toBeNull()
    await u.click(within(dialog).getByRole('button', { name: 'Delete user' }))

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
    await u.click(
      within(screen.getByRole('dialog', { name: 'Delete sole-admin?' })).getByRole(
        'button',
        { name: 'Delete user' },
      ),
    )

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
    const dialog = screen.getByRole('dialog', { name: 'Revoke ci?' })
    expect(revoked).toBeNull()
    await u.click(within(dialog).getByRole('button', { name: 'Revoke token' }))

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
          scope: { admin: true },
        }),
        token({
          id: 7,
          name: 'push',
          expires_at: '2999-01-01T00:00:00Z',
          scope: { level: 'write', repositories: [3, 4] },
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
    expect(within(push).getByText('write')).toBeInTheDocument()
    expect(within(push).getByText('2 repositories')).toBeInTheDocument()
    expect(within(push).getByText('active')).toBeInTheDocument()
  })
})
