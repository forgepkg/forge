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
import type { RealmView } from '~/api/realms'
import { routeTree } from '~/routeTree.gen'

/**
 * Admin authentication-realms screens, driven against the real route tree +
 * query hooks so the admin guard, routing, and mutations are exercised:
 *  - the list renders realms in priority order with kind badges and hides the
 *    delete affordance for the built-in local realm;
 *  - reordering PUTs the **full** new id order to /admin/realms/order;
 *  - the enabled toggle PATCHes the realm; disabling a realm people sign in
 *    with (local, OIDC, credential forwarding) asks first, and a server
 *    refusal (409) is shown with its reason;
 *  - the create form validates required fields per kind (no POST when
 *    invalid) and POSTs the parsed config when valid;
 *  - the edit form sends list values containing commas back unchanged,
 *    requires a new client secret once the issuer or client ID changes, and
 *    asks before saving a sign-in realm as disabled.
 */

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

function realm(over: Partial<RealmView>): RealmView {
  return {
    id: 1,
    kind: 'local',
    name: 'local',
    enabled: true,
    priority: 0,
    config: {},
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...over,
  }
}

const threeRealms: RealmView[] = [
  realm({ id: 1, kind: 'local', name: 'local', priority: 0 }),
  realm({
    id: 5,
    kind: 'oidc',
    name: 'corp-sso',
    priority: 1,
    config: {
      issuer: 'https://idp.example.com',
      client_id: 'forge',
      client_secret_set: true,
    },
  }),
  realm({
    id: 3,
    kind: 'credential_forwarding',
    name: 'legacy-auth',
    priority: 2,
    enabled: false,
    config: { url: 'https://auth.example.com/check', key_pepper_set: true },
  }),
]

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

interface ApiHandlers {
  realms?: RealmView[]
  onCreate?: (body: unknown) => Response
  onPatch?: (id: number, body: unknown) => Response
  onDelete?: (id: number) => Response
  onReorder?: (body: unknown) => Response
  capturedPasswords?: () => { accounts: number; captured: number }
  onConvert?: (id: number) => Response
}

/** Route the mock by method + pathname against the realms admin API. */
function mockApi(h: ApiHandlers) {
  fetchMock.mockImplementation(
    (input: RequestInfo | URL, init?: RequestInit) => {
      const raw = typeof input === 'string' ? input : input.toString()
      const url = new URL(raw, 'http://localhost')
      const method = (init?.method ?? 'GET').toUpperCase()
      const path = url.pathname
      const body = () => (init?.body ? JSON.parse(init.body as string) : {})

      if (path.endsWith('/admin/me')) return Promise.resolve(json(adminMe))

      if (path.endsWith('/admin/realms/order') && method === 'PUT') {
        return Promise.resolve(
          h.onReorder ? h.onReorder(body()) : json(h.realms ?? []),
        )
      }

      const keptMatch = path.match(/\/admin\/realms\/(\d+)\/captured-passwords$/)
      if (keptMatch && method === 'GET') {
        return Promise.resolve(
          json(h.capturedPasswords?.() ?? { accounts: 0, captured: 0 }),
        )
      }
      const convertMatch = path.match(/\/admin\/realms\/(\d+)\/convert-to-local$/)
      if (convertMatch && method === 'POST') {
        const id = Number(convertMatch[1])
        return Promise.resolve(
          h.onConvert ? h.onConvert(id) : json({ converted: 0, remaining: 0 }),
        )
      }

      const idMatch = path.match(/\/admin\/realms\/(\d+)$/)
      if (idMatch) {
        const id = Number(idMatch[1])
        const found = (h.realms ?? []).find((r) => r.id === id)
        if (method === 'GET') {
          return Promise.resolve(
            found ? json(found) : new Response('not found', { status: 404 }),
          )
        }
        if (method === 'PATCH') {
          return Promise.resolve(
            h.onPatch ? h.onPatch(id, body()) : json(found ?? realm({ id })),
          )
        }
        if (method === 'DELETE') {
          return Promise.resolve(
            h.onDelete ? h.onDelete(id) : new Response(null, { status: 204 }),
          )
        }
      }

      if (path.endsWith('/admin/realms') && method === 'GET') {
        return Promise.resolve(json(h.realms ?? []))
      }
      if (path.endsWith('/admin/realms') && method === 'POST') {
        return Promise.resolve(
          h.onCreate
            ? h.onCreate(body())
            : json(realm(body() as Partial<RealmView>), 201),
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

describe('admin realms list', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('renders realms in priority order with kind badges; local has no delete', async () => {
    mockApi({ realms: threeRealms })

    await renderAt('/manage/realms')

    expect(await screen.findByText('corp-sso')).toBeInTheDocument()
    const rows = screen.getAllByRole('row').slice(1) // skip the header row
    expect(rows.map((r) => within(r).getAllByRole('link')[0].textContent)).toEqual([
      'local',
      'corp-sso',
      'legacy-auth',
    ])
    expect(within(rows[0]).getByText('local', { selector: 'span' })).toBeInTheDocument()
    expect(within(rows[1]).getByText('oidc')).toBeInTheDocument()
    expect(within(rows[2]).getByText('credential_forwarding')).toBeInTheDocument()

    // The built-in local realm cannot be deleted, the others can.
    expect(within(rows[0]).queryByRole('button', { name: 'Delete' })).toBeNull()
    expect(within(rows[1]).getByRole('button', { name: 'Delete' })).toBeInTheDocument()
  })

  it('moving a realm up PUTs the full new id order', async () => {
    let reordered: unknown = null
    mockApi({
      realms: threeRealms,
      onReorder: (body) => {
        reordered = body
        return json(threeRealms)
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms')

    await u.click(await screen.findByRole('button', { name: 'Move corp-sso up' }))

    // Every realm id exactly once, with corp-sso (5) and local (1) swapped.
    await waitFor(() => expect(reordered).toEqual({ order: [5, 1, 3] }))
  })

  it('the enabled toggle PATCHes the realm', async () => {
    let patched: { id: number; body: unknown } | null = null
    mockApi({
      realms: threeRealms,
      onPatch: (id, body) => {
        patched = { id, body }
        return json(realm({ id: 3, enabled: true }))
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms')

    await u.click(
      await screen.findByRole('checkbox', { name: 'legacy-auth enabled' }),
    )

    await waitFor(() =>
      expect(patched).toEqual({ id: 3, body: { enabled: true } }),
    )
  })

  it('asks before disabling local; cancelling sends nothing', async () => {
    const patches: unknown[] = []
    mockApi({
      realms: threeRealms,
      onPatch: (_id, body) => {
        patches.push(body)
        return json(realm({ id: 1, enabled: false }))
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms')

    const toggle = await screen.findByRole('checkbox', { name: 'local enabled' })
    await u.click(toggle)

    const row = toggle.closest('tr')!
    expect(
      within(row).getByText(/stops every password login/),
    ).toHaveTextContent(
      'browser sign-in and NuGet clients sending a password over Basic',
    )
    expect(toggle).toBeChecked()

    await u.click(within(row).getByRole('button', { name: 'Cancel' }))
    expect(within(row).queryByText(/stops every password login/)).toBeNull()
    expect(toggle).toBeChecked()
    expect(patches).toEqual([])
    expect(
      fetchMock.mock.calls.some(
        ([, init]) => (init as RequestInit | undefined)?.method === 'PATCH',
      ),
    ).toBe(false)
  })

  it('asks before disabling an OIDC realm; sends nothing until confirmed', async () => {
    const patches: Array<{ id: number; body: unknown }> = []
    mockApi({
      realms: threeRealms,
      onPatch: (id, body) => {
        patches.push({ id, body })
        return json(realm({ id: 5, kind: 'oidc', enabled: false }))
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms')

    const toggle = await screen.findByRole('checkbox', { name: 'corp-sso enabled' })
    await u.click(toggle)

    const row = toggle.closest('tr')!
    expect(
      within(row).getByText(/stops sign-in through its identity provider/),
    ).toHaveTextContent('people who use it can no longer sign in to Forge')
    expect(toggle).toBeChecked()

    await u.click(within(row).getByRole('button', { name: 'Cancel' }))
    expect(within(row).queryByText(/stops sign-in/)).toBeNull()
    expect(patches).toEqual([])

    await u.click(toggle)
    expect(patches).toEqual([])
    await u.click(within(row).getByRole('button', { name: 'Disable' }))

    await waitFor(() =>
      expect(patches).toEqual([{ id: 5, body: { enabled: false } }]),
    )
  })

  it('asks before disabling a credential-forwarding realm', async () => {
    mockApi({
      realms: [
        realm({ id: 1, kind: 'local', name: 'local', priority: 0 }),
        realm({
          id: 3,
          kind: 'credential_forwarding',
          name: 'legacy-auth',
          priority: 1,
          config: { url: 'https://auth.example.com/check', key_pepper_set: true },
        }),
      ],
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms')

    const toggle = await screen.findByRole('checkbox', { name: 'legacy-auth enabled' })
    await u.click(toggle)

    const row = toggle.closest('tr')!
    expect(
      within(row).getByText(/stops the logins it checks against its upstream/),
    ).toHaveTextContent('NuGet clients sending those passwords over Basic')
    expect(
      fetchMock.mock.calls.some(
        ([, init]) => (init as RequestInit | undefined)?.method === 'PATCH',
      ),
    ).toBe(false)
  })

  it('shows the server refusal after disabling local is confirmed', async () => {
    let patched: { id: number; body: unknown } | null = null
    mockApi({
      realms: threeRealms,
      onPatch: (id, body) => {
        patched = { id, body }
        return new Response(
          'no enabled realm to sign in with would remain (local or OIDC); enable another one first',
          { status: 409 },
        )
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms')

    const toggle = await screen.findByRole('checkbox', { name: 'local enabled' })
    await u.click(toggle)
    const row = toggle.closest('tr')!
    await u.click(within(row).getByRole('button', { name: 'Disable' }))

    await waitFor(() =>
      expect(patched).toEqual({ id: 1, body: { enabled: false } }),
    )
    expect(await within(row).findByRole('alert')).toHaveTextContent(
      'Could not disable local: no enabled realm to sign in with would remain (local or OIDC); enable another one first',
    )
    // The checkbox still shows the stored state, and the question is gone.
    expect(toggle).toBeChecked()
    expect(within(row).queryByText(/stops every password login/)).toBeNull()
  })

  it('shows the server refusal when a delete would leave no sign-in realm', async () => {
    mockApi({
      realms: threeRealms,
      onDelete: () =>
        new Response(
          'no enabled realm to sign in with would remain (local or OIDC); enable another one first',
          { status: 409 },
        ),
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms')

    const row = (await screen.findByText('corp-sso')).closest('tr')!
    await u.click(within(row).getByRole('button', { name: 'Delete' }))
    await u.click(within(row).getByRole('button', { name: 'Confirm' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'no enabled realm to sign in with would remain (local or OIDC); enable another one first',
    )
    expect(screen.getByText('corp-sso')).toBeInTheDocument()
  })

  it('delete asks for confirmation then DELETEs', async () => {
    let deleted: number | null = null
    mockApi({
      realms: threeRealms,
      onDelete: (id) => {
        deleted = id
        return new Response(null, { status: 204 })
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms')

    const row = (await screen.findByText('legacy-auth')).closest('tr')!
    await u.click(within(row).getByRole('button', { name: 'Delete' }))
    await u.click(within(row).getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(deleted).toBe(3))
  })
})

// Typing-heavy form tests can outlast the 5 s default on a loaded machine.
describe('admin realms create', { timeout: 20_000 }, () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('validates required oidc fields inline and does not POST', async () => {
    let posted: unknown = null
    mockApi({
      realms: [],
      onCreate: (body) => {
        posted = body
        return json(realm(body as Partial<RealmView>), 201)
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/new')

    // kind defaults to oidc; submit the empty form.
    await u.click(await screen.findByRole('button', { name: 'Create realm' }))

    expect(await screen.findByText('A realm name is required.')).toBeInTheDocument()
    expect(screen.getByText('An issuer URL is required.')).toBeInTheDocument()
    expect(screen.getByText('A client ID is required.')).toBeInTheDocument()
    expect(screen.getByText('A client secret is required.')).toBeInTheDocument()
    expect(posted).toBeNull()
  })

  it('POSTs an oidc realm with parsed list fields', async () => {
    let posted: unknown = null
    mockApi({
      realms: [],
      onCreate: (body) => {
        posted = body
        return json(realm({ id: 9, kind: 'oidc', name: 'corp' }), 201)
      },
    })

    const u = userEvent.setup()
    const router = await renderAt('/manage/realms/new')

    await u.type(await screen.findByLabelText('Name'), 'corp')
    await u.type(screen.getByLabelText('Issuer URL'), 'https://idp.example.com')
    await u.type(screen.getByLabelText('Client ID'), 'forge')
    await u.type(screen.getByLabelText('Client secret'), 's3cret')
    await u.type(
      screen.getByLabelText('Login domains'),
      'example.com{Enter}corp.example.com',
    )
    await u.click(screen.getByRole('button', { name: 'Create realm' }))

    await waitFor(() => expect(posted).not.toBeNull())
    expect(posted).toEqual({
      kind: 'oidc',
      name: 'corp',
      enabled: true,
      config: {
        issuer: 'https://idp.example.com',
        client_id: 'forge',
        client_secret: 's3cret',
        auto_provision: true,
        link_existing_by_username: false,
        allow_http_issuer: false,
        login_domains: ['example.com', 'corp.example.com'],
      },
    })
    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/manage/realms'),
    )
  })

  it('switching to credential_forwarding swaps the form and parses status lists', async () => {
    let posted: unknown = null
    mockApi({
      realms: [],
      onCreate: (body) => {
        posted = body
        return json(realm({ id: 9, kind: 'credential_forwarding' }), 201)
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/new')

    await u.selectOptions(await screen.findByLabelText('Kind'), 'credential_forwarding')
    expect(screen.queryByLabelText('Issuer URL')).not.toBeInTheDocument()

    await u.type(screen.getByLabelText('Name'), 'legacy')
    await u.type(screen.getByLabelText('Upstream URL'), 'https://auth.example.com/check')
    await u.type(screen.getByLabelText('Success statuses'), '200, 204')
    await u.type(screen.getByLabelText('Key pepper'), 'pepper-1')
    await u.click(screen.getByRole('button', { name: 'Create realm' }))

    await waitFor(() => expect(posted).not.toBeNull())
    expect(posted).toEqual({
      kind: 'credential_forwarding',
      name: 'legacy',
      enabled: true,
      config: {
        url: 'https://auth.example.com/check',
        auto_provision: true,
        success_status: [200, 204],
        key_pepper: 'pepper-1',
      },
    })
  })

  it('switching to workload_identity builds the rules config', async () => {
    let posted: unknown = null
    mockApi({
      realms: [],
      onCreate: (body) => {
        posted = body
        return json(realm({ id: 9, kind: 'workload_identity' }), 201)
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/new')

    await u.selectOptions(
      await screen.findByLabelText('Kind'),
      'workload_identity',
    )
    expect(screen.queryByLabelText('Client ID')).not.toBeInTheDocument()

    await u.type(screen.getByLabelText('Name'), 'wif')
    await u.type(
      screen.getByLabelText('Issuer URL'),
      'https://token.actions.githubusercontent.com',
    )
    await u.type(
      screen.getByLabelText('Allowed audiences'),
      'https://forge.example.com',
    )

    // A newly added rule starts with one mandatory condition.
    await u.click(screen.getByRole('button', { name: 'Add rule' }))
    await u.type(screen.getByLabelText('Role'), 'ci-deployer')
    await u.type(screen.getByLabelText('Claim'), 'repository_id')
    await u.type(screen.getByLabelText('Any of'), '987654321')
    await u.click(screen.getByRole('button', { name: 'Add condition' }))
    await u.type(screen.getAllByLabelText('Claim')[1], 'repository_owner_id')
    await u.type(screen.getAllByLabelText('Any of')[1], '1234567')

    await u.click(screen.getByRole('button', { name: 'Create realm' }))

    await waitFor(() => expect(posted).not.toBeNull())
    expect(posted).toEqual({
      kind: 'workload_identity',
      name: 'wif',
      enabled: true,
      config: {
        issuer: 'https://token.actions.githubusercontent.com',
        allowed_audiences: ['https://forge.example.com'],
        allow_http_issuer: false,
        rules: [
          {
            role: 'ci-deployer',
            conditions: [
              { claim: 'repository_id', any_of: ['987654321'] },
              { claim: 'repository_owner_id', any_of: ['1234567'] },
            ],
          },
        ],
      },
    })
  })

  it('validates required workload_identity fields inline and does not POST', async () => {
    let posted: unknown = null
    mockApi({
      realms: [],
      onCreate: (body) => {
        posted = body
        return json(realm(body as Partial<RealmView>), 201)
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/new')

    await u.selectOptions(
      await screen.findByLabelText('Kind'),
      'workload_identity',
    )
    await u.click(screen.getByRole('button', { name: 'Create realm' }))

    expect(
      await screen.findByText('At least one allowed audience is required.'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('At least one rule is required.'),
    ).toBeInTheDocument()
    expect(posted).toBeNull()
  })

  it('rejects a GitHub workload rule scoped only by execution context', async () => {
    let posted: unknown = null
    mockApi({
      realms: [],
      onCreate: (body) => {
        posted = body
        return json(realm(body as Partial<RealmView>), 201)
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/new')
    await u.selectOptions(
      await screen.findByLabelText('Kind'),
      'workload_identity',
    )
    await u.type(screen.getByLabelText('Name'), 'github-actions')
    await u.type(
      screen.getByLabelText('Issuer URL'),
      'https://token.actions.githubusercontent.com',
    )
    await u.type(
      screen.getByLabelText('Allowed audiences'),
      'https://forge.example.com',
    )
    await u.click(screen.getByRole('button', { name: 'Add rule' }))
    await u.type(screen.getByLabelText('Role'), 'publisher')
    await u.type(screen.getByLabelText('Claim'), 'ref')
    await u.type(screen.getByLabelText('Any of'), 'refs/heads/main')
    await u.click(screen.getByRole('button', { name: 'Create realm' }))

    expect(
      await screen.findByText(
        'GitHub Actions rules must include both repository_id and repository_owner_id.',
      ),
    ).toBeInTheDocument()
    expect(posted).toBeNull()
  })

  it('surfaces a server 400 inline', async () => {
    mockApi({
      realms: [],
      onCreate: () => new Response('invalid config: key_pepper is required', { status: 400 }),
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/new')

    await u.type(await screen.findByLabelText('Name'), 'corp')
    await u.type(screen.getByLabelText('Issuer URL'), 'https://idp.example.com')
    await u.type(screen.getByLabelText('Client ID'), 'forge')
    await u.type(screen.getByLabelText('Client secret'), 's3cret')
    await u.click(screen.getByRole('button', { name: 'Create realm' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'invalid config: key_pepper is required',
    )
  })
})

describe('admin realms edit', { timeout: 20_000 }, () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  const adminsDn = 'CN=Forge Admins,OU=Groups,DC=corp'
  const usersDn = 'CN=Forge Users,OU=Groups,DC=corp'
  const corpSso = realm({
    id: 5,
    kind: 'oidc',
    name: 'corp-sso',
    priority: 1,
    config: {
      issuer: 'https://idp.example.com',
      client_id: 'forge',
      client_secret_set: true,
      auto_provision: true,
      link_existing_by_username: false,
      allow_http_issuer: false,
      admin_groups: [adminsDn, 'forge-ops'],
      required_claims: { groups: [usersDn] },
    },
  })

  it('saves list values containing commas unchanged', async () => {
    let patched: unknown = null
    mockApi({
      realms: [corpSso],
      onPatch: (_id, body) => {
        patched = body
        return json(corpSso)
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/5')

    expect(await screen.findByLabelText('Admin groups')).toHaveValue(
      `${adminsDn}\nforge-ops`,
    )
    expect(screen.getByLabelText('Required claims')).toHaveValue(
      `groups = ${usersDn}`,
    )

    // Edit an unrelated field, then save.
    await u.type(screen.getByLabelText('Button label'), 'Corp SSO')
    await u.click(screen.getByRole('button', { name: 'Save changes' }))

    await waitFor(() => expect(patched).not.toBeNull())
    expect(patched).toEqual({
      name: 'corp-sso',
      enabled: true,
      config: {
        issuer: 'https://idp.example.com',
        client_id: 'forge',
        auto_provision: true,
        link_existing_by_username: false,
        allow_http_issuer: false,
        admin_groups: [adminsDn, 'forge-ops'],
        required_claims: { groups: [usersDn] },
        button_label: 'Corp SSO',
      },
    })
  })

  const nexus = realm({
    id: 3,
    kind: 'credential_forwarding',
    name: 'nexus',
    priority: 2,
    config: {
      url: 'https://nexus.example.com/status',
      key_pepper_set: true,
      auto_provision: true,
      capture_password_hash: true,
    },
  })

  it('stops forwarding only while hashes are kept', async () => {
    let patched: { config?: Record<string, unknown> } | null = null
    mockApi({
      realms: [nexus],
      onPatch: (_id, body) => {
        patched = body as typeof patched
        return json(nexus)
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/3')

    const keep = await screen.findByRole('checkbox', {
      name: 'Keep a password hash of successful logins',
    })
    const only = screen.getByRole('checkbox', {
      name: 'Stop forwarding: sign in with kept passwords only',
    })
    expect(keep).toBeChecked()
    await u.click(only)
    await u.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(patched).not.toBeNull())
    expect(patched!.config).toMatchObject({
      capture_password_hash: true,
      captured_password_only: true,
    })

    // Without kept hashes there is nothing to sign in with.
    await u.click(keep)
    expect(only).not.toBeChecked()
    expect(only).toHaveAttribute('aria-disabled', 'true')
  })

  it('switches the accounts with a kept password to local ones after confirming', async () => {
    let counts = { accounts: 3, captured: 2 }
    let converted: number | null = null
    mockApi({
      realms: [nexus],
      capturedPasswords: () => counts,
      onConvert: (id) => {
        converted = id
        counts = { accounts: 1, captured: 0 }
        return json({ converted: 2, remaining: 1 })
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/3')

    expect(
      await screen.findByText(/2 of 3 accounts keep a password hash/),
    ).toBeInTheDocument()
    await u.click(
      screen.getByRole('button', { name: 'Switch accounts to local passwords…' }),
    )
    expect(converted).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Switch 2 to local passwords' }))

    await waitFor(() => expect(converted).toBe(3))
    expect(await screen.findByRole('status')).toHaveTextContent(
      'Switched 2 to local passwords; 1 left on this realm.',
    )
    expect(
      await screen.findByText(/0 of 1 account keeps a password hash/),
    ).toBeInTheDocument()
  })

  it('requires a new client secret after the issuer changes', async () => {
    let patched: unknown = null
    mockApi({
      realms: [corpSso],
      onPatch: (_id, body) => {
        patched = body
        return json(corpSso)
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/5')

    const secret = await screen.findByLabelText('Client secret')
    expect(secret).toHaveAttribute('placeholder', '•••••••• (set to replace)')
    expect(screen.queryByRole('status')).toBeNull()

    // A trailing slash is not a different issuer.
    await u.type(screen.getByLabelText('Issuer URL'), '/')
    expect(screen.queryByRole('status')).toBeNull()

    const issuer = screen.getByLabelText('Issuer URL')
    await u.clear(issuer)
    await u.type(issuer, 'https://login.example.org')
    expect(screen.getByRole('status')).toHaveTextContent(
      'The stored client secret will be dropped when you save',
    )
    expect(secret).toHaveAttribute('placeholder', 'Required')
    expect(screen.queryByText(/Leave blank to keep it/)).toBeNull()

    await u.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(
      await screen.findByText(
        'Enter the client secret for the new issuer or client ID.',
      ),
    ).toBeInTheDocument()
    expect(patched).toBeNull()

    await u.type(secret, 'new-s3cret')
    await u.click(screen.getByRole('button', { name: 'Save changes' }))

    await waitFor(() => expect(patched).not.toBeNull())
    expect(patched).toMatchObject({
      config: {
        issuer: 'https://login.example.org',
        client_id: 'forge',
        client_secret: 'new-s3cret',
      },
    })
  })

  it('asks before saving local disabled; sends nothing until confirmed', async () => {
    const local = realm({ id: 1, kind: 'local', name: 'local' })
    const patches: unknown[] = []
    mockApi({
      realms: [local],
      onPatch: (_id, body) => {
        patches.push(body)
        return json({ ...local, enabled: false })
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/1')

    await u.click(await screen.findByRole('checkbox', { name: /Enabled/ }))
    await u.click(screen.getByRole('button', { name: 'Save changes' }))

    expect(screen.getByText(/stops every password login/)).toBeInTheDocument()
    expect(patches).toEqual([])

    // Cancel keeps the form as it is and sends nothing.
    await u.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByText(/stops every password login/)).toBeNull()
    expect(screen.getByRole('checkbox', { name: /Enabled/ })).not.toBeChecked()
    expect(patches).toEqual([])

    await u.click(screen.getByRole('button', { name: 'Save changes' }))
    await u.click(screen.getByRole('button', { name: 'Disable and save' }))

    await waitFor(() =>
      expect(patches).toEqual([{ name: 'local', enabled: false }]),
    )
  })

  it('asks before saving an OIDC realm disabled', async () => {
    let patched: unknown = null
    mockApi({
      realms: [corpSso],
      onPatch: (_id, body) => {
        patched = body
        return json({ ...corpSso, enabled: false })
      },
    })

    const u = userEvent.setup()
    await renderAt('/manage/realms/5')

    await u.click(await screen.findByRole('checkbox', { name: /Enabled/ }))
    await u.click(screen.getByRole('button', { name: 'Save changes' }))

    expect(
      screen.getByText(/stops sign-in through its identity provider/),
    ).toBeInTheDocument()
    expect(patched).toBeNull()

    await u.click(screen.getByRole('button', { name: 'Disable and save' }))

    await waitFor(() => expect(patched).not.toBeNull())
    expect(patched).toMatchObject({ name: 'corp-sso', enabled: false })
  })

  it('requires a new client secret after the client ID changes', async () => {
    mockApi({ realms: [corpSso] })

    const u = userEvent.setup()
    await renderAt('/manage/realms/5')

    await u.type(await screen.findByLabelText('Client ID'), '-v2')
    expect(screen.getByRole('status')).toHaveTextContent(
      'The issuer or client ID differs from the stored one.',
    )
    expect(screen.getByLabelText('Client secret')).toHaveAttribute(
      'placeholder',
      'Required',
    )
  })
})
