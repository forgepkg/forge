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
import { clearToken, setToken } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { RealmView } from '~/api/realms'
import { routeTree } from '~/routeTree.gen'

/**
 * Admin authentication-realms screens (§12.7), driven against the real route
 * tree + query hooks so the admin guard, routing, and mutations are exercised:
 *  - the list renders realms in priority order with kind badges and hides the
 *    delete affordance for the built-in local realm;
 *  - reordering PUTs the **full** new id order to /admin/realms/order;
 *  - the enabled toggle PATCHes the realm;
 *  - the create form validates required fields per kind (no POST when
 *    invalid) and POSTs the parsed config when valid.
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
    setToken('admin-token')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearToken()
  })

  it('renders realms in priority order with kind badges; local has no delete', async () => {
    mockApi({ realms: threeRealms })

    await renderAt('/admin/realms')

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
    await renderAt('/admin/realms')

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
    await renderAt('/admin/realms')

    await u.click(
      await screen.findByRole('checkbox', { name: 'legacy-auth enabled' }),
    )

    await waitFor(() =>
      expect(patched).toEqual({ id: 3, body: { enabled: true } }),
    )
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
    await renderAt('/admin/realms')

    const row = (await screen.findByText('legacy-auth')).closest('tr')!
    await u.click(within(row).getByRole('button', { name: 'Delete' }))
    await u.click(within(row).getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(deleted).toBe(3))
  })
})

describe('admin realms create', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setToken('admin-token')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearToken()
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
    await renderAt('/admin/realms/new')

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
    const router = await renderAt('/admin/realms/new')

    await u.type(await screen.findByLabelText('Name'), 'corp')
    await u.type(screen.getByLabelText('Issuer URL'), 'https://idp.example.com')
    await u.type(screen.getByLabelText('Client ID'), 'forge')
    await u.type(screen.getByLabelText('Client secret'), 's3cret')
    await u.type(screen.getByLabelText('Login domains'), 'example.com, corp.example.com')
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
      expect(router.state.location.pathname).toBe('/admin/realms'),
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
    await renderAt('/admin/realms/new')

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

  it('surfaces a server 400 inline', async () => {
    mockApi({
      realms: [],
      onCreate: () => new Response('invalid config: key_pepper is required', { status: 400 }),
    })

    const u = userEvent.setup()
    await renderAt('/admin/realms/new')

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
