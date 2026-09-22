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
import type { MemberView, RepoView } from '~/api/repositories'
import { routeTree } from '~/routeTree.gen'

/**
 * Admin repositories screens (plan §Phase 4 testing), driven against the **real**
 * route tree + query hooks so the admin guard, routing, and mutations are all
 * exercised:
 *  - the list renders repositories;
 *  - create-hosted POSTs the right body to `/admin/repositories`;
 *  - the group members editor prevents a duplicate priority before any request.
 */

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

function repo(over: Partial<RepoView>): RepoView {
  return {
    id: 1,
    name: 'hosted-1',
    format: 'nuget',
    kind: 'hosted',
    anonymous_read: false,
    online: true,
    remote_url: null,
    package_delay_seconds: 0,
    upstream_username: null,
    has_upstream_password: false,
    metadata_ttl_seconds: null,
    not_found_ttl_seconds: null,
    allow_redeploy: false,
    prefer_hosted: false,
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
  repositories?: RepoView[]
  members?: MemberView[]
  onCreate?: (body: unknown) => Response
  onAddMember?: (body: unknown) => Response
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

      if (path.endsWith('/admin/repositories') && method === 'GET') {
        return Promise.resolve(json(h.repositories ?? []))
      }
      if (path.endsWith('/admin/repositories') && method === 'POST') {
        const body = init?.body ? JSON.parse(init.body as string) : {}
        return Promise.resolve(
          h.onCreate ? h.onCreate(body) : json(repo(body), 201),
        )
      }
      if (path.endsWith('/members') && method === 'GET') {
        return Promise.resolve(json(h.members ?? []))
      }
      if (path.endsWith('/members') && method === 'POST') {
        const body = init?.body ? JSON.parse(init.body as string) : {}
        return Promise.resolve(
          h.onAddMember ? h.onAddMember(body) : json(null, 201),
        )
      }
      // A single repo GET (edit screen) — return the first repo.
      const m = path.match(/\/admin\/repositories\/([^/]+)$/)
      if (m && method === 'GET') {
        const name = decodeURIComponent(m[1])
        const found = (h.repositories ?? []).find((r) => r.name === name)
        return Promise.resolve(found ? json(found) : json('nope', 404))
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

describe('admin repositories', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('lists repositories with their kind and status', async () => {
    mockApi({
      repositories: [
        repo({ id: 1, name: 'hosted-1', kind: 'hosted' }),
        repo({ id: 2, name: 'proxy-1', kind: 'proxy', online: false }),
      ],
    })

    await renderAt('/admin/repositories')

    expect(await screen.findByText('hosted-1')).toBeInTheDocument()
    expect(screen.getByText('proxy-1')).toBeInTheDocument()
    expect(screen.getByText('offline')).toBeInTheDocument()
  })

  it('create-hosted POSTs the right body', async () => {
    let posted: unknown = null
    mockApi({
      repositories: [],
      onCreate: (body) => {
        posted = body
        return json(repo({ name: (body as RepoView).name }), 201)
      },
    })

    const user = userEvent.setup()
    await renderAt('/admin/repositories/new')

    await user.type(await screen.findByLabelText('Name'), 'brand-new')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))

    await waitFor(() => expect(posted).not.toBeNull())
    expect(posted).toMatchObject({ name: 'brand-new', kind: 'hosted' })
    expect(posted).not.toHaveProperty('remote_url')
  })

  it('group members editor blocks a duplicate priority before requesting', async () => {
    let addCalled = false
    mockApi({
      repositories: [
        repo({ id: 1, name: 'grp', kind: 'group' }),
        repo({ id: 2, name: 'inner', kind: 'hosted' }),
      ],
      members: [{ name: 'existing', kind: 'hosted', priority: 100 }],
      onAddMember: () => {
        addCalled = true
        return json(null, 201)
      },
    })

    const user = userEvent.setup()
    await renderAt('/admin/repositories/grp/members')

    // The existing member is shown with its priority.
    expect(await screen.findByText('existing')).toBeInTheDocument()

    // Pick the candidate and reuse the existing priority (100) → blocked.
    await user.selectOptions(screen.getByLabelText('Repository'), 'inner')
    const priority = screen.getByLabelText('Priority')
    await user.clear(priority)
    await user.type(priority, '100')
    await user.click(screen.getByRole('button', { name: 'Add member' }))

    expect(
      await screen.findByText('Priority 100 is already used in this group.'),
    ).toBeInTheDocument()
    expect(addCalled).toBe(false)
  })

  it('group members editor adds a member with a unique priority', async () => {
    let posted: unknown = null
    mockApi({
      repositories: [
        repo({ id: 1, name: 'grp', kind: 'group' }),
        repo({ id: 2, name: 'inner', kind: 'hosted' }),
      ],
      members: [{ name: 'existing', kind: 'hosted', priority: 100 }],
      onAddMember: (body) => {
        posted = body
        return json(null, 201)
      },
    })

    const user = userEvent.setup()
    await renderAt('/admin/repositories/grp/members')

    await user.selectOptions(
      await screen.findByLabelText('Repository'),
      'inner',
    )
    const priority = screen.getByLabelText('Priority')
    await user.clear(priority)
    await user.type(priority, '50')
    await user.click(screen.getByRole('button', { name: 'Add member' }))

    await waitFor(() => expect(posted).not.toBeNull())
    expect(posted).toEqual({ member: 'inner', priority: 50 })
  })
})
