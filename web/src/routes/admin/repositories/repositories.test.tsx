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
 *  - the group members editor prevents a duplicate priority before any request,
 *    toggles a member's owner flag, explains a refused owner removal, and
 *    offers other groups as (nested) members.
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
    reserved_prefixes: [],
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
  onUpdate?: (name: string, body: unknown) => Response
  onAddMember?: (body: unknown) => Response
  onPatchMember?: (member: string, body: unknown) => Response
  onRemoveMember?: (member: string) => Response
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
      const memberMatch = path.match(/\/members\/([^/]+)$/)
      if (memberMatch && method === 'PATCH') {
        const member = decodeURIComponent(memberMatch[1])
        const body = init?.body ? JSON.parse(init.body as string) : {}
        return Promise.resolve(
          h.onPatchMember
            ? h.onPatchMember(member, body)
            : new Response(null, { status: 204 }),
        )
      }
      if (memberMatch && method === 'DELETE') {
        const member = decodeURIComponent(memberMatch[1])
        return Promise.resolve(
          h.onRemoveMember
            ? h.onRemoveMember(member)
            : new Response(null, { status: 204 }),
        )
      }
      // A single repo GET (edit screen) — return the first repo.
      const m = path.match(/\/admin\/repositories\/([^/]+)$/)
      if (m && method === 'GET') {
        const name = decodeURIComponent(m[1])
        const found = (h.repositories ?? []).find((r) => r.name === name)
        return Promise.resolve(found ? json(found) : json('nope', 404))
      }
      if (m && method === 'PUT') {
        const name = decodeURIComponent(m[1])
        const body = init?.body ? JSON.parse(init.body as string) : {}
        const found = (h.repositories ?? []).find((r) => r.name === name)
        return Promise.resolve(
          h.onUpdate ? h.onUpdate(name, body) : json({ ...found, ...body }),
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

    await renderAt('/manage/repositories')

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
    await renderAt('/manage/repositories/new')

    await user.type(await screen.findByLabelText('Name'), 'brand-new')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))

    await waitFor(() => expect(posted).not.toBeNull())
    expect(posted).toMatchObject({ name: 'brand-new', kind: 'hosted' })
    expect(posted).not.toHaveProperty('remote_url')
  })

  it('create blocks an invalid repository name before requesting', async () => {
    let posted = false
    mockApi({
      repositories: [],
      onCreate: () => {
        posted = true
        return json(repo({}), 201)
      },
    })

    const user = userEvent.setup()
    await renderAt('/manage/repositories/new')

    await user.type(await screen.findByLabelText('Name'), 'Team Packages')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/no spaces/)
    expect(posted).toBe(false)
  })

  it('edit PUTs only what changed; "Remove stored credentials" sends explicit nulls', async () => {
    const stored = repo({
      id: 7,
      name: 'private-feed',
      kind: 'proxy',
      remote_url: 'https://pkgs.example.com/v3/index.json',
      upstream_username: 'svc',
      has_upstream_password: true,
      metadata_ttl_seconds: 600,
    })
    const puts: unknown[] = []
    mockApi({
      repositories: [stored],
      onUpdate: (_name, body) => {
        puts.push(body)
        const b = body as Record<string, unknown>
        const cleared = b.upstream_password === null
        return json({
          ...stored,
          upstream_username: cleared ? null : stored.upstream_username,
          has_upstream_password: !cleared && stored.has_upstream_password,
        })
      },
    })

    const user = userEvent.setup()
    await renderAt('/manage/repositories/private-feed')

    // An untouched save sends nothing that could clear stored values.
    await user.click(await screen.findByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0]).toEqual({})

    await user.click(
      await screen.findByRole('button', { name: 'Remove stored credentials' }),
    )
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(puts).toHaveLength(2))
    expect(puts[1]).toEqual({ upstream_username: null, upstream_password: null })

    // The form is re-seeded from the saved view: nothing left to remove.
    await waitFor(() =>
      expect(
        screen.queryByRole('button', { name: 'Remove stored credentials' }),
      ).toBeNull(),
    )
    expect(screen.getByLabelText('Upstream username')).toBeEnabled()
  })

  it('group members editor blocks a duplicate priority before requesting', async () => {
    let addCalled = false
    mockApi({
      repositories: [
        repo({ id: 1, name: 'grp', kind: 'group' }),
        repo({ id: 2, name: 'inner', kind: 'hosted' }),
      ],
      members: [
        { name: 'existing', kind: 'hosted', priority: 100, owner: false },
        { name: 'releases', kind: 'hosted', priority: 50, owner: true },
      ],
      onAddMember: () => {
        addCalled = true
        return json(null, 201)
      },
    })

    const user = userEvent.setup()
    await renderAt('/manage/repositories/grp/members')

    // The existing member is shown with its priority, and an owner is marked.
    expect(await screen.findByText('existing')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'existing owner' })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'releases owner' })).toBeChecked()

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
      members: [{ name: 'existing', kind: 'hosted', priority: 100, owner: false }],
      onAddMember: (body) => {
        posted = body
        return json(null, 201)
      },
    })

    const user = userEvent.setup()
    await renderAt('/manage/repositories/grp/members')

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

  it('the owner toggle PATCHes the member and re-fetches the list', async () => {
    const patches: Array<{ member: string; body: unknown }> = []
    const members: MemberView[] = [
      { name: 'existing', kind: 'hosted', priority: 100, owner: false },
      { name: 'releases', kind: 'hosted', priority: 50, owner: true },
      { name: 'nuget-org', kind: 'proxy', priority: 10, owner: false },
    ]
    const handlers: ApiHandlers = {
      repositories: [repo({ id: 1, name: 'grp', kind: 'group' })],
      members,
      onPatchMember: (member, body) => {
        patches.push({ member, body })
        mockApi({
          ...handlers,
          members: members.map((m) =>
            m.name === member ? { ...m, ...(body as { owner: boolean }) } : m,
          ),
        })
        return new Response(null, { status: 204 })
      },
    }
    mockApi(handlers)

    const user = userEvent.setup()
    await renderAt('/manage/repositories/grp/members')

    const toggle = await screen.findByRole('checkbox', { name: 'existing owner' })
    // A proxy cannot own package ids, so its toggle is off.
    expect(screen.getByRole('checkbox', { name: 'nuget-org owner' })).toHaveAttribute(
      'aria-disabled',
      'true',
    )

    await user.click(toggle)
    await waitFor(() =>
      expect(patches).toEqual([{ member: 'existing', body: { owner: true } }]),
    )
    await waitFor(() => expect(toggle).toBeChecked())

    await user.click(screen.getByRole('checkbox', { name: 'releases owner' }))
    await waitFor(() =>
      expect(patches[1]).toEqual({ member: 'releases', body: { owner: false } }),
    )
  })

  it('shows the server error when the owner toggle is refused', async () => {
    mockApi({
      repositories: [repo({ id: 1, name: 'grp', kind: 'group' })],
      members: [{ name: 'existing', kind: 'hosted', priority: 100, owner: false }],
      onPatchMember: () => new Response('membership not found', { status: 404 }),
    })

    const user = userEvent.setup()
    await renderAt('/manage/repositories/grp/members')

    const toggle = await screen.findByRole('checkbox', { name: 'existing owner' })
    await user.click(toggle)

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Could not flag existing as owner: membership not found',
    )
    expect(toggle).not.toBeChecked()
  })

  it('removing an owner shows the 409 reason with a hint to unflag it', async () => {
    let removed: string | null = null
    mockApi({
      repositories: [repo({ id: 1, name: 'grp', kind: 'group' })],
      members: [{ name: 'releases', kind: 'hosted', priority: 50, owner: true }],
      onRemoveMember: (member) => {
        removed = member
        return new Response(
          "this member owns the group's package ids; unflag it as owner before removing it",
          { status: 409 },
        )
      },
    })

    const user = userEvent.setup()
    await renderAt('/manage/repositories/grp/members')

    await user.click(await screen.findByRole('button', { name: 'Remove' }))

    await waitFor(() => expect(removed).toBe('releases'))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      "this member owns the group's package ids; unflag it as owner before removing it Clear the owner box of releases first, then remove it.",
    )
    expect(screen.getByText('releases')).toBeInTheDocument()
  })

  it('offers other groups as members and shows a refused nesting', async () => {
    let posted: unknown = null
    mockApi({
      repositories: [
        repo({ id: 1, name: 'grp', kind: 'group' }),
        repo({ id: 2, name: 'inner', kind: 'hosted' }),
        repo({ id: 3, name: 'outer', kind: 'group' }),
      ],
      members: [],
      onAddMember: (body) => {
        posted = body
        return new Response(
          'adding this member would create a cycle in the group graph',
          { status: 409 },
        )
      },
    })

    const user = userEvent.setup()
    await renderAt('/manage/repositories/grp/members')

    const select = await screen.findByLabelText('Repository')
    await waitFor(() =>
      expect(
        Array.from((select as HTMLSelectElement).options).map((o) => o.value),
      ).toEqual(['', 'inner', 'outer']),
    )
    // The group itself is never a candidate.
    expect(screen.queryByRole('option', { name: 'grp (group)' })).toBeNull()

    await user.selectOptions(select, 'outer')
    await user.click(screen.getByRole('button', { name: 'Add member' }))

    await waitFor(() => expect(posted).toEqual({ member: 'outer', priority: 100 }))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'adding this member would create a cycle in the group graph',
    )
  })

  it('says why no repository can be added, without claiming groups cannot nest', async () => {
    mockApi({
      repositories: [
        repo({ id: 1, name: 'grp', kind: 'group' }),
        repo({ id: 2, name: 'inner', kind: 'hosted' }),
      ],
      members: [{ name: 'inner', kind: 'hosted', priority: 100, owner: false }],
    })

    await renderAt('/manage/repositories/grp/members')

    expect(
      await screen.findByText(/No eligible repositories to add/),
    ).not.toHaveTextContent(/nested/)
  })
})
