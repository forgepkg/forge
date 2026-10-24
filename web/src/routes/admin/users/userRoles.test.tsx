import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import { FakeRbacApi, repo, token, user } from '~/test/fakeRbacApi'
import { renderApp } from '~/test/renderApp'

/**
 * Roles, effective access and token scopes on the admin user screens,
 * against the real route tree and a stateful fake of the RBAC API:
 *  - the user list shows each user's access level (admin, writer or reader)
 *    from their role assignments and their other roles, and the create page
 *    gives a new user its access level;
 *  - the user page switches the access level, assigns and removes roles,
 *    shows the 409 for the last administrator, and lists the effective
 *    access with repository and selector names;
 *  - tokens are created with a scope, and an admin changes a token's scope.
 */

let api: FakeRbacApi

describe('admin user roles', () => {
  beforeEach(() => {
    api = new FakeRbacApi({
      users: [
        user({ id: 1, username: 'root', is_admin: true }),
        user({ id: 2, username: 'alice' }),
        user({ id: 3, username: 'legacy', is_admin: true }),
        user({ id: 4, username: 'publisher' }),
      ],
      repos: [repo({ id: 10, name: 'internal' }), repo({ id: 11, name: 'public' })],
      selectors: [
        { id: 20, name: 'acme', description: '', includes: ['acme.*'], excludes: [] },
      ],
    })
    api.state.roles.push({ id: 7, name: 'ci-pushers', description: 'CI pushes', builtin: false })
    api.state.assignments.push([1, 1], [2, 7], [4, 4])
    api.state.grants.push(
      { id: 30, role_id: 7, repository_id: 10, level: 'write', selector_id: null },
      { id: 31, role_id: 7, repository_id: null, level: 'read', selector_id: 20 },
    )
    vi.stubGlobal('fetch', vi.fn(api.fetch))
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it("lists each user's access level from their roles, and their other roles", async () => {
    await renderApp('/manage/users')

    const row = (name: string) =>
      screen.getByRole('link', { name }).closest('tr')!
    const cells = (name: string) => within(row(name)).getAllByRole('cell')
    await screen.findByRole('link', { name: 'alice' })
    expect(screen.getByRole('columnheader', { name: 'Access' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Roles' })).toBeInTheDocument()

    await waitFor(() => expect(cells('publisher')[2]).toHaveTextContent('writer'))
    expect(cells('root')[2]).toHaveTextContent('admin')
    expect(cells('alice')[2]).toHaveTextContent('reader')
    // The legacy flag without the role still makes an administrator.
    expect(cells('legacy')[2]).toHaveTextContent('admin')
    expect(within(row('legacy')).getByText('admin (flag)')).toBeInTheDocument()

    // A custom role is listed with a link to it; the access level's role is
    // not listed twice.
    await waitFor(() =>
      expect(within(cells('alice')[3]).getByRole('link', { name: 'ci-pushers' })).toHaveAttribute(
        'href',
        '/manage/roles/7',
      ),
    )
    expect(cells('root')[3]).toHaveTextContent('—')
    expect(cells('publisher')[3]).toHaveTextContent('—')
  })

  it('switches a user between reader, writer and admin', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/users/2')

    const form = await screen.findByRole('form', { name: 'Change access' })
    expect(within(form).getByRole('radio', { name: /^Reader/ })).toBeChecked()
    expect(within(form).getByRole('button', { name: 'Change access' })).toBeDisabled()

    await u.click(within(form).getByRole('radio', { name: /^Writer/ }))
    await u.click(within(form).getByRole('button', { name: 'Change access' }))
    await waitFor(() =>
      expect(api.sent('PUT', /^\/admin\/users\/2\/roles$/)[0]?.body).toEqual({ role_id: 4 }),
    )
    await waitFor(() =>
      expect(within(form).getByRole('radio', { name: /^Writer/ })).toBeChecked(),
    )

    // Writer → admin: the admin role first, then writer goes.
    await u.click(within(form).getByRole('radio', { name: /^Admin/ }))
    await u.click(within(form).getByRole('button', { name: 'Change access' }))
    await waitFor(() =>
      expect(api.sent('DELETE', /^\/admin\/users\/2\/roles\/4$/)).toHaveLength(1),
    )
    expect(api.sent('PUT', /^\/admin\/users\/2\/roles$/)[1]?.body).toEqual({ role_id: 1 })
    expect(api.state.assignments).toContainEqual([2, 1])
    expect(api.state.assignments).not.toContainEqual([2, 4])
    // The custom role stays.
    expect(api.state.assignments).toContainEqual([2, 7])

    // Back to reader takes the admin role.
    await u.click(within(form).getByRole('radio', { name: /^Reader/ }))
    await u.click(within(form).getByRole('button', { name: 'Change access' }))
    await waitFor(() =>
      expect(api.sent('DELETE', /^\/admin\/users\/2\/roles\/1$/)).toHaveLength(1),
    )
    expect(api.state.assignments).toContainEqual([2, 7])
  })

  it('keeps the last administrator an admin, with the server’s reason', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/users/1')

    const form = await screen.findByRole('form', { name: 'Change access' })
    await waitFor(() =>
      expect(within(form).getByRole('radio', { name: /^Admin/ })).toBeChecked(),
    )
    await u.click(within(form).getByRole('radio', { name: /^Writer/ }))
    await u.click(within(form).getByRole('button', { name: 'Change access' }))

    expect(await within(form).findByRole('alert')).toHaveTextContent(
      'this would leave no active administrator',
    )
    // The writer role was given first, so the user lost nothing.
    expect(api.state.assignments).toContainEqual([1, 1])
  })

  it('creates a user with its access level', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/users/new')

    await u.type(await screen.findByLabelText('Username'), 'carol@example.com')
    await u.click(screen.getByRole('radio', { name: /^Writer/ }))
    await u.click(screen.getByRole('button', { name: 'Create and invite' }))

    await waitFor(() => expect(api.sent('POST', /^\/admin\/users$/)).toHaveLength(1))
    expect(api.sent('POST', /^\/admin\/users$/)[0].body).toEqual({
      username: 'carol@example.com',
      role: 'writer',
    })
    // The role goes with the create: nothing is assigned afterwards.
    expect(api.sent('PUT', /\/roles$/)).toHaveLength(0)
    await u.click(await screen.findByRole('link', { name: 'Go to carol@example.com' }))
    expect(await screen.findByRole('radio', { name: /^Writer/ })).toBeChecked()
  })

  it("assigns and removes a user's roles", async () => {
    const u = userEvent.setup()
    await renderApp('/manage/users/2')

    expect(await screen.findByRole('link', { name: 'ci-pushers' })).toBeInTheDocument()
    const form = screen.getByRole('form', { name: 'Assign role' })
    const picker = within(form).getByLabelText('Role')
    await waitFor(() =>
      expect(within(picker).getByRole('option', { name: 'authenticated' })).toBeInTheDocument(),
    )
    // A role the user holds is not offered again.
    expect(within(picker).queryByRole('option', { name: 'ci-pushers' })).toBeNull()
    await u.selectOptions(picker, 'authenticated')
    await u.click(within(form).getByRole('button', { name: 'Assign role' }))
    await waitFor(() =>
      expect(api.sent('PUT', /^\/admin\/users\/2\/roles$/)[0]?.body).toEqual({ role_id: 3 }),
    )
    expect(await screen.findByRole('link', { name: 'authenticated' })).toBeInTheDocument()

    await u.click(screen.getByRole('button', { name: 'Remove role ci-pushers' }))
    await waitFor(() =>
      expect(api.sent('DELETE', /^\/admin\/users\/2\/roles\/7$/)).toHaveLength(1),
    )
    await waitFor(() =>
      expect(screen.queryByRole('link', { name: 'ci-pushers' })).toBeNull(),
    )
  })

  it('shows the refusal to take admin from the last administrator', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/users/1')

    await u.click(await screen.findByRole('button', { name: 'Remove role admin' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'this would leave no active administrator',
    )
    expect(screen.getByRole('button', { name: 'Remove role admin' })).toBeInTheDocument()
  })

  it('shows the effective access with repository and selector names', async () => {
    await renderApp('/manage/users/2')

    const write = (await screen.findByText('write')).closest('tr')!
    expect(within(write).getByRole('link', { name: 'internal' })).toBeInTheDocument()
    expect(within(write).getByText('All packages')).toBeInTheDocument()
    const read = screen.getByText('read').closest('tr')!
    expect(within(read).getByText('All repositories')).toBeInTheDocument()
    expect(within(read).getByRole('link', { name: 'acme' })).toBeInTheDocument()
    expect(screen.queryByText('administrator')).toBeNull()
  })

  it('shows an administrator as allowed everything', async () => {
    await renderApp('/manage/users/1')
    expect(await screen.findByText('administrator')).toBeInTheDocument()
    expect(screen.getByText(/May do everything/)).toBeInTheDocument()
  })

  it('creates a token with a scope', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/users/2')

    await u.type(await screen.findByLabelText('Token name'), 'ci')
    await u.click(screen.getByRole('checkbox', { name: /^Admin API/ }))
    await u.click(screen.getByRole('radio', { name: 'At most this level' }))
    // read is chosen by default; raise it to write.
    await u.click(screen.getByRole('radio', { name: /^write/ }))
    await u.click(screen.getByRole('radio', { name: /^Only these repositories/ }))
    // Admin needs every repository.
    expect(screen.getByRole('checkbox', { name: /^Admin API/ })).toBeDisabled()
    expect(screen.getByRole('checkbox', { name: /^Admin API/ })).not.toBeChecked()
    expect(screen.getByRole('button', { name: 'Create token' })).toBeDisabled()
    expect(screen.getByText('Choose at least one repository.')).toBeInTheDocument()
    await u.click(await screen.findByRole('checkbox', { name: 'internal' }))
    await u.click(screen.getByRole('button', { name: 'Create token' }))
    await waitFor(() =>
      expect(api.sent('POST', /^\/admin\/users\/2\/tokens$/)[0]?.body).toEqual(
        expect.objectContaining({
          name: 'ci',
          scope: { level: 'write', repositories: [10] },
        }),
      ),
    )
    expect(
      Date.parse(
        (api.sent('POST', /^\/admin\/users\/2\/tokens$/)[0]?.body as { expires_at: string })
          .expires_at,
      ),
    ).toBeGreaterThan(Date.now())
    expect(await screen.findByText('plaintext-secret')).toBeInTheDocument()
    const row = (await screen.findByText('ci', { selector: 'td' })).closest('tr')!
    expect(within(row).getByText('write')).toBeInTheDocument()
    expect(within(row).getByText('1 repository')).toBeInTheDocument()
  })

  it('creates an unscoped token without a scope', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/users/2')

    await u.type(await screen.findByLabelText('Token name'), 'laptop')
    await u.click(screen.getByRole('button', { name: 'Create token' }))
    await waitFor(() => expect(api.sent('POST', /\/tokens$/)).toHaveLength(1))
    const body = api.sent('POST', /\/tokens$/)[0]?.body as {
      name: string
      expires_at: string
      scope?: unknown
    }
    expect(body.name).toBe('laptop')
    expect(Date.parse(body.expires_at)).toBeGreaterThan(Date.now())
    expect(body).not.toHaveProperty('scope')
  })

  it("changes a token's scope", async () => {
    api.state.tokens.push(
      token({ id: 40, user_id: 2, name: 'deploy', scope: { level: 'read', repositories: [11] } }),
    )
    const u = userEvent.setup()
    await renderApp('/manage/users/2')

    await u.click(await screen.findByRole('button', { name: 'Edit scope of deploy' }))
    const form = screen.getByRole('form', { name: 'Scope of deploy' })
    // Seeded from the stored scope.
    expect(within(form).getByRole('radio', { name: 'At most this level' })).toBeChecked()
    expect(within(form).getByRole('radio', { name: /^read/ })).toBeChecked()
    expect(await within(form).findByRole('checkbox', { name: 'public' })).toBeChecked()
    await u.click(within(form).getByRole('radio', { name: 'Every repository the owner can reach' }))
    await u.click(within(form).getByRole('checkbox', { name: /^Admin API/ }))
    await u.click(within(form).getByRole('button', { name: 'Save scope' }))

    await waitFor(() =>
      expect(api.sent('PATCH', /^\/admin\/tokens\/40\/scope$/)[0]?.body).toEqual({
        scope: { level: 'read', admin: true },
      }),
    )
    await waitFor(() =>
      expect(screen.queryByRole('form', { name: 'Scope of deploy' })).toBeNull(),
    )
    const row = screen.getByText('deploy', { selector: 'td' }).closest('tr')!
    expect(await within(row).findByText('admin')).toBeInTheDocument()
  })

  it("clears a token's scope", async () => {
    api.state.tokens.push(
      token({ id: 41, user_id: 2, name: 'narrow', scope: { level: 'read' } }),
    )
    const u = userEvent.setup()
    await renderApp('/manage/users/2')

    await u.click(await screen.findByRole('button', { name: 'Edit scope of narrow' }))
    const form = screen.getByRole('form', { name: 'Scope of narrow' })
    await u.click(within(form).getByRole('radio', { name: /^The owner's levels/ }))
    await u.click(within(form).getByRole('button', { name: 'Save scope' }))
    await waitFor(() =>
      expect(api.sent('PATCH', /^\/admin\/tokens\/41\/scope$/)[0]?.body).toEqual({
        scope: null,
      }),
    )
  })
})
