import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import { FakeRbacApi, repo, user } from '~/test/fakeRbacApi'
import { renderApp } from '~/test/renderApp'

/**
 * Admin roles screens, against the real route tree and a stateful fake of the
 * RBAC API:
 *  - the list shows each role's description, built-in badge and grant and
 *    user counts, and offers no delete for a built-in role;
 *  - creating a role opens its page;
 *  - deleting a role first names the users and grants it takes along, in
 *    a confirmation dialog;
 *  - the role page adds grants (one level, labelled with the Nexus actions
 *    it covers; adding one again sets its level) and removes them, adds and
 *    removes members, and shows why the last administrator keeps `admin`;
 *  - a repository's page shows its anonymous access: the flag together with
 *    the anonymous role's grants, linking to the role.
 */

let api: FakeRbacApi

function seed() {
  api = new FakeRbacApi({
    users: [
      user({ id: 1, username: 'root', is_admin: true }),
      user({ id: 2, username: 'alice' }),
      user({ id: 3, username: 'bob', auth_source: 'oidc' }),
    ],
    repos: [
      repo({ id: 10, name: 'internal' }),
      repo({ id: 11, name: 'public', anonymous_read: true }),
    ],
    selectors: [
      { id: 20, name: 'acme', description: '', includes: ['acme.*'], excludes: [] },
    ],
  })
  api.state.roles.push({ id: 7, name: 'ci-pushers', description: 'CI', builtin: false })
  api.state.assignments.push([1, 1], [2, 7], [3, 7])
  api.state.grants.push(
    { id: 30, role_id: 7, repository_id: 10, level: 'write', selector_id: null },
    { id: 31, role_id: 7, repository_id: null, level: 'read', selector_id: 20 },
    { id: 32, role_id: 2, repository_id: 11, level: 'read', selector_id: null },
    { id: 33, role_id: 2, repository_id: 10, level: 'read', selector_id: 20 },
  )
  vi.stubGlobal('fetch', vi.fn(api.fetch))
}

describe('admin roles', () => {
  beforeEach(() => {
    seed()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('lists roles with their counts and protects the built-in ones', async () => {
    await renderApp('/manage/roles')

    const row = (name: string) =>
      screen.getByRole('link', { name }).closest('tr')!
    await screen.findByRole('link', { name: 'ci-pushers' })

    const ci = within(row('ci-pushers')).getAllByRole('cell')
    expect(ci[1]).toHaveTextContent('CI')
    expect(ci[2]).toHaveTextContent('2')
    expect(ci[3]).toHaveTextContent('2')
    expect(within(row('ci-pushers')).getByRole('button', { name: 'Delete ci-pushers' })).toBeInTheDocument()

    const admin = row('admin')
    expect(within(admin).getByText('built-in')).toBeInTheDocument()
    expect(within(admin).queryByRole('button', { name: /Delete/ })).toBeNull()
  })

  it('creates a role and opens it', async () => {
    const u = userEvent.setup()
    const router = await renderApp('/manage/roles')

    await u.type(await screen.findByLabelText('Name'), 'deployers')
    await u.type(screen.getByLabelText('Description'), 'Pushes releases')
    await u.click(screen.getByRole('button', { name: 'Create role' }))

    await waitFor(() =>
      expect(router.state.location.pathname).toMatch(/^\/manage\/roles\/\d+$/),
    )
    expect(api.sent('POST', /^\/admin\/roles$/)[0].body).toEqual({
      name: 'deployers',
      description: 'Pushes releases',
    })
    expect(await screen.findByRole('heading', { name: 'deployers' })).toBeInTheDocument()
  })

  it('names the users and grants a role takes along before deleting it', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/roles')

    await u.click(await screen.findByRole('button', { name: 'Delete ci-pushers' }))
    const confirm = await screen.findByRole('dialog', { name: 'Delete ci-pushers?' })
    expect(await within(confirm).findByText('alice')).toBeInTheDocument()
    expect(within(confirm).getByText('bob')).toBeInTheDocument()
    expect(within(confirm).getByText('write on internal')).toBeInTheDocument()
    expect(
      within(confirm).getByText('read on all repositories (packages of acme)'),
    ).toBeInTheDocument()
    expect(api.sent('DELETE', /^\/admin\/roles\/7$/)).toHaveLength(0)

    await u.click(within(confirm).getByRole('button', { name: 'Delete role' }))

    await waitFor(() => expect(api.sent('DELETE', /^\/admin\/roles\/7$/)).toHaveLength(1))
    await waitFor(() =>
      expect(screen.queryByRole('link', { name: 'ci-pushers' })).toBeNull(),
    )
  })

  it('adds a grant of one level, labelled with the Nexus actions', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/roles/7')

    const form = await screen.findByRole('form', { name: 'Add grant' })
    const repository = within(form).getByLabelText('Repository')
    const level = within(form).getByLabelText('Level')
    await waitFor(() =>
      expect(within(repository).getByRole('option', { name: 'internal' })).toBeInTheDocument(),
    )

    // Three ordered levels, each with what it covers; no admin.
    expect(
      within(level)
        .getAllByRole('option')
        .map((o) => o.textContent),
    ).toEqual([
      'read (browse, read)',
      'write (browse, read, add, edit)',
      'delete (browse, read, add, edit, delete)',
    ])
    expect(level).toHaveValue('read')
    expect(within(form).getByText('Covers browse, read.')).toBeInTheDocument()

    await u.selectOptions(repository, 'internal')
    await u.selectOptions(level, 'delete')
    expect(within(form).getByText('Covers browse, read, add, edit, delete.')).toBeInTheDocument()
    await waitFor(() =>
      expect(within(form).getByRole('option', { name: 'acme' })).toBeInTheDocument(),
    )
    await u.selectOptions(within(form).getByLabelText('Content selector'), 'acme')
    await u.click(within(form).getByRole('button', { name: 'Add grant' }))

    await waitFor(() => expect(api.sent('PUT', /\/grants$/)).toHaveLength(1))
    expect(api.sent('PUT', /\/grants$/)[0].body).toEqual({
      level: 'delete',
      repository_id: 10,
      selector_id: 20,
    })
    // The new grant is listed with names, not ids.
    const table = screen.getAllByRole('table')[0]
    await waitFor(() => expect(within(table).getByText('delete')).toBeInTheDocument())
    const added = within(table).getByText('delete').closest('tr')!
    expect(within(added).getByRole('link', { name: 'internal' })).toBeInTheDocument()
    expect(within(added).getByRole('link', { name: 'acme' })).toBeInTheDocument()
  })

  it('sets the level of a grant the role has on that repository', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/roles/7')

    const form = await screen.findByRole('form', { name: 'Add grant' })
    const repository = within(form).getByLabelText('Repository')
    await waitFor(() =>
      expect(within(repository).getByRole('option', { name: 'internal' })).toBeInTheDocument(),
    )
    await u.selectOptions(repository, 'internal')
    await u.selectOptions(within(form).getByLabelText('Level'), 'read')
    await u.click(within(form).getByRole('button', { name: 'Add grant' }))

    await waitFor(() => expect(api.sent('PUT', /\/grants$/)).toHaveLength(1))
    const grants = screen.getAllByRole('table')[0]
    await waitFor(() => expect(within(grants).queryByText('write')).toBeNull())
    const internal = within(grants).getByRole('link', { name: 'internal' }).closest('tr')!
    expect(within(internal).getByText('read')).toBeInTheDocument()
    expect(api.state.grants.filter((g) => g.role_id === 7)).toHaveLength(2)
  })

  it('removes a grant', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/roles/7')

    const grants = (await screen.findAllByRole('table'))[0]
    const write = (await within(grants).findByText('write')).closest('tr')!
    await u.click(within(write).getByRole('button', { name: 'Remove' }))

    await waitFor(() =>
      expect(api.sent('DELETE', /^\/admin\/roles\/7\/grants\/30$/)).toHaveLength(1),
    )
    await waitFor(() => expect(within(grants).queryByText('write')).toBeNull())
  })

  it('adds and removes members', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/roles/7')

    const form = await screen.findByRole('form', { name: 'Add member' })
    const picker = within(form).getByLabelText('User')
    // Only users who do not hold the role yet are offered.
    await waitFor(() =>
      expect(within(picker).getByRole('option', { name: /^root/ })).toBeInTheDocument(),
    )
    expect(within(picker).queryByRole('option', { name: /^alice/ })).toBeNull()
    await u.selectOptions(picker, within(picker).getByRole('option', { name: /^root/ }))
    await u.click(within(form).getByRole('button', { name: 'Add member' }))
    await waitFor(() =>
      expect(api.sent('PUT', /^\/admin\/users\/1\/roles$/)[0]?.body).toEqual({ role_id: 7 }),
    )
    expect(await screen.findByRole('link', { name: 'root' })).toBeInTheDocument()

    await u.click(screen.getByRole('button', { name: 'Remove bob' }))
    await waitFor(() =>
      expect(api.sent('DELETE', /^\/admin\/users\/3\/roles\/7$/)).toHaveLength(1),
    )
    await waitFor(() => expect(screen.queryByRole('link', { name: 'bob' })).toBeNull())
  })

  it('shows why the last administrator keeps the admin role', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/roles/1')

    expect(await screen.findByText(/may do everything/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete role…' })).toBeNull()
    await u.click(await screen.findByRole('button', { name: 'Remove root' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'this would leave no active administrator',
    )
    expect(screen.getByRole('link', { name: 'root' })).toBeInTheDocument()
  })

  it('edits the description and deletes the role from its page', async () => {
    const u = userEvent.setup()
    const router = await renderApp('/manage/roles/7')

    const description = await screen.findByLabelText('Description')
    await u.clear(description)
    await u.type(description, 'Pushes from CI')
    await u.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(api.sent('PATCH', /^\/admin\/roles\/7$/)[0]?.body).toEqual({
        description: 'Pushes from CI',
      }),
    )

    await u.click(screen.getByRole('button', { name: 'Delete role…' }))
    const confirm = await screen.findByRole('dialog', { name: 'Delete ci-pushers?' })
    await within(confirm).findByText('alice')
    await u.click(within(confirm).getByRole('button', { name: 'Delete role' }))
    await waitFor(() => expect(router.state.location.pathname).toBe('/manage/roles'))
  })

  it("shows a repository's anonymous access with the anonymous role's grants", async () => {
    await renderApp('/manage/repositories/public')

    const panel = await screen.findByRole('region', { name: 'Anonymous access' })
    expect(within(panel).getByText('on')).toBeInTheDocument()
    expect(await within(panel).findByText('on this repository,')).toBeInTheDocument()
    expect(within(panel).getByText('All packages')).toBeInTheDocument()
    expect(
      within(panel).getByRole('link', { name: /Change the anonymous role/ }),
    ).toHaveAttribute('href', '/manage/roles/2')
  })

  it('shows a selector-scoped anonymous grant on a repository without the flag', async () => {
    await renderApp('/manage/repositories/internal')

    const panel = await screen.findByRole('region', { name: 'Anonymous access' })
    expect(within(panel).getByText('off')).toBeInTheDocument()
    expect(await within(panel).findByRole('link', { name: 'acme' })).toBeInTheDocument()
  })
})
