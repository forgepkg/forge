import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import { FakeRbacApi, token, user } from '~/test/fakeRbacApi'
import { renderApp } from '~/test/renderApp'

/**
 * Admin → Service accounts (#508), against the real route tree and a
 * stateful fake of the admin API:
 *  - the list shows the service accounts alone, with their description,
 *    trusted-header realm, access level and last use; the Users list leaves
 *    them out;
 *  - the create page POSTs `kind: 'service'` with the description, realm
 *    and access level, offers no admin level and takes no email;
 *  - the account page saves what changed of its description and realm (a
 *    realm deleted since is not sent again), never offers the
 *    admin role or level, issues a token whose secret shows once, and
 *    deactivates it after a confirmation.
 */

const edgeRealm = {
  id: 5,
  kind: 'trusted_header',
  name: 'edge-lb',
  enabled: true,
  priority: 30,
  config: {
    username_header: 'x-forwarded-user',
    secret_header: 'x-forge-proxy-secret',
    secret_set: true,
    auto_provision: false,
  },
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

let api: FakeRbacApi

describe('admin service accounts', () => {
  beforeEach(() => {
    api = new FakeRbacApi({
      users: [
        user({ id: 1, username: 'root@example.com', is_admin: true }),
        user({ id: 2, username: 'alice@example.com' }),
        user({
          id: 3,
          username: 'office-lan@example.com',
          kind: 'service',
          auth_source: 'service',
          description: 'The office network, admitted by the load balancer',
          realm: 'edge-lb',
          last_used_at: '2026-10-01T12:00:00Z',
        }),
        user({
          id: 4,
          username: 'ci@example.com',
          kind: 'service',
          auth_source: 'service',
          description: null,
          realm: null,
          last_used_at: null,
        }),
      ],
      realms: [edgeRealm],
    })
    api.state.assignments.push([1, 1], [4, 4])
    vi.stubGlobal('fetch', vi.fn(api.fetch))
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('lists the service accounts alone, with their realm and last use', async () => {
    const router = await renderApp('/manage/service-accounts')

    const row = (name: string) =>
      screen.getByRole('link', { name }).closest('tr')!
    const cells = (name: string) => within(row(name)).getAllByRole('cell')
    await screen.findByRole('link', { name: 'office-lan@example.com' })
    expect(screen.queryByRole('link', { name: 'alice@example.com' })).toBeNull()
    expect(cells('office-lan@example.com')[0]).toHaveTextContent(
      'The office network, admitted by the load balancer',
    )
    expect(cells('office-lan@example.com')[1]).toHaveTextContent('edge-lb')
    expect(cells('ci@example.com')[1]).toHaveTextContent('tokens only')
    expect(cells('ci@example.com')[2]).toHaveTextContent('writer')
    expect(cells('ci@example.com')[3]).toHaveTextContent('never')
    expect(cells('office-lan@example.com')[3]).not.toHaveTextContent('never')
    expect(screen.getByRole('link', { name: 'New service account' })).toHaveAttribute(
      'href',
      '/manage/service-accounts/new',
    )

    // The Users list leaves them out.
    await router.navigate({ to: '/manage/users' })
    await screen.findByRole('link', { name: 'alice@example.com' })
    expect(screen.queryByRole('link', { name: 'ci@example.com' })).toBeNull()
  })

  it('creates a service account with its description, realm and access level', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/service-accounts/new')

    const form = await screen.findByRole('form', { name: 'New service account' })
    // Never an admin, and no email.
    expect(within(form).queryByRole('radio', { name: /^Admin/ })).toBeNull()
    expect(within(form).queryByLabelText(/Email/)).toBeNull()

    await u.type(within(form).getByLabelText('Name'), 'builds')
    await u.tab()
    expect(within(form).getByText(/must be a UPN/)).toBeInTheDocument()
    await u.clear(within(form).getByLabelText('Name'))
    await u.type(within(form).getByLabelText('Name'), 'builds@example.com')
    await u.type(within(form).getByLabelText(/Description/), 'Build agents; owner: platform')
    await waitFor(() =>
      expect(within(form).getByRole('option', { name: 'edge-lb' })).toBeInTheDocument(),
    )
    await u.selectOptions(within(form).getByLabelText('Trusted-header realm'), 'edge-lb')
    await u.click(within(form).getByRole('radio', { name: /^Writer/ }))
    await u.click(within(form).getByRole('button', { name: 'Create service account' }))

    await waitFor(() =>
      expect(api.sent('POST', /^\/admin\/users$/)[0]?.body).toEqual({
        username: 'builds@example.com',
        kind: 'service',
        description: 'Build agents; owner: platform',
        role: 'writer',
        realm: 'edge-lb',
      }),
    )
    expect(await screen.findByText(/the proxy of edge-lb names it/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to builds@example.com' })).toHaveAttribute(
      'href',
      expect.stringMatching(/^\/manage\/service-accounts\/\d+$/),
    )
  })

  it('saves the description and realm, and never offers the admin role', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/service-accounts/4')

    expect(await screen.findByText(/^Realm:/)).toHaveTextContent('none (API tokens only)')
    const settings = screen.getByRole('form', { name: 'Service account' })
    await waitFor(() =>
      expect(within(settings).getByRole('option', { name: 'edge-lb' })).toBeInTheDocument(),
    )
    await u.type(within(settings).getByLabelText(/Description/), 'CI of the web team')
    await u.selectOptions(within(settings).getByLabelText('Trusted-header realm'), 'edge-lb')
    await u.click(within(settings).getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(api.sent('PATCH', /^\/admin\/users\/4$/)[0]?.body).toEqual({
        description: 'CI of the web team',
        realm: 'edge-lb',
      }),
    )
    expect(await within(settings).findByText('Saved ci@example.com.')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText(/^Realm:/)).toHaveTextContent('edge-lb'))

    // Back to no realm: the realm alone is sent, as null.
    await u.selectOptions(within(settings).getByLabelText('Trusted-header realm'), '')
    await u.click(within(settings).getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(api.sent('PATCH', /^\/admin\/users\/4$/)[1]?.body).toEqual({ realm: null }),
    )

    // The access level has no admin, and neither do the roles to assign.
    const access = screen.getByRole('form', { name: 'Change access' })
    await waitFor(() =>
      expect(within(access).getByRole('radio', { name: /^Writer/ })).toBeChecked(),
    )
    expect(within(access).queryByRole('radio', { name: /^Admin/ })).toBeNull()
    const assign = screen.getByRole('form', { name: 'Assign role' })
    await waitFor(() =>
      expect(within(assign).getByRole('option', { name: 'anonymous' })).toBeInTheDocument(),
    )
    expect(within(assign).queryByRole('option', { name: 'admin' })).toBeNull()
  })

  it('saves a description alone once its realm is gone, without re-sending the realm', async () => {
    // The account's realm was deleted (or renamed) since it was assigned.
    api.state.realms = []
    const u = userEvent.setup()
    await renderApp('/manage/service-accounts/3')

    const settings = await screen.findByRole('form', { name: 'Service account' })
    const field = within(settings).getByLabelText(/Description/)
    await u.clear(field)
    await u.type(field, 'The office network')
    await u.click(within(settings).getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(api.sent('PATCH', /^\/admin\/users\/3$/)[0]?.body).toEqual({
        description: 'The office network',
      }),
    )
    expect(await within(settings).findByText('Saved office-lan@example.com.')).toBeInTheDocument()
  })

  it('issues a token for a service account, showing the secret once', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/service-accounts/4')

    await u.type(await screen.findByLabelText('Token name'), 'pipeline')
    await u.click(screen.getByRole('button', { name: 'Create token' }))

    expect(await screen.findByText('plaintext-secret')).toBeInTheDocument()
    expect(api.sent('POST', /^\/admin\/users\/4\/tokens$/)[0]?.body).toMatchObject({
      name: 'pipeline',
    })
    expect(await screen.findByRole('cell', { name: 'pipeline' })).toBeInTheDocument()
  })

  it("points a service account's user page to its own, and back", async () => {
    await renderApp('/manage/users/4')
    expect(await screen.findByText('A service account')).toBeInTheDocument()
    const links = screen.getAllByRole('link', { name: 'Service accounts' })
    expect(links.map((l) => l.getAttribute('href'))).toContain('/manage/service-accounts/4')
    expect(screen.queryByRole('button', { name: 'Sign out everywhere…' })).toBeNull()
  })

  it("points a user's service-account page to the user's", async () => {
    await renderApp('/manage/service-accounts/2')
    expect(await screen.findByText('Not a service account')).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: 'Users' }).at(-1)).toHaveAttribute(
      'href',
      '/manage/users/2',
    )
  })

  it('deactivates a service account after a confirmation', async () => {
    api.state.tokens.push(token({ id: 50, user_id: 3, name: 'lan' }))
    const u = userEvent.setup()
    await renderApp('/manage/service-accounts/3')

    const settings = await screen.findByRole('form', { name: 'Service account' })
    expect(
      within(settings).getByText('office-lan@example.com is active: its tokens and its realm authenticate it.'),
    ).toBeInTheDocument()
    await u.click(within(settings).getByRole('button', { name: 'Deactivate…' }))
    const dialog = screen.getByRole('dialog', { name: 'Deactivate office-lan@example.com?' })
    expect(dialog).toHaveTextContent(/tokens and its trusted-header realm stop authenticating it/)
    await u.click(within(dialog).getByRole('button', { name: 'Deactivate service account' }))

    await waitFor(() =>
      expect(api.sent('PATCH', /^\/admin\/users\/3$/)[0]?.body).toEqual({ active: false }),
    )
    expect(await within(settings).findByText(/Deactivated office-lan@example.com/)).toBeInTheDocument()
    expect(within(settings).getByRole('button', { name: 'Reactivate…' })).toBeInTheDocument()
    expect(screen.getByText(/its tokens are refused until it is reactivated/)).toBeInTheDocument()
  })
})
