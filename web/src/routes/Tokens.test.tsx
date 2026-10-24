import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import { FakeRbacApi } from '~/test/fakeRbacApi'
import { renderApp } from '~/test/renderApp'

/**
 * Self-service tokens (`/tokens`): a signed-in user scopes a new token to a
 * level (labelled with the Nexus actions it covers) and to repositories they
 * can read (by id, from `/browse/repos`), or leaves it unscoped, which sends
 * no scope at all.
 */

const readerMe: Me = {
  user: { id: 2, username: 'alice', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

let api: FakeRbacApi

describe('self-service tokens', () => {
  beforeEach(() => {
    api = new FakeRbacApi({
      me: readerMe,
      browseRepos: [
        { id: 10, name: 'internal', kind: 'hosted', online: true, format: 'nuget' },
        { id: 12, name: 'images', kind: 'hosted', online: true, format: 'docker' },
      ],
    })
    vi.stubGlobal('fetch', vi.fn(api.fetch))
    setSession('reader-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('creates a token scoped to a level and repositories', async () => {
    const u = userEvent.setup()
    await renderApp('/tokens')

    await u.type(await screen.findByLabelText('Token name'), 'push-images')
    await u.click(screen.getByRole('radio', { name: 'At most this level' }))
    const levels = screen.getByRole('group', { name: 'Level of the token' })
    expect(within(levels).getAllByRole('radio').map((r) => r.getAttribute('value'))).toEqual([
      'read',
      'write',
      'delete',
    ])
    expect(within(levels).getByRole('radio', { name: 'read (browse, read)' })).toBeChecked()
    await u.click(
      within(levels).getByRole('radio', { name: 'write (browse, read, add, edit)' }),
    )
    await u.click(screen.getByRole('radio', { name: /^Only these repositories/ }))
    await u.click(await screen.findByRole('checkbox', { name: 'images' }))
    await u.click(screen.getByRole('button', { name: 'Create token' }))

    await waitFor(() =>
      expect(api.sent('POST', /^\/admin\/me\/tokens$/)[0]?.body).toEqual({
        name: 'push-images',
        scope: { level: 'write', repositories: [12] },
      }),
    )
    expect(await screen.findByText('my-plaintext-secret')).toBeInTheDocument()
    const row = (await screen.findByText('push-images', { selector: 'td' })).closest('tr')!
    expect(within(row).getByText('write')).toBeInTheDocument()
    expect(within(row).getByText('1 repository')).toBeInTheDocument()
    // Reset for the next token.
    expect(screen.getByLabelText('Token name')).toHaveValue('')
    expect(screen.getByRole('radio', { name: /^The owner's levels/ })).toBeChecked()
    // No admin endpoint was needed.
    expect(api.requests.some((r) => /^\/admin\/(roles|repositories)/.test(r.path))).toBe(false)
  })

  it('refuses a scope without repositories', async () => {
    const u = userEvent.setup()
    await renderApp('/tokens')

    await u.type(await screen.findByLabelText('Token name'), 'nothing')
    await u.click(screen.getByRole('radio', { name: /^Only these repositories/ }))
    expect(screen.getByText('Choose at least one repository.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create token' })).toBeDisabled()
  })

  it('sends no scope for an unscoped token', async () => {
    const u = userEvent.setup()
    await renderApp('/tokens')

    await u.type(await screen.findByLabelText('Token name'), 'laptop')
    await u.click(screen.getByRole('button', { name: 'Create token' }))
    await waitFor(() =>
      expect(api.sent('POST', /^\/admin\/me\/tokens$/)[0]?.body).toEqual({ name: 'laptop' }),
    )
  })
})
