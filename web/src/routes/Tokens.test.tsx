import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
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

    await waitFor(() => {
      const body = api.sent('POST', /^\/admin\/me\/tokens$/)[0]?.body as
        | { name: string; expires_at?: string; scope?: unknown }
        | undefined
      expect(body).toMatchObject({
        name: 'push-images',
        scope: { level: 'write', repositories: [12] },
      })
      expect(Date.parse(body!.expires_at!)).toBeGreaterThan(Date.now())
    })
    expect(await screen.findByText('my-plaintext-secret')).toBeInTheDocument()
    expect(screen.getByText(/This token expires/)).toBeInTheDocument()
    const row = (await screen.findByText('push-images', { selector: 'td' })).closest('tr')!
    expect(within(row).getByText('write')).toBeInTheDocument()
    expect(within(row).getByText('1 repository')).toBeInTheDocument()
    expect(within(row).getAllByRole('cell')[2]).not.toHaveTextContent('never')
    expect(screen.getByRole('columnheader', { name: 'Expires' })).toBeInTheDocument()
    // Reset for the next token.
    expect(screen.getByLabelText('Token name')).toHaveValue('')
    expect(screen.getByLabelText('Token expiry')).toHaveValue('90-days')
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

  it('sends a finite default expiry for an unscoped token', async () => {
    const u = userEvent.setup()
    await renderApp('/tokens')

    const started = Date.now()
    await u.type(await screen.findByLabelText('Token name'), 'laptop')
    await u.click(screen.getByRole('button', { name: 'Create token' }))
    await waitFor(() => expect(api.sent('POST', /^\/admin\/me\/tokens$/)).toHaveLength(1))
    const body = api.sent('POST', /^\/admin\/me\/tokens$/)[0]!.body as {
      name: string
      expires_at: string
    }
    expect(body.name).toBe('laptop')
    expect(Date.parse(body.expires_at)).toBeGreaterThan(started + 89 * 24 * 60 * 60 * 1000)
  })

  it('sends the selected expiry for each choice', async () => {
    const u = userEvent.setup()
    await renderApp('/tokens')
    const expiry = await screen.findByLabelText('Token expiry')
    const choices = [
      { value: '90-days', days: 90 },
      { value: '30-days', days: 30 },
      { value: '1-year', years: 1 },
      { value: 'custom', date: '2099-12-31' },
      { value: 'never' },
    ] as const

    for (const [index, choice] of choices.entries()) {
      if (choice.value !== '90-days') await u.selectOptions(expiry, choice.value)
      if (choice.value === 'never') {
        expect(screen.getByText('This token stays valid until it is revoked.')).toBeInTheDocument()
      }
      await u.type(await screen.findByLabelText('Token name'), `choice-${index}`)
      if (choice.value === 'custom') {
        fireEvent.change(screen.getByLabelText('Expiry date'), {
          target: { value: choice.date },
        })
      }
      const started = Date.now()
      await u.click(screen.getByRole('button', { name: 'Create token' }))
      await waitFor(() =>
        expect(api.sent('POST', /^\/admin\/me\/tokens$/)).toHaveLength(index + 1),
      )
      const body = api.sent('POST', /^\/admin\/me\/tokens$/)[index]!.body as {
        name: string
        expires_at?: string
      }
      expect(body.name).toBe(`choice-${index}`)
      if ('date' in choice) {
        expect(body.expires_at).toBe(`${choice.date}T23:59:59.999Z`)
      } else if ('days' in choice || 'years' in choice) {
        const expected = new Date(started)
        if ('years' in choice) expected.setUTCFullYear(expected.getUTCFullYear() + choice.years)
        else expected.setUTCDate(expected.getUTCDate() + choice.days)
        expect(Math.abs(Date.parse(body.expires_at!) - expected.getTime())).toBeLessThan(3000)
      } else {
        expect(body).not.toHaveProperty('expires_at')
      }
    }
  })

  it('refuses a custom expiry date that is not in the future', async () => {
    const u = userEvent.setup()
    await renderApp('/tokens')
    await u.type(await screen.findByLabelText('Token name'), 'invalid-date')
    await u.selectOptions(screen.getByLabelText('Token expiry'), 'custom')
    const submit = screen.getByRole('button', { name: 'Create token' })
    expect(submit).toBeDisabled()

    const past = new Date()
    past.setUTCDate(past.getUTCDate() - 1)
    fireEvent.change(screen.getByLabelText('Expiry date'), {
      target: { value: past.toISOString().slice(0, 10) },
    })
    expect(screen.getByText('Choose a date in the future.')).toBeInTheDocument()
    expect(submit).toBeDisabled()
    expect(api.sent('POST', /^\/admin\/me\/tokens$/)).toHaveLength(0)
  })

  it('accepts the minimum custom expiry date', async () => {
    const u = userEvent.setup()
    await renderApp('/tokens')
    await u.type(await screen.findByLabelText('Token name'), 'tomorrow')
    await u.selectOptions(screen.getByLabelText('Token expiry'), 'custom')
    const date = screen.getByLabelText('Expiry date') as HTMLInputElement
    fireEvent.change(date, { target: { value: date.min } })

    const submit = screen.getByRole('button', { name: 'Create token' })
    expect(submit).toBeEnabled()
    await u.click(submit)
    await waitFor(() => expect(api.sent('POST', /^\/admin\/me\/tokens$/)).toHaveLength(1))
    expect(
      (api.sent('POST', /^\/admin\/me\/tokens$/)[0]!.body as { expires_at: string }).expires_at,
    ).toBe(`${date.min}T23:59:59.999Z`)
  })
})
