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
    vi.unstubAllEnvs()
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

  it('shows the clients’ snippets with the new token filled in', async () => {
    api = new FakeRbacApi({
      me: readerMe,
      browseRepos: [
        {
          id: 10,
          name: 'internal',
          kind: 'hosted',
          online: true,
          format: 'nuget',
          url: 'https://forge.example.com/repository/internal',
        },
        {
          id: 11,
          name: 'npm-all',
          kind: 'group',
          online: true,
          format: 'npm',
          url: 'https://forge.example.com/repository/npm-all',
        },
        {
          id: 12,
          name: 'images',
          kind: 'hosted',
          online: true,
          format: 'docker',
          registry: 'forge.example.com',
          pull_prefix: 'forge.example.com/images',
        },
      ],
    })
    vi.stubGlobal('fetch', vi.fn(api.fetch))
    const u = userEvent.setup()
    await renderApp('/tokens')

    expect(screen.queryByRole('heading', { name: 'Use this token' })).not.toBeInTheDocument()
    await u.type(await screen.findByLabelText('Token name'), 'laptop')
    await u.click(screen.getByRole('button', { name: 'Create token' }))

    const panel = (await screen.findByRole('heading', { name: 'Use this token' })).closest(
      'section',
    )!
    const tabs = within(panel).getByRole('tablist', { name: 'Client' })
    expect(within(tabs).getAllByRole('tab').map((t) => t.textContent)).toEqual([
      'NuGet',
      'npm',
      'Docker',
    ])
    expect(
      within(panel).getByText(
        'dotnet nuget add source https://forge.example.com/repository/internal/index.json --name internal --username alice --password my-plaintext-secret --store-password-in-clear-text',
      ),
    ).toBeInTheDocument()
    expect(within(panel).getByText('NuGet.config')).toBeInTheDocument()

    await u.click(within(tabs).getByRole('tab', { name: 'npm' }))
    expect(
      within(panel).getByText(
        'npm config set //forge.example.com/repository/npm-all/:_authToken my-plaintext-secret',
      ),
    ).toBeInTheDocument()

    await u.click(within(tabs).getByRole('tab', { name: 'Docker' }))
    expect(
      within(panel).getByText(
        'echo my-plaintext-secret | docker login forge.example.com --username alice --password-stdin',
      ),
    ).toBeInTheDocument()
    // A hosted repository and an unscoped token: pushing is offered.
    expect(within(panel).getByRole('button', { name: 'Copy push command' })).toBeInTheDocument()

    // Dismissing the secret takes its snippets along.
    await u.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByRole('heading', { name: 'Use this token' })).not.toBeInTheDocument()
  })

  it('names only the repositories of a scoped token, without pushes for a read token', async () => {
    api = new FakeRbacApi({
      me: readerMe,
      browseRepos: [
        {
          id: 10,
          name: 'internal',
          kind: 'hosted',
          online: true,
          format: 'nuget',
          url: 'https://forge.example.com/repository/internal',
        },
        {
          id: 12,
          name: 'images',
          kind: 'hosted',
          online: true,
          format: 'docker',
          registry: 'forge.example.com',
          pull_prefix: 'forge.example.com/images',
        },
      ],
    })
    vi.stubGlobal('fetch', vi.fn(api.fetch))
    const u = userEvent.setup()
    await renderApp('/tokens')

    await u.type(await screen.findByLabelText('Token name'), 'pull-only')
    await u.click(screen.getByRole('radio', { name: 'At most this level' }))
    await u.click(screen.getByRole('radio', { name: /^Only these repositories/ }))
    await u.click(await screen.findByRole('checkbox', { name: 'images' }))
    await u.click(screen.getByRole('button', { name: 'Create token' }))

    const panel = (await screen.findByRole('heading', { name: 'Use this token' })).closest(
      'section',
    )!
    expect(
      within(within(panel).getByRole('tablist', { name: 'Client' }))
        .getAllByRole('tab')
        .map((t) => t.textContent),
    ).toEqual(['Docker'])
    expect(
      within(panel).getByText(
        'echo my-plaintext-secret | docker login forge.example.com --username alice --password-stdin',
      ),
    ).toBeInTheDocument()
    expect(within(panel).getByRole('button', { name: 'Copy pull command' })).toBeInTheDocument()
    expect(within(panel).queryByRole('button', { name: 'Copy push command' })).not.toBeInTheDocument()
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
        expect(body.expires_at).toBe(new Date(`${choice.date}T23:59:59.999`).toISOString())
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
    ).toBe(new Date(`${date.min}T23:59:59.999`).toISOString())
  })

  it('keeps a custom expiry on the selected date in a non-UTC timezone', async () => {
    vi.stubEnv('TZ', 'Asia/Tokyo')
    const u = userEvent.setup()
    await renderApp('/tokens')
    await u.type(await screen.findByLabelText('Token name'), 'tokyo')
    await u.selectOptions(screen.getByLabelText('Token expiry'), 'custom')
    const date = screen.getByLabelText('Expiry date') as HTMLInputElement
    fireEvent.change(date, { target: { value: date.min } })

    await u.click(screen.getByRole('button', { name: 'Create token' }))
    await waitFor(() => expect(api.sent('POST', /^\/admin\/me\/tokens$/)).toHaveLength(1))
    const body = api.sent('POST', /^\/admin\/me\/tokens$/)[0]!.body as {
      expires_at: string
    }
    const [year, month, day] = date.min.split('-').map(Number)
    const expected = new Date(year!, month! - 1, day!, 23, 59, 59, 999).toISOString()
    expect(body.expires_at).toBe(expected)
    expect(body.expires_at).not.toBe(`${date.min}T23:59:59.999Z`)
    const selectedDate = new Date(`${date.min}T12:00:00`).toLocaleDateString(undefined, {
      dateStyle: 'medium',
    })
    expect(
      await screen.findByText(`This token expires ${selectedDate}.`),
    ).toBeInTheDocument()
  })
})
