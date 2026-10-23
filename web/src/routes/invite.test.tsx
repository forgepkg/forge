import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { renderApp } from '~/test/renderApp'

/**
 * The invitation page (`/invite#<token>`, #322): it names the account the
 * link is for, takes the password twice (at least 12 characters, the same
 * both times), sends the token only in request bodies, and goes on to the
 * sign-in with the username filled in. A link that does not work gets the
 * one generic answer.
 */

const INVALID =
  'This invitation is invalid or has expired; ask your administrator for a new one.'

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

function bodies(suffix: string): unknown[] {
  return fetchMock.mock.calls
    .filter(([input]) => {
      const raw = typeof input === 'string' ? input : input.toString()
      return new URL(raw, 'http://localhost').pathname.endsWith(suffix)
    })
    .map(([, init]) => JSON.parse(((init as RequestInit).body as string) ?? '{}'))
}

function mockApi(live: boolean) {
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const url = new URL(raw, 'http://localhost')
    if (url.pathname.endsWith('/auth/invitations/lookup')) {
      return Promise.resolve(
        live
          ? json({ username: 'alice@example.com', expires_at: '2026-10-26T09:00:00Z' })
          : json({ error: INVALID }, 400),
      )
    }
    if (url.pathname.endsWith('/auth/invitations/accept')) {
      return Promise.resolve(json({ username: 'alice@example.com' }))
    }
    if (url.pathname.endsWith('/auth/login-options')) {
      return Promise.resolve(json({ mode: 'combined', password: true, oidc: [] }))
    }
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

describe('invitation page', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sets the password and goes on to the sign-in', async () => {
    mockApi(true)
    const u = userEvent.setup()
    const router = await renderApp('/invite#tok-123')

    expect(await screen.findByText('alice@example.com')).toBeInTheDocument()
    expect(bodies('/auth/invitations/lookup')).toEqual([{ token: 'tok-123' }])
    // The token never goes into a URL.
    for (const [input] of fetchMock.mock.calls) {
      expect(String(input)).not.toContain('tok-123')
    }

    await u.type(screen.getByLabelText('Password'), 'short')
    await u.type(screen.getByLabelText('Password again'), 'short')
    await u.click(screen.getByRole('button', { name: 'Set password' }))
    expect(screen.getByRole('alert')).toHaveTextContent('at least 12 characters')

    await u.clear(screen.getByLabelText('Password'))
    await u.type(screen.getByLabelText('Password'), 'a-long-enough-one')
    await u.click(screen.getByRole('button', { name: 'Set password' }))
    expect(screen.getByRole('alert')).toHaveTextContent('The two passwords differ.')
    expect(bodies('/auth/invitations/accept')).toHaveLength(0)

    await u.clear(screen.getByLabelText('Password again'))
    await u.type(screen.getByLabelText('Password again'), 'a-long-enough-one')
    await u.click(screen.getByRole('button', { name: 'Set password' }))

    await waitFor(() => expect(router.state.location.pathname).toBe('/login'))
    expect(bodies('/auth/invitations/accept')).toEqual([
      { token: 'tok-123', password: 'a-long-enough-one' },
    ])
    expect(await screen.findByText('Your password is set. Sign in with it.')).toBeInTheDocument()
    expect(await screen.findByLabelText('Username')).toHaveValue('alice@example.com')
  })

  it('gives one answer for a link that does not work', async () => {
    mockApi(false)
    await renderApp('/invite#used')
    expect(await screen.findByRole('alert')).toHaveTextContent(INVALID)
    expect(screen.queryByLabelText('Password')).toBeNull()
  })

  it('needs a token', async () => {
    mockApi(true)
    await renderApp('/invite')
    expect(await screen.findByRole('alert')).toHaveTextContent(INVALID)
    expect(bodies('/auth/invitations/lookup')).toHaveLength(0)
  })
})
