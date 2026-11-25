import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'

import { makeQueryClient } from '~/lib/queryClient'
import { clearSession, setSession } from '~/lib/auth'
import type { RepoView, SigningKey } from '~/api/repositories'
import { keyExpiry, SigningKeysPanel } from './SigningKeysPanel'

/**
 * The signing keys panel: **Delete key** deletes nothing until its dialog,
 * which names the key, the key clients must trust instead and that it
 * cannot be undone, is confirmed; Cancel keeps the key. Each key shows its
 * expiry, and an expired key, which signs no longer, is called out.
 */

const OLD = 'AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555'
const NEW = 'FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000'

function key(fingerprint: string, expires_at: string | null = null): SigningKey {
  return {
    expires_at,
    fingerprint,
    algorithm: 'Ed25519',
    user_id: 'apt-hosted',
    public_key: `-----BEGIN PGP PUBLIC KEY BLOCK-----\n${fingerprint}\n-----END PGP PUBLIC KEY BLOCK-----`,
    created_at: '2026-11-01T00:00:00Z',
  }
}

const repo = { name: 'apt-hosted', format: 'apt', kind: 'hosted' } as RepoView

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

function mockKeys(keys: SigningKey[]) {
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input.toString(), 'http://localhost')
    const method = (init?.method ?? 'GET').toUpperCase()
    if (url.pathname.endsWith('/admin/repositories/apt-hosted/signing-keys') && method === 'GET') {
      return Promise.resolve(json(keys))
    }
    if (method === 'DELETE') return Promise.resolve(new Response(null, { status: 204 }))
    return Promise.resolve(json({ error: 'unexpected' }, 404))
  })
}

function deletes() {
  return fetchMock.mock.calls.filter(
    ([, init]) => (init as RequestInit | undefined)?.method === 'DELETE',
  )
}

function renderPanel() {
  render(
    <QueryClientProvider client={makeQueryClient()}>
      <SigningKeysPanel repo={repo} />
    </QueryClientProvider>,
  )
}

describe('SigningKeysPanel', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    clearSession()
    vi.unstubAllGlobals()
  })

  it('asks before deleting a key, and Cancel keeps it', async () => {
    const user = userEvent.setup()
    mockKeys([key(OLD), key(NEW)])
    renderPanel()

    const buttons = await screen.findAllByRole('button', { name: 'Delete key' })
    await user.click(buttons[0])

    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('AAAA 1111 BBBB 2222 CCCC 3333 DDDD 4444 EEEE 5555')
    expect(dialog).toHaveTextContent(
      'Clients must trust the remaining key FFFF 6666 AAAA 7777 BBBB 8888 CCCC 9999 DDDD 0000 first',
    )
    expect(dialog).toHaveTextContent('This cannot be undone.')
    expect(deletes()).toHaveLength(0)

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(deletes()).toHaveLength(0)
  })

  it('deletes the key once the dialog is confirmed', async () => {
    const user = userEvent.setup()
    mockKeys([key(OLD), key(NEW)])
    renderPanel()

    const buttons = await screen.findAllByRole('button', { name: 'Delete key' })
    await user.click(buttons[0])
    await user.click(
      within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete key' }),
    )

    await waitFor(() => expect(deletes()).toHaveLength(1))
    expect(String(deletes()[0][0])).toContain(`/admin/repositories/apt-hosted/signing-keys/${OLD}`)
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('offers no delete for the last key', async () => {
    mockKeys([key(OLD)])
    renderPanel()

    expect(await screen.findByRole('button', { name: 'Delete key' })).toBeDisabled()
  })

  it('shows when each key expires', async () => {
    mockKeys([key(OLD), key(NEW, '2999-03-04T12:00:00Z')])
    renderPanel()

    expect(await screen.findByText('never expires')).toBeInTheDocument()
    expect(screen.getByText(/^expires .*2999/)).toBeInTheDocument()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('warns of an expired key beside one that signs', async () => {
    mockKeys([key(OLD, '2020-03-04T12:00:00Z'), key(NEW)])
    renderPanel()

    expect(await screen.findByText(/^expired .*2020/)).toBeInTheDocument()
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('An expired key signs no longer')
    expect(alert).toHaveTextContent('AAAA 1111 BBBB 2222 CCCC 3333 DDDD 4444 EEEE 5555')
    expect(alert).not.toHaveTextContent('FFFF 6666')
  })

  it('says that nothing signs once every key has expired', async () => {
    mockKeys([key(OLD, '2020-03-04T12:00:00Z')])
    renderPanel()

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('The signing key has expired')
    expect(alert).toHaveTextContent('apt-get update fails')
    expect(alert).toHaveTextContent('Generate or import a key')
  })
})

describe('keyExpiry', () => {
  const now = new Date('2026-11-25T00:00:00Z')

  it('tells never, later, soon and expired apart', () => {
    expect(keyExpiry(null, now)).toEqual({ state: 'never', label: 'never expires' })
    expect(keyExpiry(undefined, now).state).toBe('never')
    expect(keyExpiry('2028-01-01T00:00:00Z', now).state).toBe('valid')
    expect(keyExpiry('2026-12-10T00:00:00Z', now).state).toBe('soon')
    expect(keyExpiry('2026-11-24T23:59:59Z', now).state).toBe('expired')
    expect(keyExpiry('2026-11-25T00:00:00Z', now).state).toBe('expired')
    expect(keyExpiry('2026-11-24T00:00:00Z', now).label).toMatch(/^expired .*2026/)
  })
})
