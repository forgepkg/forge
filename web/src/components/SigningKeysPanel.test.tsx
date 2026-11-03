import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'

import { makeQueryClient } from '~/lib/queryClient'
import { clearSession, setSession } from '~/lib/auth'
import type { RepoView, SigningKey } from '~/api/repositories'
import { SigningKeysPanel } from './SigningKeysPanel'

/**
 * The signing keys panel: **Delete key** deletes nothing until its dialog,
 * which names the key, the key clients must trust instead and that it
 * cannot be undone, is confirmed; Cancel keeps the key.
 */

const OLD = 'AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555'
const NEW = 'FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000'

function key(fingerprint: string): SigningKey {
  return {
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
})
