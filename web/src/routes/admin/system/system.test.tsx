import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { BlobCacheStats, CryptoKeys, ServerAddresses } from '~/api/system'
import { renderApp } from '~/test/renderApp'

/**
 * The system screen (`/manage/system`), driven against the real route tree
 * and query hooks:
 *  - the secret encryption's keys and root key version;
 *  - each rotation asks first, posts to its layer, reports what it did and
 *    reads the keys again; a held rotation lock reads as a retryable conflict;
 *  - the blob cache's numbers, or its absence, with the answering instance;
 *  - the public and alias base URLs, or that there are no aliases.
 */

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

const instance = { host: 'forge-7d9c', started_at: '2026-10-23T06:00:00Z' }

const cryptoKeys: CryptoKeys = {
  root_key_version: 'v2',
  keys: [
    {
      layer: 'dek',
      version: 3,
      algorithm: 'aes-256-gcm',
      state: 'active',
      scope: 'secrets',
      created_at: '2026-10-01T00:00:00Z',
      rotated_at: null,
      wrapping_kek_version: 2,
    },
    {
      layer: 'kek',
      version: 2,
      algorithm: 'aes-256-gcm-siv',
      state: 'active',
      scope: 'secrets',
      created_at: '2026-09-01T00:00:00Z',
      rotated_at: null,
      root_key_id: 'env',
      root_key_version: 'v2',
    },
    {
      layer: 'kek',
      version: 1,
      algorithm: 'aes-256-gcm-siv',
      state: 'revoked',
      scope: 'secrets',
      created_at: '2026-01-01T00:00:00Z',
      rotated_at: '2026-09-01T00:00:00Z',
      root_key_id: 'env',
      root_key_version: 'v1',
    },
  ],
}

const cacheStats: BlobCacheStats = {
  enabled: true,
  instance,
  path: '/var/cache/forge',
  object_store_down: true,
  entries: 1204,
  size_bytes: 5 * 1024 ** 3,
  reserved_bytes: 0,
  limit_bytes: 20 * 1024 ** 3,
  limit_auto: true,
  hit_ratio: 0.75,
  hits: 300,
  hit_bytes: 3 * 1024 ** 3,
  hits_while_store_down: 12,
  misses: 100,
  fills: 98,
  fill_failures: 2,
  corrupt: 0,
  evictions: 7,
  evicted_bytes: 700 * 1024 ** 2,
  bypassed: 1,
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

const addresses: ServerAddresses = {
  public_base_url: 'https://forge.example.com',
  alias_base_urls: ['https://nexus.example.com', 'http://old.example.com:8081'],
}

interface ApiHandlers {
  keys?: CryptoKeys
  cache?: BlobCacheStats
  addresses?: ServerAddresses
  onRotate?: (layer: string) => Response
}

function mockApi(h: ApiHandlers) {
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const path = new URL(raw, 'http://localhost').pathname
    const method = (init?.method ?? 'GET').toUpperCase()
    if (path.endsWith('/admin/me')) return Promise.resolve(json(adminMe))
    if (path.endsWith('/admin/crypto/keys')) return Promise.resolve(json(h.keys ?? cryptoKeys))
    const rotate = /\/admin\/crypto\/rotate\/(\w+)$/.exec(path)
    if (rotate && method === 'POST') {
      return Promise.resolve(h.onRotate ? h.onRotate(rotate[1]) : json({}))
    }
    if (path.endsWith('/admin/blob-cache')) return Promise.resolve(json(h.cache ?? cacheStats))
    if (path.endsWith('/admin/addresses')) return Promise.resolve(json(h.addresses ?? addresses))
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

/** The paths of the requests sent so far. */
function requests(method: string, path: RegExp): string[] {
  return fetchMock.mock.calls
    .filter(([, init]) => ((init as RequestInit | undefined)?.method ?? 'GET') === method)
    .map(([input]) => new URL(String(input), 'http://localhost').pathname)
    .filter((p) => path.test(p))
}

describe('admin system screen', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('lists the encryption keys, KEKs first, newest first', async () => {
    mockApi({})
    await renderApp('/manage/system')

    const table = await screen.findByRole('table', { name: 'Encryption keys' })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows.map((r) => within(r).getAllByRole('cell').slice(0, 3).map((c) => c.textContent))).toEqual([
      ['KEK', '2', 'active'],
      ['KEK', '1', 'revoked'],
      ['DEK', '3', 'active'],
    ])
    expect(within(rows[0]).getByText('root v2')).toBeInTheDocument()
    expect(within(rows[2]).getByText('KEK 2')).toBeInTheDocument()
    const panel = screen.getByRole('region', { name: 'Secret encryption' })
    expect(within(panel).getByText('Root key version')).toBeInTheDocument()
  })

  it('rotates the data key after confirming, reports it and reads the keys again', async () => {
    mockApi({
      onRotate: () =>
        json({ rotated: 'dek', new_version: 4, resealed_secrets: 9, revoked_deks: 1 }),
    })
    const user = userEvent.setup()
    await renderApp('/manage/system')

    await user.click(await screen.findByRole('button', { name: 'Rotate DEK' }))
    const dialog = screen.getByRole('dialog', { name: 'Rotate the data key?' })
    // Nothing is sent before the confirmation.
    expect(requests('POST', /rotate/)).toEqual([])
    const before = requests('GET', /crypto\/keys$/).length
    await user.click(within(dialog).getByRole('button', { name: 'Rotate DEK' }))

    expect(
      await screen.findByText(
        'The data key is now version 4: 9 secrets encrypted again, 1 old data key revoked.',
      ),
    ).toBeInTheDocument()
    expect(requests('POST', /rotate/)).toEqual(['/admin/crypto/rotate/dek'])
    await waitFor(() => expect(requests('GET', /crypto\/keys$/).length).toBeGreaterThan(before))
  })

  it('sends nothing when the confirmation is cancelled', async () => {
    mockApi({})
    const user = userEvent.setup()
    await renderApp('/manage/system')

    await user.click(await screen.findByRole('button', { name: 'Re-wrap under the current root' }))
    const dialog = screen.getByRole('dialog', { name: 'Re-wrap the key-encryption keys?' })
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))

    expect(screen.queryByRole('dialog')).toBeNull()
    expect(requests('POST', /rotate/)).toEqual([])
  })

  it('reads a held rotation lock as a conflict to retry', async () => {
    mockApi({
      onRotate: () =>
        new Response(
          'a key rotation is already running (the rotation worker or another admin request); retry shortly',
          { status: 409 },
        ),
    })
    const user = userEvent.setup()
    await renderApp('/manage/system')

    await user.click(await screen.findByRole('button', { name: 'Rotate KEK' }))
    await user.click(
      within(screen.getByRole('dialog')).getByRole('button', { name: 'Rotate KEK' }),
    )

    expect(
      await screen.findByText('Another rotation is running; try again in a moment.'),
    ).toBeInTheDocument()
    expect(requests('POST', /rotate/)).toEqual(['/admin/crypto/rotate/kek'])
  })

  it('shows the blob cache of the answering instance', async () => {
    mockApi({})
    await renderApp('/manage/system')

    const panel = await screen.findByRole('region', { name: 'Local blob cache' })
    expect(await within(panel).findByText('75%')).toBeInTheDocument()
    expect(within(panel).getByText('300 hits, 100 misses')).toBeInTheDocument()
    expect(within(panel).getByText('3.0 GiB')).toBeInTheDocument()
    expect(within(panel).getByRole('progressbar', { name: 'Size' })).toHaveAttribute(
      'aria-valuetext',
      '5.0 GiB of 20.0 GiB (auto)',
    )
    expect(within(panel).getByText('/var/cache/forge')).toBeInTheDocument()
    expect(within(panel).getByText('S3 is unreachable')).toBeInTheDocument()
    expect(within(panel).getByText('forge-7d9c')).toBeInTheDocument()
  })

  it('says when the instance has no blob cache, and refreshes', async () => {
    mockApi({ cache: { enabled: false, instance } })
    const user = userEvent.setup()
    await renderApp('/manage/system')

    const panel = await screen.findByRole('region', { name: 'Local blob cache' })
    expect(
      await within(panel).findByText('This instance has no local blob cache'),
    ).toBeInTheDocument()
    const before = requests('GET', /blob-cache$/).length
    await user.click(within(panel).getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(requests('GET', /blob-cache$/).length).toBe(before + 1))
  })

  it('shows the public URL and the aliases', async () => {
    mockApi({})
    await renderApp('/manage/system')

    const panel = await screen.findByRole('region', { name: 'Addresses' })
    expect(await within(panel).findByText('https://forge.example.com')).toBeInTheDocument()
    const aliases = within(panel).getByRole('list', { name: 'Aliases' })
    expect(within(aliases).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'https://nexus.example.com',
      'http://old.example.com:8081',
    ])
    expect(within(panel).getByText(/a page opened under an alias is redirected/)).toBeInTheDocument()
  })

  it('says when there are no aliases', async () => {
    mockApi({ addresses: { public_base_url: 'https://forge.example.com', alias_base_urls: [] } })
    await renderApp('/manage/system')

    const panel = await screen.findByRole('region', { name: 'Addresses' })
    expect(await within(panel).findByText('None')).toBeInTheDocument()
    expect(within(panel).queryByRole('list', { name: 'Aliases' })).toBeNull()
    expect(within(panel).getAllByText('server.alias_base_urls').length).toBeGreaterThan(1)
  })
})
