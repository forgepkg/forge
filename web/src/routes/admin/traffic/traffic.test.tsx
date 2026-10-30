import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { GeoipStatus, TrafficOverview, TrafficSettings } from '~/api/traffic'
import { renderApp } from '~/test/renderApp'

/**
 * The traffic screens (`/manage/traffic` and its settings), driven against
 * the real route tree and query hooks:
 *  - the totals and the lists by repository, country, network and client;
 *    each row narrows the view, the filters are sent and kept in the URL and
 *    removed one by one;
 *  - without a geolocation database, the countries say how to get one;
 *  - the settings, the MaxMind account (the key never shown) and its
 *    download, and turning geolocation off after confirming.
 */

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

const recording = { enabled: true, client_addresses: true, countries: true, asns: true }

const overview: TrafficOverview = {
  from: '2026-10-24',
  to: '2026-10-30',
  instances: [
    { id: 'web-1_20261030T100000Z_00a1', host: 'web-1', started_at: '2026-10-30T10:00:00Z' },
    { id: 'web-2_20261030T110000Z_00b2', host: 'web-2', started_at: '2026-10-30T11:00:00Z' },
  ],
  totals: { requests: 1234, bytes: 5 * 1024 ** 2, clients: 3, countries: 2, asns: 2 },
  days: [
    { day: '2026-10-29', requests: 600, bytes: 1024, clients: 2 },
    { day: '2026-10-30', requests: 634, bytes: 2048, clients: 3 },
  ],
  repositories: [
    { name: 'npm-proxy', requests: 1000, bytes: 4 * 1024 ** 2, clients: 2 },
    { name: '', requests: 234, bytes: 1024 ** 2, clients: 3 },
  ],
  countries: [
    { country: 'DE', requests: 900, bytes: 3 * 1024 ** 2, clients: 1 },
    { country: '', requests: 334, bytes: 2 * 1024 ** 2, clients: 2 },
  ],
  asns: [{ asn: 3320, org: 'Deutsche Telekom AG', requests: 900, bytes: 3 * 1024 ** 2, clients: 1 }],
  clients: [
    {
      network: '2001:db8:1:2::/64',
      address: '2001:db8:1:2::7',
      country: 'DE',
      asn: 3320,
      as_org: 'Deutsche Telekom AG',
      requests: 900,
      bytes: 3 * 1024 ** 2,
      repositories: ['npm-proxy', ''],
      days: 2,
      first_day: '2026-10-29',
      last_day: '2026-10-30',
    },
  ],
  recording,
}

const settings: TrafficSettings = { enabled: true, client_addresses: true, retention_days: 90 }

const geoip = (over: Partial<GeoipStatus['maxmind']> = {}): GeoipStatus => ({
  country: { database_type: 'GeoLite2-Country', built_at: '2026-10-28T00:00:00Z', size: 9_000_000 },
  asn: { database_type: 'GeoLite2-ASN', built_at: '2026-10-28T00:00:00Z', size: 8_000_000 },
  maxmind: {
    account_id: '123456',
    license_key_set: true,
    last_attempt: '2026-10-30T10:00:00Z',
    last_success: '2026-10-30T10:00:00Z',
    last_error: null,
    url: 'https://download.maxmind.com',
    editions: ['GeoLite2-Country', 'GeoLite2-ASN'],
    ...over,
  },
})

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

function mockApi(h: { overview?: TrafficOverview; geoip?: GeoipStatus } = {}) {
  // The geolocation status, as the server keeps it between requests.
  let geo = h.geoip ?? geoip()
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost')
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {}
    if (url.pathname.endsWith('/admin/me')) return Promise.resolve(json(adminMe))
    if (url.pathname.endsWith('/admin/traffic')) return Promise.resolve(json(h.overview ?? overview))
    if (url.pathname.endsWith('/admin/settings/traffic')) {
      return Promise.resolve(json(method === 'PUT' ? { ...settings, ...body } : settings))
    }
    if (url.pathname.endsWith('/admin/traffic/geoip/update')) {
      geo = { ...geo, maxmind: { ...geo.maxmind, last_error: 'MaxMind refused the account ID or the license key (401)' } }
      return Promise.resolve(json(geo))
    }
    if (url.pathname.endsWith('/admin/traffic/geoip')) {
      if (method === 'DELETE') {
        geo = { country: null, asn: null, maxmind: { ...geo.maxmind, account_id: null, license_key_set: false } }
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      if (method === 'PUT') {
        geo = {
          ...geo,
          maxmind: { ...geo.maxmind, account_id: String(body.account_id), license_key_set: true },
        }
      }
      return Promise.resolve(json(geo))
    }
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

/** The query strings of the requests to `path` sent so far. */
function sent(path: string, method = 'GET'): URLSearchParams[] {
  return fetchMock.mock.calls
    .filter(([, init]) => ((init as RequestInit | undefined)?.method ?? 'GET') === method)
    .map(([input]) => new URL(String(input), 'http://localhost'))
    .filter((u) => u.pathname === path)
    .map((u) => u.searchParams)
}

/** The bodies of the requests to `path` sent with `method`. */
function bodies(path: string, method: string): unknown[] {
  return fetchMock.mock.calls
    .filter(([input, init]) => {
      const i = init as RequestInit | undefined
      return i?.method === method && new URL(String(input), 'http://localhost').pathname === path
    })
    .map(([, init]) => {
      const raw = (init as RequestInit).body
      return raw ? (JSON.parse(String(raw)) as unknown) : null
    })
}

describe('admin traffic screens', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('shows the totals and where the requests came from', async () => {
    mockApi()
    await renderApp('/manage/traffic')

    expect(await screen.findByText('1,234')).toBeInTheDocument()
    expect(sent('/admin/traffic')[0].get('range')).toBe('30d')

    const repos = screen.getByRole('table', { name: 'Repositories by requests' })
    expect(within(repos).getByRole('link', { name: 'npm-proxy' })).toBeInTheDocument()
    expect(
      within(repos).getByRole('link', { name: 'No repository (web UI, APIs, sign-in)' }),
    ).toBeInTheDocument()
    const countries = screen.getByRole('table', { name: 'Countries by requests' })
    expect(within(countries).getByRole('link', { name: 'Germany' })).toBeInTheDocument()
    expect(within(countries).getByRole('link', { name: 'Unknown' })).toBeInTheDocument()
    const asns = screen.getByRole('table', { name: 'Autonomous systems by requests' })
    expect(within(asns).getByRole('link', { name: 'AS3320 Deutsche Telekom AG' })).toBeInTheDocument()
    const clients = screen.getByRole('table', { name: 'Top clients' })
    const row = within(clients).getAllByRole('row')[1]
    expect(within(row).getByRole('link', { name: '2001:db8:1:2::/64' })).toBeInTheDocument()
    expect(within(row).getByText('Germany')).toBeInTheDocument()
    expect(within(row).getByText('npm-proxy, No repository (web UI, APIs, sign-in)')).toBeInTheDocument()
    expect(screen.getAllByText(/GeoLite Data created by MaxMind/).length).toBeGreaterThan(0)
    expect(screen.getByRole('img', { name: /Requests by day: 1,234 in all/ })).toBeInTheDocument()
  })

  it('narrows the view from its lists, and removes the filters one by one', async () => {
    mockApi()
    const user = userEvent.setup()
    const router = await renderApp('/manage/traffic')
    await screen.findByText('1,234')

    await user.click(screen.getByRole('radio', { name: '7 days' }))
    await user.click(screen.getByRole('link', { name: 'npm-proxy' }))
    await user.click(await screen.findByRole('link', { name: 'Germany' }))
    await waitFor(() =>
      expect(
        sent('/admin/traffic').some(
          (q) => q.get('range') === '7d' && q.get('repository') === 'npm-proxy' && q.get('country') === 'DE',
        ),
      ).toBe(true),
    )
    expect(router.state.location.search).toMatchObject({ range: '7d', repository: 'npm-proxy', country: 'DE' })

    await user.click(screen.getByRole('button', { name: 'Remove the filter Repository: npm-proxy' }))
    await waitFor(() => expect(router.state.location.search).not.toHaveProperty('repository'))
    expect(router.state.location.search).toMatchObject({ country: 'DE' })

    // The requests to no repository and the unknown country are filters too.
    await user.click(screen.getByRole('link', { name: 'No repository (web UI, APIs, sign-in)' }))
    await waitFor(() => expect(sent('/admin/traffic').some((q) => q.get('repository') === '-')).toBe(true))
    await user.click(screen.getByRole('button', { name: 'Clear all' }))
    await waitFor(() => expect(router.state.location.search).not.toHaveProperty('country'))
  })

  it('shows the days as a table on request', async () => {
    mockApi()
    const user = userEvent.setup()
    await renderApp('/manage/traffic')
    await screen.findByText('1,234')

    await user.click(screen.getByRole('radio', { name: 'Table' }))
    const table = screen.getByRole('table', { name: 'Requests by day' })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows.map((r) => within(r).getAllByRole('cell')[1].textContent)).toEqual(['634', '600'])
  })

  it('says how to look countries up without a database, and when nothing is recorded', async () => {
    mockApi({
      overview: {
        ...overview,
        totals: { ...overview.totals, countries: 0, asns: 0 },
        countries: [{ country: '', requests: 1234, bytes: 0, clients: 3 }],
        asns: [{ asn: 0, org: '', requests: 1234, bytes: 0, clients: 3 }],
        recording: { ...recording, enabled: false, countries: false, asns: false },
      },
    })
    await renderApp('/manage/traffic')
    expect(await screen.findByText('Traffic is not recorded')).toBeInTheDocument()
    expect(screen.getByText('Countries are not looked up')).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: 'Autonomous systems by requests' })).toBeNull()
  })

  it('saves the recording settings', async () => {
    mockApi()
    const user = userEvent.setup()
    await renderApp('/manage/traffic/settings')

    await user.click(await screen.findByRole('switch', { name: /Client addresses/ }))
    const retention = screen.getByRole('textbox', { name: 'Keep the statistics for (days)' })
    await user.clear(retention)
    await user.type(retention, '0')
    await user.click(screen.getByRole('button', { name: 'Save recording' }))
    expect(await screen.findByText(/Enter a whole number of days from 1/)).toBeInTheDocument()
    expect(bodies('/admin/settings/traffic', 'PUT')).toEqual([])

    await user.clear(retention)
    await user.type(retention, '30')
    await user.click(screen.getByRole('button', { name: 'Save recording' }))
    await waitFor(() =>
      expect(bodies('/admin/settings/traffic', 'PUT')).toEqual([
        { enabled: true, client_addresses: false, retention_days: 30 },
      ]),
    )
  })

  it('sets the MaxMind account, downloads, and turns geolocation off', async () => {
    mockApi({ geoip: { country: null, asn: null, maxmind: { ...geoip().maxmind, account_id: null, license_key_set: false, last_success: null } } })
    const user = userEvent.setup()
    await renderApp('/manage/traffic/settings')

    expect(await screen.findAllByText('Not loaded')).toHaveLength(2)
    await user.click(screen.getByRole('button', { name: 'Save account' }))
    expect(screen.getByText('Enter your MaxMind account ID, a number.')).toBeInTheDocument()
    expect(screen.getByText('Enter a license key.')).toBeInTheDocument()

    await user.type(screen.getByRole('textbox', { name: 'MaxMind account ID' }), '123456')
    await user.type(screen.getByLabelText('License key'), 'abc_secret')
    await user.click(screen.getByRole('button', { name: 'Save account' }))
    await waitFor(() =>
      expect(bodies('/admin/traffic/geoip', 'PUT')).toEqual([
        { account_id: '123456', license_key: 'abc_secret' },
      ]),
    )
    // The key is not kept on screen once stored.
    await waitFor(() => expect(screen.getByLabelText('License key')).toHaveValue(''))

    await user.click(await screen.findByRole('button', { name: 'Download now' }))
    expect(await screen.findByText('The last download failed')).toBeInTheDocument()
    expect(screen.getByText(/refused the account ID or the license key/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Turn off' }))
    const dialog = screen.getByRole('dialog', { name: 'Turn geolocation off?' })
    expect(bodies('/admin/traffic/geoip', 'DELETE')).toEqual([])
    await user.click(within(dialog).getByRole('button', { name: 'Turn off' }))
    await waitFor(() => expect(bodies('/admin/traffic/geoip', 'DELETE')).toHaveLength(1))
    expect(await screen.findByText('Not set')).toBeInTheDocument()
  })
})
