import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { TrafficClientDetail, TrafficOverview, TrafficSettings } from '~/api/traffic'
import { renderApp } from '~/test/renderApp'

/**
 * The traffic screens (`/manage/traffic`, its client view and its settings),
 * driven against the real route tree and query hooks:
 *  - the overview's totals, top clients and repositories, with the range,
 *    instance and repository sent as asked and kept in the URL;
 *  - a client's view with its request log, accounts named by user;
 *  - the settings, each panel saving only its own fields.
 */

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

const recording = { enabled: true, client_addresses: true, request_log: true }

const point = (start: string, requests: number) => ({
  start,
  requests,
  bytes: requests * 1000,
  client_errors: 1,
  server_errors: 0,
})

const overview: TrafficOverview = {
  from: '2026-10-30T13:00:00Z',
  to: '2026-10-30T14:00:00Z',
  step_seconds: 60,
  resolution: 'minute',
  instances: [
    { id: 'web-1_20261030T100000Z_00a1', host: 'web-1', started_at: '2026-10-30T10:00:00Z' },
    { id: 'web-2_20261030T110000Z_00b2', host: 'web-2', started_at: '2026-10-30T11:00:00Z' },
  ],
  totals: {
    requests: 1234,
    bytes: 5 * 1024 ** 2,
    client_errors: 40,
    denied: 12,
    not_found: 25,
    throttled: 3,
    server_errors: 2,
    mean_ms: 18.25,
    p50_ms: 10,
    p95_ms: 250,
    p99_ms: 1000,
  },
  series: [point('2026-10-30T13:00:00Z', 600), point('2026-10-30T13:01:00Z', 634)],
  surfaces: [
    { surface: 'plugin_npm', requests: 1000, bytes: 4 * 1024 ** 2 },
    { surface: 'oci', requests: 234, bytes: 1024 ** 2 },
  ],
  repositories: [
    { name: 'npm-proxy', requests: 1000, bytes: 4 * 1024 ** 2, client_errors: 30, server_errors: 2 },
  ],
  statuses: [
    { status: 200, requests: 1192 },
    { status: 404, requests: 25 },
  ],
  clients: [
    {
      network: '2001:db8:1:2::/64',
      address: '2001:db8:1:2::7',
      requests: 900,
      bytes: 3 * 1024 ** 2,
      client_errors: 20,
      denied: 5,
      not_found: 15,
      throttled: 0,
      server_errors: 1,
      user_agent: 'npm/10.8.2 node/v22',
      account: 'token',
      user_id: 7,
      username: 'ci-bot',
      hosts: ['web-1', 'web-2'],
      first_seen: '2026-10-30T13:00:00Z',
      last_seen: '2026-10-30T13:59:00Z',
    },
  ],
  recording,
}

const clientDetail: TrafficClientDetail = {
  network: '2001:db8:1:2::/64',
  from: '2026-10-30T13:00:00Z',
  to: '2026-10-30T14:00:00Z',
  step_seconds: 60,
  resolution: 'minute',
  instances: overview.instances,
  totals: overview.clients[0],
  series: overview.series,
  log: {
    from: '2026-10-30T13:00:00Z',
    to: '2026-10-30T14:00:00Z',
    matched: 2,
    entries: [
      {
        time: '2026-10-30T13:59:00Z',
        address: '2001:db8:1:2::7',
        method: 'GET',
        path: '/repository/npm-proxy/left-pad',
        surface: 'plugin_npm',
        repository: 'npm-proxy',
        status: 404,
        bytes: 21,
        duration_ms: 3.5,
        user_agent: 'npm/10.8.2 node/v22',
        account: 'token',
        user_id: 7,
        username: 'ci-bot',
        host: 'web-2',
      },
    ],
    paths: [{ value: '/repository/npm-proxy/left-pad', requests: 2 }],
    user_agents: [{ value: 'npm/10.8.2 node/v22', requests: 2 }],
    accounts: [{ account: 'token', user_id: 7, username: 'ci-bot', requests: 2 }],
    statuses: [{ value: '404', requests: 2 }],
  },
  recording,
}

const settings: TrafficSettings = {
  enabled: true,
  client_addresses: true,
  request_log: true,
  statistics_retention_days: 400,
  client_retention_days: 30,
  request_log_retention_days: 7,
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

function mockApi(h: { overview?: TrafficOverview; onPut?: (body: unknown) => Response } = {}) {
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost')
    const method = (init?.method ?? 'GET').toUpperCase()
    if (url.pathname.endsWith('/admin/me')) return Promise.resolve(json(adminMe))
    if (url.pathname.endsWith('/admin/traffic')) return Promise.resolve(json(h.overview ?? overview))
    if (url.pathname.endsWith('/admin/traffic/client')) return Promise.resolve(json(clientDetail))
    if (url.pathname.endsWith('/admin/settings/traffic')) {
      if (method === 'PUT') {
        const body: unknown = JSON.parse(String(init?.body))
        return Promise.resolve(
          h.onPut ? h.onPut(body) : json({ ...settings, ...(body as object) }),
        )
      }
      return Promise.resolve(json(settings))
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

  it('shows the totals, the top clients and the repositories', async () => {
    mockApi()
    await renderApp('/manage/traffic')

    expect(await screen.findByText('1,234')).toBeInTheDocument()
    expect(screen.getByText('95 % answered within 250 ms, half within 10 ms')).toBeInTheDocument()
    expect(sent('/admin/traffic')[0].get('range')).toBe('24h')

    const clients = screen.getByRole('table', { name: 'Top clients' })
    const row = within(clients).getAllByRole('row')[1]
    expect(within(row).getByRole('link', { name: '2001:db8:1:2::/64' })).toBeInTheDocument()
    expect(within(row).getByText('ci-bot (API token)')).toBeInTheDocument()
    expect(within(row).getByText('web-1, web-2')).toBeInTheDocument()

    const repos = screen.getByRole('table', { name: 'Repositories by requests' })
    expect(within(repos).getByRole('link', { name: 'npm-proxy' })).toBeInTheDocument()
    const surfaces = screen.getByRole('table', { name: 'Requests by surface' })
    expect(within(surfaces).getByText('Docker registry')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: /Requests over time: 1,234 in all/ })).toBeInTheDocument()
  })

  it('asks for the range, instance and repository chosen', async () => {
    mockApi()
    const user = userEvent.setup()
    const router = await renderApp('/manage/traffic')
    await screen.findByText('1,234')

    await user.click(screen.getByRole('radio', { name: '7 days' }))
    await waitFor(() => expect(sent('/admin/traffic').some((q) => q.get('range') === '7d')).toBe(true))

    await user.selectOptions(screen.getByRole('combobox', { name: 'Instance' }), 'web-2_20261030T110000Z_00b2')
    await waitFor(() =>
      expect(sent('/admin/traffic').some((q) => q.get('instance') === 'web-2_20261030T110000Z_00b2')).toBe(true),
    )

    await user.click(screen.getByRole('link', { name: 'npm-proxy' }))
    await waitFor(() =>
      expect(sent('/admin/traffic').some((q) => q.get('repository') === 'npm-proxy')).toBe(true),
    )
    expect(router.state.location.search).toMatchObject({
      range: '7d',
      instance: 'web-2_20261030T110000Z_00b2',
      repository: 'npm-proxy',
    })
  })

  it('shows the points as a table on request', async () => {
    mockApi()
    const user = userEvent.setup()
    await renderApp('/manage/traffic')
    await screen.findByText('1,234')

    await user.click(screen.getByRole('radio', { name: 'Table' }))
    const table = screen.getByRole('table', { name: 'Requests over time' })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows.map((r) => within(r).getAllByRole('cell')[1].textContent)).toEqual(['634', '600'])
  })

  it('says when nothing is recorded', async () => {
    mockApi({ overview: { ...overview, recording: { ...recording, enabled: false } } })
    await renderApp('/manage/traffic')
    expect(await screen.findByText('Traffic is not recorded')).toBeInTheDocument()
  })

  it("opens a client's view with its request log", async () => {
    mockApi()
    const user = userEvent.setup()
    await renderApp('/manage/traffic?range=6h')
    await user.click(await screen.findByRole('link', { name: '2001:db8:1:2::/64' }))

    const log = await screen.findByRole('table', { name: 'Request log' })
    const row = within(log).getAllByRole('row')[1]
    expect(within(row).getByText('GET /repository/npm-proxy/left-pad')).toBeInTheDocument()
    expect(within(row).getByText('404')).toBeInTheDocument()
    expect(within(row).getByText('ci-bot (API token)')).toBeInTheDocument()
    const accounts = screen.getByRole('table', { name: 'Accounts in the request log' })
    expect(within(accounts).getByText('ci-bot (API token)')).toBeInTheDocument()

    const asked = sent('/admin/traffic/client')[0]
    expect(asked.get('network')).toBe('2001:db8:1:2::/64')
    expect(asked.get('range')).toBe('6h')
  })

  it('saves each settings panel on its own', async () => {
    mockApi()
    const user = userEvent.setup()
    await renderApp('/manage/traffic/settings')

    await user.click(await screen.findByRole('switch', { name: /Request log/ }))
    await user.click(screen.getByRole('button', { name: 'Save recording' }))
    await waitFor(() => expect(sent('/admin/settings/traffic', 'PUT')).toHaveLength(1))
    const puts = fetchMock.mock.calls.filter(
      ([, init]) => (init as RequestInit | undefined)?.method === 'PUT',
    )
    expect(JSON.parse(String((puts[0][1] as RequestInit).body))).toEqual({
      enabled: true,
      client_addresses: true,
      request_log: false,
    })

    const log = screen.getByRole('textbox', { name: 'Keep the request log for (days)' })
    await user.clear(log)
    await user.type(log, '0')
    await user.click(screen.getByRole('button', { name: 'Save retention' }))
    expect(await screen.findByText(/Enter a whole number of days from 1/)).toBeInTheDocument()
    expect(sent('/admin/settings/traffic', 'PUT')).toHaveLength(1)

    await user.clear(log)
    await user.type(log, '14')
    await user.click(screen.getByRole('button', { name: 'Save retention' }))
    await waitFor(() => expect(sent('/admin/settings/traffic', 'PUT')).toHaveLength(2))
    const second = fetchMock.mock.calls.filter(
      ([, init]) => (init as RequestInit | undefined)?.method === 'PUT',
    )[1]
    expect(JSON.parse(String((second[1] as RequestInit).body))).toEqual({
      statistics_retention_days: 400,
      client_retention_days: 30,
      request_log_retention_days: 14,
    })
  })
})
