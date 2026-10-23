import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { RealmView } from '~/api/realms'
import type { RepoView } from '~/api/repositories'
import type { AuthSettings } from '~/api/settings'
import { renderApp } from '~/test/renderApp'
import { formatDuration } from './Settings'

/**
 * Admin settings screen (`/manage/settings`), driven against the real route
 * tree and query hooks:
 *  - it shows the stored settings and the repositories allowing anonymous
 *    reads;
 *  - each section PUTs only its own fields, as the API's types;
 *  - wrong values are refused before a request, and the server's refusal is
 *    shown with its reason.
 */

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

const stored: AuthSettings = {
  anonymous_mode: 'off',
  anonymous_ip_allowlist: [],
  login_mode: 'identifier_first',
  allow_password_basic: false,
  session_idle_ttl_seconds: 28800,
  session_absolute_ttl_seconds: 604800,
  login_max_failures: 10,
  login_failure_window_seconds: 300,
}

function repo(over: Partial<RepoView>): RepoView {
  return {
    id: 1,
    name: 'hosted-1',
    format: 'nuget',
    kind: 'hosted',
    anonymous_read: false,
    online: true,
    remote_url: null,
    package_delay_seconds: 0,
    upstream_username: null,
    has_upstream_password: false,
    metadata_ttl_seconds: null,
    not_found_ttl_seconds: null,
    allow_redeploy: false,
    prefer_hosted: false,
    reserved_prefixes: [],
    host: null,
    immutable_tags: false,
    latest_mutable: false,
    writable_member: null,
    max_upload_bytes: null,
    ...over,
  }
}

function realm(over: Partial<RealmView>): RealmView {
  return {
    id: 1,
    kind: 'local',
    name: 'local',
    enabled: true,
    priority: 0,
    config: {},
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...over,
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

interface ApiHandlers {
  settings?: AuthSettings
  repositories?: RepoView[]
  realms?: RealmView[]
  onPut?: (body: Record<string, unknown>) => Response
}

function mockApi(h: ApiHandlers) {
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const path = new URL(raw, 'http://localhost').pathname
    const method = (init?.method ?? 'GET').toUpperCase()
    if (path.endsWith('/admin/me')) return Promise.resolve(json(adminMe))
    if (path.endsWith('/admin/settings/auth')) {
      if (method === 'PUT') {
        const body = JSON.parse(init?.body as string) as Record<string, unknown>
        return Promise.resolve(
          h.onPut ? h.onPut(body) : json({ ...(h.settings ?? stored), ...body }),
        )
      }
      return Promise.resolve(json(h.settings ?? stored))
    }
    if (path.endsWith('/admin/repositories')) {
      return Promise.resolve(json(h.repositories ?? []))
    }
    if (path.endsWith('/admin/realms')) return Promise.resolve(json(h.realms ?? []))
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

/** The bodies of the PUTs sent so far. */
function puts(): Record<string, unknown>[] {
  return fetchMock.mock.calls
    .filter(([, init]) => (init as RequestInit | undefined)?.method?.toUpperCase() === 'PUT')
    .map(([, init]) => JSON.parse((init as RequestInit).body as string))
}

function section(name: string): HTMLElement {
  const legend = screen.getByText(name, { selector: '[data-slot=legend]' })
  return legend.closest('form') as HTMLElement
}

describe('admin settings', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('shows the stored settings and the repositories allowing anonymous reads', async () => {
    mockApi({
      settings: { ...stored, login_mode: 'combined', allow_password_basic: true },
      repositories: [
        repo({ id: 1, name: 'public-feed', anonymous_read: true }),
        repo({ id: 2, name: 'private-feed' }),
      ],
      realms: [realm({ id: 3, kind: 'credential_forwarding', name: 'nexus' })],
    })
    await renderApp('/manage/settings')

    const anonymous = await waitFor(() => section('Anonymous access'))
    expect(within(anonymous).getByRole('combobox', { name: 'Mode' })).toHaveValue('off')
    const listed = await within(anonymous).findByRole('region', {
      name: 'Repositories allowing anonymous reads',
    })
    expect(within(listed).getByRole('link', { name: 'public-feed' })).toBeInTheDocument()
    expect(within(listed).queryByText('private-feed')).toBeNull()

    const signIn = section('Sign-in')
    expect(within(signIn).getByRole('combobox', { name: 'Login screen' })).toHaveValue(
      'combined',
    )
    expect(
      within(signIn).getByRole('checkbox', {
        name: 'Accept passwords over HTTP Basic on the feeds',
      }),
    ).toBeChecked()
    expect(
      within(signIn).getByRole('textbox', { name: 'Session idle timeout (seconds)' }),
    ).toHaveValue('28800')
    expect(within(signIn).getByText(/\(= 8 hours\)/)).toBeInTheDocument()
    expect(
      await within(signIn).findByText(/credential-forwarding realm nexus accepts passwords/),
    ).toBeInTheDocument()
  })

  it('saving anonymous access PUTs its own fields only', async () => {
    mockApi({})
    const u = userEvent.setup()
    await renderApp('/manage/settings')
    const anonymous = await waitFor(() => section('Anonymous access'))

    await u.selectOptions(within(anonymous).getByRole('combobox', { name: 'Mode' }), 'allowlist')
    // An allowlist without entries is refused before any request.
    await u.click(within(anonymous).getByRole('button', { name: 'Save anonymous access' }))
    expect(await within(anonymous).findByRole('alert')).toHaveTextContent(
      'List at least one address or network',
    )
    expect(puts()).toEqual([])

    await u.type(
      within(anonymous).getByRole('textbox', { name: 'IP allowlist' }),
      ' loopback {enter}{enter}10.0.0.0/8',
    )
    await u.click(within(anonymous).getByRole('button', { name: 'Save anonymous access' }))
    await waitFor(() =>
      expect(puts()).toEqual([
        { anonymous_mode: 'allowlist', anonymous_ip_allowlist: ['loopback', '10.0.0.0/8'] },
      ]),
    )
    expect(await within(anonymous).findByRole('status')).toHaveTextContent('Saved.')
  })

  it('saving sign-in PUTs numbers, refuses wrong ones first and shows a refusal', async () => {
    mockApi({
      onPut: () => new Response('login_failure_window_seconds must be between 1 and 86400 (a day), got 99999', { status: 400 }),
    })
    const u = userEvent.setup()
    await renderApp('/manage/settings')
    const signIn = await waitFor(() => section('Sign-in'))

    const idle = within(signIn).getByRole('textbox', { name: 'Session idle timeout (seconds)' })
    await u.clear(idle)
    await u.type(idle, 'soon')
    await u.click(within(signIn).getByRole('button', { name: 'Save sign-in' }))
    expect(await within(signIn).findByText('Enter a number of seconds, at least 1.')).toBeInTheDocument()
    expect(puts()).toEqual([])

    await u.clear(idle)
    await u.type(idle, '600')
    const window = within(signIn).getByRole('textbox', { name: 'Lockout window (seconds)' })
    await u.clear(window)
    await u.type(window, '99999')
    await u.selectOptions(
      within(signIn).getByRole('combobox', { name: 'Login screen' }),
      'combined',
    )
    await u.click(
      within(signIn).getByRole('checkbox', {
        name: 'Accept passwords over HTTP Basic on the feeds',
      }),
    )
    await u.click(within(signIn).getByRole('button', { name: 'Save sign-in' }))
    await waitFor(() =>
      expect(puts()).toEqual([
        {
          login_mode: 'combined',
          allow_password_basic: true,
          session_idle_ttl_seconds: 600,
          session_absolute_ttl_seconds: 604800,
          login_max_failures: 10,
          login_failure_window_seconds: 99999,
        },
      ]),
    )
    expect(await within(signIn).findByRole('alert')).toHaveTextContent(
      'login_failure_window_seconds must be between 1 and 86400 (a day), got 99999',
    )
  })
})

describe('formatDuration', () => {
  it('names the largest whole unit', () => {
    expect(formatDuration(28800)).toBe('8 hours')
    expect(formatDuration(604800)).toBe('7 days')
    expect(formatDuration(60)).toBe('1 minute')
    expect(formatDuration(90)).toBe('90 seconds')
    expect(formatDuration(1)).toBe('1 second')
  })
})
